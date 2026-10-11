"""Correlated private evidence and bounded-clock proof predicates.

Operator assertions, fixture results and native collector receipts remain distinct.
Imports cannot rewrite first observations or promote the committed acceptance ledger.
"""

from datetime import timedelta

from .config import binding_digest
from .models import Evidence, GovernanceError, now, require


def before_registration(evidence, submitted_at, registry_clock):
    """Prove latest possible detection precedes earliest registration and receipt was timely."""
    source_clock = evidence.clock_bound
    if (
        evidence.provenance != "native"
        or not evidence.independent
        or not evidence.attributed
        or source_clock is None
        or type(registry_clock) is not int
        or not 0 <= source_clock <= 5
        or not 0 <= registry_clock <= 5
    ):
        return False
    return evidence.received_at < submitted_at and evidence.observed_at + timedelta(
        seconds=source_clock
    ) < submitted_at - timedelta(seconds=registry_clock)


def attach(store, evidence, *, revision):
    """Attach strict evidence only to the current case/binding/environment generation."""
    require(isinstance(evidence, Evidence))

    def update(journal):
        """Validate current case attribution and invalidate every unconsumed dependent review."""
        candidate = next(
            (c for c in journal.candidates if c.candidate_id == evidence.candidate_id), None
        )
        require(candidate is not None and candidate.case_id == evidence.case_id)
        require(
            evidence.generation == candidate.generation
            and evidence.environment == journal.environment,
            "configuration_changed",
        )
        require(
            evidence.binding_digest == binding_digest(candidate.binding), "configuration_changed"
        )
        require(candidate.state != "closed", "closed")
        require(
            not any(e.evidence_id == evidence.evidence_id for e in journal.evidence),
            "replay_conflict",
        )
        # New evidence invalidates every unconsumed review rather than silently
        # letting an old human decision authorize a changed case.
        reviews = tuple(
            r
            for r in journal.reviews
            if r.candidate_id != candidate.candidate_id
            or r.consumed
            or any(a.review_id == r.review_id for a in journal.registrations)
        )
        return journal.model_copy(
            update={"evidence": (*journal.evidence, evidence), "reviews": reviews}
        )

    return store.change(update, revision=revision)


def reviewed(value, operator):
    """Record host review while preserving source provenance and original event time."""
    try:
        evidence = Evidence.model_validate(value)
        require(evidence.reviewed_at is None and evidence.reviewed_by is None, "invalid_input")
        return Evidence.model_validate(
            evidence.model_dump() | {"reviewed_by": operator, "reviewed_at": now()}
        )
    except GovernanceError:
        raise
    except Exception:
        raise GovernanceError("invalid_input") from None


def import_file(store, path, candidate_id, operator, *, revision):
    """Review one owner-only bounded evidence envelope and verify its artifact digest.

    Artifact content is used only inside this boundary and is not journaled. Review
    records an operator assertion; native discovery additionally needs the independently
    authenticated observation already captured by ingress. Duplicate identical imports
    are idempotent, while reuse of an evidence ID with changed metadata is rejected.
    """
    import hashlib
    import os
    from pathlib import Path

    from agent.recovery.store import check_stat
    from agent.validation.models import canonical, implementation_revision
    from agent.validation.store import decode_json, no_symlinks

    target = Path(path).absolute()
    no_symlinks(target)
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as file:
            before = os.fstat(file.fileno())
            check_stat(before)
            raw = file.read(1048577)
            after = target.lstat()
            require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "storage_error")
            require(len(raw) <= 1048576, "capacity_exhausted")
        envelope = decode_json(raw)
        if (
            isinstance(envelope, dict)
            and set(envelope) == {"schema_version", "captured_evidence_id"}
            and envelope["schema_version"] == 1
        ):
            from uuid import UUID

            return review_captured(
                store,
                UUID(envelope["captured_evidence_id"]),
                candidate_id,
                operator,
                revision=revision,
            )
        require(
            isinstance(envelope, dict)
            and set(envelope) == {"schema_version", "evidence", "artifact"}
            and envelope["schema_version"] == 1
        )
        item = Evidence.model_validate(envelope["evidence"])
        require(item.candidate_id == candidate_id)
        require(
            item.artifact_digest == hashlib.sha256(canonical(envelope["artifact"])).hexdigest(),
            "replay_conflict",
        )
        require(item.implementation == implementation_revision(), "configuration_changed")
        state = store.read()
        require(state.revision == revision, "review_stale")
        existing = next((e for e in state.evidence if e.evidence_id == item.evidence_id), None)
        if existing:
            require(
                existing.model_dump(exclude={"reviewed_by", "reviewed_at"})
                == item.model_dump(exclude={"reviewed_by", "reviewed_at"}),
                "replay_conflict",
            )
            return existing
        if item.provenance == "native" and item.kind in {"discovery", "notification", "triage"}:
            observation = next(
                (o for o in state.observations if o.observation_id == item.observation_id), None
            )
            candidate = next((c for c in state.candidates if c.candidate_id == candidate_id), None)
            profile = next(
                (
                    s
                    for s in state.sources
                    if observation
                    and s.alias == observation.source
                    and s.generation == observation.source_generation
                ),
                None,
            )
            if item.kind in {"discovery", "notification"}:
                require(
                    profile
                    and profile.clock_bound is not None
                    and item.clock_bound == profile.clock_bound,
                    "native_evidence_missing",
                )
            expected = {
                "discovery": {"unknown"},
                "notification": {"notification"},
                "triage": {"triaged", "managed"},
            }[item.kind]
            require(
                observation
                and candidate
                and candidate.binding
                and observation.candidate_id == candidate_id
                and observation.provenance == "native"
                and observation.kind in expected
                and observation.object == candidate.binding.source_object
                and observation.source_digest == item.source_digest
                and observation.received_at == item.received_at
                and observation.occurred_at == item.observed_at,
                "native_evidence_missing",
            )
        reviewed_item = reviewed(item.model_dump(), operator)
        attach(store, reviewed_item, revision=revision)
        return reviewed_item
    except GovernanceError:
        raise
    except Exception:
        raise GovernanceError("invalid_input") from None


def close(store, candidate_id, operator, *, revision):
    """Archive locally after every possible credential expires or is explicitly resolved.

    This operation never deletes a registration, changes provider authority or releases
    containment. Uncertain registration submission must be resolved first.
    """
    from pydantic import TypeAdapter

    from .models import Alias

    TypeAdapter(Alias).validate_python(operator)

    def update(state):
        """Refuse every unresolved pin before assigning a local closure timestamp."""
        candidate = next((c for c in state.candidates if c.candidate_id == candidate_id), None)
        require(candidate and candidate.state != "closed", "closed")
        require(
            not any(
                a.candidate_id == candidate_id
                and a.state in {"prepared", "submitted", "uncertain", "conflict"}
                for a in state.registrations
            ),
            "creation_uncertain",
        )
        require(
            not any(
                i.candidate_id == candidate_id
                and i.state != "denied"
                and (i.safe_after is None or i.safe_after > now())
                for i in state.credentials
            ),
            "issuance_unresolved",
        )
        archived = candidate.model_copy(
            update={"state": "closed", "closed_at": now(), "revision": candidate.revision + 1}
        )
        return state.model_copy(
            update={
                "candidates": tuple(
                    archived if c.candidate_id == candidate_id else c for c in state.candidates
                )
            }
        )

    with store.lock("effect.lock"):
        return store.change(update, revision=revision)


def resolve(store, attempt_id, operator, *, revision):
    """Record explicit resolution from reviewed, exact-attempt provider evidence only.

    Absence on a read or worker exit is insufficient. Resolution requires a provider
    completion/non-issuance receipt and preserves the attempt so it cannot be replayed.
    """
    from pydantic import TypeAdapter

    from agent.validation.models import implementation_revision

    from .models import Alias

    TypeAdapter(Alias).validate_python(operator)

    def update(state):
        """Consume current native evidence without inferring creation ownership."""
        record = next(
            (
                a
                for a in (*state.credentials, *state.registrations)
                if getattr(a, "intent_id", getattr(a, "attempt_id", None)) == attempt_id
            ),
            None,
        )
        require(
            record and record.state in {"submitted", "uncertain", "conflict"}, "issuance_unresolved"
        )
        candidate = next(c for c in state.candidates if c.candidate_id == record.candidate_id)
        proof = next(
            (
                e
                for e in reversed(state.evidence)
                if e.attempt_id == attempt_id
                and e.kind == "resolution"
                and e.outcome == "pass"
                and e.provenance == "native"
                and e.independent
                and e.attributed
                and e.reviewed_by
                and e.reviewed_at
                and e.generation == candidate.generation
                and e.implementation == implementation_revision()
                and e.environment == state.environment
                and e.binding_digest == binding_digest(candidate.binding)
            ),
            None,
        )
        require(
            proof
            and proof.facts is not None
            and proof.facts.completed_at is not None
            and proof.facts.no_issuance is True,
            "native_evidence_missing",
        )
        require(
            record.submitted_at
            and proof.facts.completed_at >= record.submitted_at
            and proof.facts.completed_at <= now(),
            "proof_inconclusive",
        )
        key = "credentials" if hasattr(record, "intent_id") else "registrations"
        updated = record.model_copy(
            update={"state": "denied", "finished_at": now(), "reason": "provider_denied"}
        )
        return state.model_copy(
            update={key: tuple(updated if a == record else a for a in getattr(state, key))}
        )

    with store.lock("effect.lock"):
        return store.change(update, revision=revision)


def review_captured(store, evidence_id, candidate_id, operator, *, revision):
    """Review a trusted adapter's already captured receipt without reconstructing raw bodies."""
    from agent.validation.models import implementation_revision

    result = None

    def update(state):
        """Review only an unchanged current receipt and invalidate enrollment previews."""
        nonlocal result
        item = next(
            (
                e
                for e in state.evidence
                if e.evidence_id == evidence_id and e.candidate_id == candidate_id
            ),
            None,
        )
        candidate = next((c for c in state.candidates if c.candidate_id == candidate_id), None)
        require(item and candidate and candidate.state != "closed", "invalid_input")
        require(
            item.implementation == implementation_revision()
            and item.generation == candidate.generation
            and item.environment == state.environment
            and item.binding_digest == binding_digest(candidate.binding),
            "configuration_changed",
        )
        if item.reviewed_at:
            result = item
            return state
        result = reviewed(item.model_dump(), operator)
        return state.model_copy(
            update={
                "evidence": tuple(
                    result if e.evidence_id == evidence_id else e for e in state.evidence
                ),
                "reviews": tuple(
                    r for r in state.reviews if r.candidate_id != candidate_id or r.consumed
                ),
            }
        )

    store.change(update, revision=revision)
    return result
