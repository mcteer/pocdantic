"""One-use enrollment decisions and durable-before-dispatch registry creation.

Readback cannot attribute an abandoned create to this process. Every create is preceded
by current metadata and absence; any changed review or uncertain prior attempt blocks it.
"""

from datetime import timedelta

from agent.validation.models import implementation_revision

from .config import binding_digest, fresh
from .coordinator import commit_checked
from .models import GovernanceError, RegistrationAttempt, Review, now, require


def candidate(state, candidate_id):
    """Resolve one local case; native display names are never lookup keys."""
    item = next((c for c in state.candidates if c.candidate_id == candidate_id), None)
    require(item is not None)
    return item


def evidence_digest(state, item):
    """Bind a decision to the complete evidence set, including contradictory observations."""
    return binding_digest(
        {
            "evidence": [
                e.model_dump(mode="json")
                for e in state.evidence
                if e.candidate_id == item.candidate_id
            ],
            "observations": [
                o.model_dump(mode="json")
                for o in state.observations
                if o.candidate_id == item.candidate_id
            ],
        }
    )


def qualifying(state, item):
    """Require reviewed native collector attribution, timely notice and captured absence."""
    if item.binding is None:
        return False
    observations = {
        o.observation_id: o
        for o in state.observations
        if o.candidate_id == item.candidate_id
        and o.provenance == "native"
        and o.kind == "unknown"
        and o.object == item.binding.source_object
    }
    latest = {}
    for evidence in sorted(state.evidence, key=lambda e: e.received_at):
        if evidence.candidate_id == item.candidate_id:
            latest[evidence.kind] = evidence
    for kind in ("registry_absence", "discovery", "notification"):
        evidence = latest.get(kind)
        if (
            evidence is None
            or evidence.provenance != "native"
            or evidence.outcome != "pass"
            or not evidence.independent
            or not evidence.attributed
            or not evidence.reviewed_by
            or not evidence.reviewed_at
            or evidence.clock_bound is None
            or evidence.generation != item.generation
            or evidence.environment != state.environment
            or evidence.implementation != implementation_revision()
            or evidence.binding_digest != binding_digest(item.binding)
        ):
            return False
        if kind == "registry_absence" and not evidence.healthy:
            return False
        if kind == "discovery" and evidence.observation_id not in observations:
            return False
    return bool(observations)


def review(store, candidate_id, revision, operator, *, qualifies=qualifying):
    """Prepare one exact current decision; no provider call or enrollment occurs here."""
    result = None

    def update(state):
        """Bind a one-use review to current case, readiness, evidence and implementation bytes."""
        nonlocal result
        item = candidate(state, candidate_id)
        require(
            item.state == "observed"
            and item.binding
            and item.readiness
            and fresh(item.binding, item.readiness),
            "review_stale",
        )
        require(qualifies(state, item), "native_evidence_missing")
        require(
            not any(
                a.candidate_id == candidate_id and a.state != "denied" for a in state.registrations
            ),
            "creation_uncertain",
        )
        updated = item.model_copy(update={"state": "reviewed", "revision": item.revision + 1})
        result = Review(
            candidate_id=candidate_id,
            candidate_revision=updated.revision,
            journal_revision=state.revision + 1,
            binding_digest=binding_digest(item.binding),
            metadata_digest=item.readiness.metadata_digest,
            evidence_digest=evidence_digest(state, item),
            implementation=implementation_revision(),
            operator=operator,
        )
        return state.model_copy(
            update={
                "candidates": tuple(
                    updated if c.candidate_id == candidate_id else c for c in state.candidates
                ),
                "reviews": (*state.reviews, result),
            }
        )

    store.change(update, revision=revision)
    return result


def metadata_current(fingerprints, item):
    """Compare the entire metadata snapshot rather than only selected successful checks."""
    return binding_digest(fingerprints) == item.readiness.metadata_digest


async def enroll(store, review_id, revision, adapter, check, *, metadata_check=metadata_current):
    """Consume the fresh review and persist submission before one exact POST, never retry."""
    state = store.read()
    require(state.revision == revision, "review_stale")
    decision = next((r for r in state.reviews if r.review_id == review_id), None)
    require(decision is not None and not decision.consumed, "review_stale")
    item = candidate(state, decision.candidate_id)
    require(item.binding and item.readiness and fresh(item.binding, item.readiness), "review_stale")
    check()
    fingerprints = await adapter.metadata(item.binding)
    require(metadata_check(fingerprints, item), "configuration_changed")
    await adapter.absence(item.binding)
    check()
    attempt = None

    def submit(current):
        """Consume the exact current review and reserve submission before any provider mutation."""
        nonlocal attempt
        latest = candidate(current, item.candidate_id)
        require(
            latest == item
            and decision.journal_revision == current.revision
            and decision.candidate_revision == item.revision
            and decision.binding_digest == binding_digest(item.binding)
            and decision.evidence_digest == evidence_digest(current, item)
            and decision.implementation == implementation_revision()
            and timedelta(0) <= now() - decision.created_at <= timedelta(seconds=300),
            "review_stale",
        )
        require(
            not any(
                a.candidate_id == item.candidate_id and a.state != "denied"
                for a in current.registrations
            ),
            "creation_uncertain",
        )
        attempt = RegistrationAttempt(
            candidate_id=item.candidate_id,
            generation=item.generation,
            review_id=review_id,
            binding_digest=binding_digest(item.binding),
            state="submitted",
            submitted_at=now(),
        )
        consumed = decision.model_copy(update={"consumed": True})
        enrolling = item.model_copy(update={"state": "enrolling", "revision": item.revision + 1})
        return current.model_copy(
            update={
                "reviews": tuple(
                    consumed if r.review_id == review_id else r for r in current.reviews
                ),
                "candidates": tuple(
                    enrolling if c.candidate_id == item.candidate_id else c
                    for c in current.candidates
                ),
                "registrations": (*current.registrations, attempt),
            }
        )

    commit_checked(store, check, submit, revision=revision)

    def acknowledge(registration_id, source_digest):
        """Persist the provider acknowledgement before any subsequent readback request."""

        def update(current):
            """Retain exact returned identity without claiming confirmed creation."""
            records = tuple(
                a.model_copy(
                    update={"registration_id": registration_id, "source_digest": source_digest}
                )
                if a.attempt_id == attempt.attempt_id
                else a
                for a in current.registrations
            )
            return current.model_copy(update={"registrations": records})

        store.change(update)

    adapter.acknowledge = acknowledge
    try:
        check()
        result = await adapter.create(item.binding)
        check()

        def confirm(current):
            """Record confirmed creation only if the current enrollment binding still matches."""
            latest = candidate(current, item.candidate_id)
            require(
                latest.generation == item.generation and latest.binding == item.binding,
                "configuration_changed",
            )
            confirmed = attempt.model_copy(
                update={
                    "state": "confirmed",
                    "finished_at": now(),
                    "registration_id": result["registration_id"],
                    "readback_digest": result["digest"],
                    "source_digest": result["source_digest"],
                }
            )
            registered = latest.model_copy(
                update={
                    "state": "registered",
                    "revision": latest.revision + 1,
                    "registration_id": result["registration_id"],
                    "registration_digest": result["digest"],
                    "registered_at": now(),
                }
            )
            return current.model_copy(
                update={
                    "registrations": tuple(
                        confirmed if a.attempt_id == attempt.attempt_id else a
                        for a in current.registrations
                    ),
                    "candidates": tuple(
                        registered if c.candidate_id == item.candidate_id else c
                        for c in current.candidates
                    ),
                }
            )

        commit_checked(store, check, confirm)
        return attempt.attempt_id
    except BaseException:

        def block(current):
            """Retain failed or interrupted creation as uncertainty, preventing any replay."""
            retained = next(a for a in current.registrations if a.attempt_id == attempt.attempt_id)
            uncertain = retained.model_copy(
                update={"state": "uncertain", "reason": "creation_uncertain"}
            )
            latest = candidate(current, item.candidate_id)
            blocked = latest.model_copy(
                update={
                    "state": "blocked",
                    "reason": "creation_uncertain",
                    "revision": latest.revision + 1,
                }
            )
            return current.model_copy(
                update={
                    "registrations": tuple(
                        uncertain if a.attempt_id == attempt.attempt_id else a
                        for a in current.registrations
                    ),
                    "candidates": tuple(
                        blocked if c.candidate_id == item.candidate_id else c
                        for c in current.candidates
                    ),
                }
            )

        store.change(block)
        raise GovernanceError("creation_uncertain") from None
