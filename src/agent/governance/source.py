"""Bounded observation projection and durable intake, entirely separate from effects.

The caller must signature-verify relay claims before calling ingest. Native payloads
identify observations only; none of their fields can choose authority or provider actions.
"""

import base64
import hashlib
import re
from datetime import datetime
from uuid import UUID, uuid4

from agent.validation.models import canonical
from agent.validation.store import decode_json

from .config import binding_digest
from .models import Candidate, GovernanceError, Observation, now, require

SECRET_KEYS = {
    "password",
    "api_token",
    "api_key",
    "bearer_token",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "authorization",
    "credential",
    "credentials",
    "private_key",
    "secret",
    "vault_token",
}


def contains_token(value):
    """Recognize compact signed tokens even when header JSON uses unusual whitespace."""
    for match in re.finditer(r"([A-Za-z0-9_-]{2,})\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value):
        try:
            part = match.group(1)
            header = decode_json(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
            if isinstance(header, dict) and "alg" in header:
                return True
        except Exception:
            continue
    return False


def inspect(value, depth=0):
    """Count scalars and reject deep/nonfinite/secret fields before selecting any content."""
    require(depth <= 8, "source_invalid")
    if isinstance(value, dict):
        count = 0
        for key, item in value.items():
            require(isinstance(key, str) and len(key) <= 256, "source_invalid")
            normalized = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
            require(
                normalized.replace("_", "") not in {k.replace("_", "") for k in SECRET_KEYS},
                "source_invalid",
            )
            count += inspect(item, depth + 1)
    elif isinstance(value, list):
        count = sum(inspect(item, depth + 1) for item in value)
    else:
        require(value is None or type(value) in (str, bool, int, float), "source_invalid")
        if isinstance(value, str):
            require(
                not contains_token(value),
                "source_invalid",
            )
        count = 1
    require(count <= 128, "source_invalid")
    return count


def select(body, pointer):
    """Resolve one fixed JSON Pointer to a scalar, never evaluating source code."""
    value = body
    for raw in pointer[1:].split("/"):
        component = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            require(component in value, "source_invalid")
            value = value[component]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", component):
            require(int(component) < len(value), "source_invalid")
            value = value[int(component)]
        else:
            raise GovernanceError("source_invalid")
    require(not isinstance(value, (dict, list)), "source_invalid")
    return value


def authenticate(source, claims):
    """Require separate exact enrolled relay authority and bounded token freshness."""
    require(isinstance(claims, dict), "identity_rejected")
    require(
        claims.get("iss") == source.issuer
        and claims.get("sub") == source.subject
        and claims.get("aud") in (source.audience, [source.audience]),
        "identity_rejected",
    )
    scopes = claims.get("scope")
    require(isinstance(scopes, str) and "governance:observe" in scopes.split(), "identity_rejected")
    issued, expiry = claims.get("iat"), claims.get("exp")
    current = int(now().timestamp())
    require(
        type(issued) is int
        and type(expiry) is int
        and 0 < expiry - issued <= 300
        and current - 300 <= issued <= current + 30
        and expiry > current,
        "identity_rejected",
    )


def project(source, raw, received):
    """Validate and select a bounded source event; raw bodies are never journaled."""
    require(len(raw) <= 65536, "capacity_exhausted")
    try:
        body = decode_json(raw)
        require(isinstance(body, dict), "source_invalid")
        inspect(body)
        require(
            all(
                select(body, p) == v and type(select(body, p)) is type(v)
                for p, v in source.predicates.items()
            ),
            "source_invalid",
        )
        chosen = {key: select(body, p) for key, p in source.pointers.items()}
        require(type(chosen["kind"]) is str and chosen["kind"] in source.kinds, "source_invalid")
        chosen["kind"] = source.kinds[chosen["kind"]]
        for key in ("event", "object", "time"):
            require(type(chosen[key]) is str and 1 <= len(chosen[key]) <= 256, "source_invalid")
        occurred = datetime.fromisoformat(chosen["time"])
        require(
            occurred.tzinfo is not None and occurred.utcoffset().total_seconds() == 0,
            "source_invalid",
        )
        require(-30 <= (received - occurred).total_seconds() <= 300, "source_invalid")
        return chosen, occurred, hashlib.sha256(canonical(chosen)).hexdigest()
    except GovernanceError:
        raise
    except Exception:
        raise GovernanceError("source_invalid") from None


def ingest(store, alias, raw, claims, *, expected_source=None):
    """Commit before acknowledgement, rechecking the source generation under the short lock."""
    state = store.read()
    source = next((s for s in state.sources if s.alias == alias), None)
    require(source is not None, "source_not_ready")
    require(expected_source is None or source == expected_source, "configuration_changed")
    authenticate(source, claims)
    received = now()
    selected, occurred, digest = project(source, raw, received)
    receipt = None

    def update(journal):
        """Recheck the source and commit immutable event identity before acknowledgement."""
        nonlocal receipt
        current = next((s for s in journal.sources if s.alias == alias), None)
        require(current == source, "configuration_changed")
        duplicate = next(
            (
                o
                for o in journal.observations
                if o.source == alias
                and o.source_generation == source.generation
                and o.event == selected["event"]
            ),
            None,
        )
        if duplicate:
            require(duplicate.selected_digest == digest, "replay_conflict")
            receipt = {
                "schema_version": 1,
                "candidate_id": str(duplicate.candidate_id),
                "observation_id": str(duplicate.observation_id),
                "disposition": "duplicate",
            }
            return journal
        linked = next(
            (
                o
                for o in journal.observations
                if o.source == alias
                and o.source_generation == source.generation
                and o.object == selected["object"]
            ),
            None,
        )
        candidate = next(
            (c for c in journal.candidates if linked and c.candidate_id == linked.candidate_id),
            None,
        )
        candidates = journal.candidates
        if candidate is None:
            require(selected["kind"] == "unknown", "source_invalid")
            correlation = UUID(selected["correlation"]) if selected.get("correlation") else None
            candidate = next(
                (
                    c
                    for c in candidates
                    if correlation == c.case_id and c.state == "prepared" and c.source == alias
                ),
                None,
            )
            if candidate is None:
                candidate = Candidate(
                    alias="finding-" + uuid4().hex[:20],
                    source=alias,
                    source_generation=source.generation,
                    source_snapshot=source,
                    state="observed",
                )
                candidates = (*candidates, candidate)
            else:
                candidate = candidate.model_copy(
                    update={"state": "observed", "revision": candidate.revision + 1}
                )
                candidates = tuple(
                    candidate if c.candidate_id == candidate.candidate_id else c for c in candidates
                )
        require(candidate.state != "closed", "closed")
        observation = Observation(
            candidate_id=candidate.candidate_id,
            source=alias,
            source_generation=source.generation,
            source_digest=binding_digest(source),
            event=selected["event"],
            object=selected["object"],
            kind=selected["kind"],
            occurred_at=occurred,
            received_at=received,
            first_seen=selected.get("first_seen"),
            confidence=selected.get("confidence"),
            correlation=selected.get("correlation"),
            selected_digest=digest,
            provenance=source.provenance,
        )
        receipt = {
            "schema_version": 1,
            "candidate_id": str(candidate.candidate_id),
            "observation_id": str(observation.observation_id),
            "disposition": "accepted",
        }
        return journal.model_copy(
            update={"candidates": candidates, "observations": (*journal.observations, observation)}
        )

    store.change(update)
    return receipt
