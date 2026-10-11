"""Fixed private operator inputs and metadata-only readiness.

Drafts are untrusted until strict validation and exact metadata comparison. They never
supply executable adapters, runtime authority or token-selected destinations.
"""

import hashlib
import os
import re
from datetime import datetime, timedelta

from pydantic import Field, SecretStr, StrictBool

from agent.recovery.store import check_stat
from agent.validation.models import canonical
from agent.validation.store import decode_json

from .models import (
    Alias,
    Binding,
    Digest,
    GovernanceError,
    Native,
    Readiness,
    Record,
    Source,
    now,
    require,
)


class Draft(Record):
    """Source activation input with no candidate credentials or provider mutations."""

    sources: tuple[Source, ...] = Field(default=(), max_length=16)


class Client(Record):
    """Private credentials and reviewed subject for one distinct OAuth client."""

    alias: Alias
    subject: Native
    client_id: SecretStr = Field(min_length=1, max_length=256)
    client_secret: SecretStr = Field(min_length=1, max_length=16384)


class Secrets(Record):
    """Trusted credentials for fixed reviewed roles; representation is always private."""

    operator: SecretStr | None = Field(default=None, min_length=1, max_length=16384)
    candidate: Client | None = None
    healthy: Client | None = None


def fixed_name(name):
    """Accept only compiled draft names, preventing arbitrary filesystem input."""
    return (
        name in {"config.draft.json", "secrets.json"}
        or bool(re.fullmatch(r"review-[a-f0-9-]{36}\.json", name))
        or bool(re.fullmatch(r"candidate-[a-f0-9-]{36}\.draft\.json", name))
    )


def read_private(store, name, *, limit=1024 * 1024):
    """Read one owned bounded file through verified descriptors, rejecting replacement."""
    require(fixed_name(name))
    try:
        with store._directory() as directory:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, "rb") as file:
                before = os.fstat(file.fileno())
                check_stat(before)
                raw = file.read(limit + 1)
                after = os.stat(name, dir_fd=directory, follow_symlinks=False)
                require(
                    (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "storage_error"
                )
                require(len(raw) <= limit, "capacity_exhausted")
                return decode_json(raw)
    except GovernanceError:
        raise
    except Exception:
        raise GovernanceError("invalid_input") from None


def create_private(store, name, value):
    """Create a template exclusively; existing operator work is never overwritten."""
    require(fixed_name(name))
    try:
        with store._directory() as directory:
            fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
            )
            with os.fdopen(fd, "wb") as file:
                file.write(canonical(value))
                file.flush()
                os.fsync(file.fileno())
            os.fsync(directory)
    except Exception:
        raise GovernanceError("storage_error") from None


def binding_digest(binding):
    """Fingerprint all reviewed inputs without publishing their values."""
    return hashlib.sha256(canonical(binding)).hexdigest()


def fresh(binding, readiness):
    """Require readiness within five minutes and the exact unchanged binding."""
    age = now() - readiness.checked_at
    return (
        readiness.ready
        and timedelta(0) <= age <= timedelta(seconds=300)
        and readiness.binding_digest == binding_digest(binding)
    )


async def readiness(binding, adapter):
    """Read exact metadata only; any failure or mismatch prevents native effects."""
    require(isinstance(binding, Binding))
    try:
        fingerprints = await adapter.metadata(binding)
        expected = {
            "role": binding.trust.role_digest,
            "config": binding.trust.config_digest,
            "entitlement": binding.entitlement_digest,
            **{f"policy-{k}": v for k, v in binding.policies.items()},
        }
        require(all(fingerprints.get(k) == v for k, v in expected.items()), "configuration_changed")
        require(
            fingerprints.get("entity") is not None
            and fingerprints.get("alias") is not None
            and fingerprints.get("oauth_profile") is not None,
            "missing_authority",
        )
        return Readiness(
            binding_digest=binding_digest(binding),
            metadata_digest=binding_digest(fingerprints),
            ready=True,
            reason="ok",
            fingerprints=fingerprints,
            checks={
                stage: "ok"
                for stage in (
                    "enterprise",
                    "entity",
                    "alias",
                    "oauth",
                    "license",
                    "spiffe",
                    "policies",
                    "mounts",
                    "operator",
                    "registry",
                )
            },
        )
    except Exception as error:
        reason = str(error) if isinstance(error, GovernanceError) else "configuration_changed"
        stage = getattr(adapter, "stage", "configuration")
        return Readiness(
            binding_digest=binding_digest(binding),
            metadata_digest="0" * 64,
            ready=False,
            reason=reason,
            checks={stage: reason},
        )


class Entitlement(Record):
    """Expiring host review of independent license evidence, bound to one deployment."""

    origin: Native
    namespace: str
    model_config = {"populate_by_name": True, "serialize_by_alias": True}
    product_version: Native = Field(alias="version")
    registry: StrictBool
    spiffe: StrictBool
    artifact_digest: Digest
    reviewed_by: Alias
    reviewed_at: datetime
    expires_at: datetime
    digest: Digest


class CandidateDraft(Record):
    """Host-reviewed candidate mapping and independently reviewed entitlement receipt."""

    binding: Binding | None = None
    entitlement: Entitlement | None = None


def activate(store, candidate_id, draft, snapshot, *, revision):
    """Commit a checked draft, invalidating dependent reviews on an actual binding change.

    Registration attempts and unresolved credentials pin their exact profile; changing
    that profile is refused rather than disconnecting already dispatched effects.
    """
    require(draft.binding is not None)

    def update(state):
        """Compare current case and retain original observations while activating metadata."""
        candidate = next((c for c in state.candidates if c.candidate_id == candidate_id), None)
        require(candidate and candidate.state != "closed", "closed")
        changed = candidate.binding is not None and candidate.binding != draft.binding
        require(
            not changed or not any(a.candidate_id == candidate_id for a in state.registrations),
            "configuration_changed",
        )
        require(
            not changed
            or not any(
                i.candidate_id == candidate_id
                and i.state != "denied"
                and (i.safe_after is None or i.safe_after > now())
                for i in state.credentials
            ),
            "issuance_unresolved",
        )
        updated = candidate.model_copy(
            update={
                "binding": draft.binding,
                "readiness": snapshot,
                "revision": candidate.revision + 1,
                "generation": candidate.generation + int(changed),
                "state": "registered"
                if candidate.state == "registered"
                else "observed"
                if any(
                    o.candidate_id == candidate_id and o.kind == "unknown"
                    for o in state.observations
                )
                else "prepared",
                "reason": snapshot.reason,
            }
        )
        require(
            candidate.state != "enrolling"
            and (candidate.state != "registered" or candidate.binding == draft.binding),
            "configuration_changed",
        )
        return state.model_copy(
            update={
                "candidates": tuple(
                    updated if c.candidate_id == candidate_id else c for c in state.candidates
                ),
                "reviews": tuple(
                    r for r in state.reviews if r.candidate_id != candidate_id or r.consumed
                ),
            }
        )

    return store.change(update, revision=revision)
