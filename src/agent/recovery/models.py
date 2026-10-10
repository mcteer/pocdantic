"""Strict private recovery records and closed, credential-free public projections.

Revisions prevent stale reconciliation. Native handles and environment fingerprints
belong only in private records; public messages come from fixed reason/action mappings.
"""

import re
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Revision = Annotated[StrictInt, Field(gt=0)]
Native = Annotated[str, Field(min_length=1, max_length=1024)]
State = Literal["intent", "acquired", "cleanup_pending", "unresolved", "resolved"]
Resolution = Literal["revoked", "not_issued"]
REASONS = {
    "configuration_missing": ("configuration", "configure"),
    "dependency_unreachable": ("connection", "check_connection"),
    "diagnostic_timeout": ("connection", "check_provider"),
    "provider_access_denied": ("credential", "contact_operator"),
    "sign_in_required": ("identity", "sign_in"),
    "acquisition_uncertain": ("credential", "inspect_evidence"),
    "cleanup_unconfirmed": ("cleanup", "recover_exact_lease"),
    "recovery_uninitialized": ("storage", "initialize"),
    "recovery_storage_error": ("storage", "repair_storage"),
    "recovery_environment_mismatch": ("storage", "restore_configuration"),
    "recovery_evidence_required": ("recovery", "obtain_native_evidence"),
    "recovery_evidence_invalid": ("recovery", "inspect_evidence"),
    "recovery_access_denied": ("recovery", "contact_operator"),
    "recovery_busy": ("recovery", "wait"),
    "recovery_capacity": ("storage", "resolve_incidents"),
    "diagnostics_busy": ("connection", "wait"),
}


def now():
    """Return an aware UTC wall-clock timestamp for durable provenance."""
    return datetime.now(UTC)


def valid_handle(path, handle):
    """Require a native lease under the exact credential path, with the supported suffix grammar."""
    prefix = path + "/"
    return (
        isinstance(handle, str)
        and handle.startswith(prefix)
        and bool(re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", handle[len(prefix) :]))
    )


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    schema_version: Literal[1] = 1

    @field_validator("schema_version", mode="before")
    @classmethod
    def version(cls, value):
        """Reject coercion and unsupported schema versions before parsing other fields."""
        if type(value) is not int or value != 1:
            raise ValueError("recovery_storage_error")
        return value

    @model_validator(mode="after")
    def utc(self):
        """Require all contract timestamps to be timezone-aware UTC."""
        for value in self.__dict__.values():
            if isinstance(value, datetime) and (
                value.tzinfo is None or value.utcoffset().total_seconds()
            ):
                raise ValueError("recovery_storage_error")
        return self


class Private(Contract):
    def __repr__(self):
        """Hide native fields from debugging representations."""
        return f"{type(self).__name__}(private)"

    def __str__(self):
        """Use the same non-revealing representation for string formatting."""
        return repr(self)


class Receipt(Private):
    outcome: Literal["lease_identified", "revoked", "not_issued"]
    incident_id: UUID
    incident_revision: Revision
    operation_id: UUID
    environment_digest: Digest
    native_request_id: Native | None = None
    native_response_id: Native | None = None
    source_digests: tuple[Digest, ...] = Field(default=(), max_length=2)
    verifier_version: Literal[1] = 1
    checked_at: datetime = Field(default_factory=now)
    reviewer_label: str | None = Field(default=None, min_length=1, max_length=64)
    reviewed_at: datetime | None = None

    @model_validator(mode="after")
    def imported(self):
        """Imported proof requires explicit provenance review and native pair identifiers."""
        if type(self.verifier_version) is not int or self.verifier_version != 1:
            raise ValueError("recovery_evidence_invalid")
        if self.source_digests and (
            not self.reviewer_label
            or not self.reviewer_label.strip()
            or not self.reviewed_at
            or not self.native_request_id
            or self.native_request_id != self.native_response_id
            or len(set(self.source_digests)) != len(self.source_digests)
        ):
            raise ValueError("recovery_evidence_invalid")
        return self


class Summary(Contract):
    incident_id: UUID
    stage: str
    reason_code: str
    next_action: str

    @model_validator(mode="after")
    def mapping(self):
        """Require incident explanations to use the closed reason/stage/action catalog."""
        if REASONS.get(self.reason_code) != (self.stage, self.next_action):
            raise ValueError("recovery_evidence_invalid")
        return self


class Attempt(Private):
    incident_id: UUID
    operation_id: UUID
    environment_digest: Digest
    revision: Revision = 1
    credential_path: str = Field(min_length=1, max_length=256)
    state: State = "intent"
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)
    native_request_id: Native | None = None
    lease_handle: Native | None = None
    reason_code: str = "acquisition_uncertain"
    resolution: Resolution | None = None
    receipt: Receipt | None = None

    @model_validator(mode="after")
    def consistent(self):
        """Validate path, handle scope, terminal state, and exact receipt binding."""
        from agent.vault import validate_path

        try:
            validate_path(self.credential_path)
        except Exception:
            raise ValueError("recovery_storage_error") from None
        if (
            not self.credential_path.startswith("database/creds/")
            or self.credential_path == "database/creds/"
            or self.reason_code not in REASONS
            or self.lease_handle is not None
            and not valid_handle(self.credential_path, self.lease_handle)
        ):
            raise ValueError("recovery_storage_error")
        if self.state in {"acquired", "cleanup_pending"} and not self.lease_handle:
            raise ValueError("recovery_storage_error")
        if self.state == "resolved":
            if not self.resolution or not self.receipt or self.receipt.outcome != self.resolution:
                raise ValueError("recovery_storage_error")
            if self.resolution == "revoked" and not self.lease_handle:
                raise ValueError("recovery_storage_error")
            if self.resolution == "not_issued" and self.lease_handle:
                raise ValueError("recovery_storage_error")
        elif self.receipt and self.receipt.outcome != "lease_identified":
            raise ValueError("recovery_storage_error")
        elif self.resolution is not None:
            raise ValueError("recovery_storage_error")
        if self.receipt and (
            self.receipt.incident_id != self.incident_id
            or self.receipt.operation_id != self.operation_id
            or self.receipt.environment_digest != self.environment_digest
            or self.receipt.incident_revision > self.revision
        ):
            raise ValueError("recovery_evidence_invalid")
        return self

    def summary(self):
        """Project only the opaque incident reference and fixed next-step codes."""
        stage, action = REASONS[self.reason_code]
        return Summary(
            incident_id=self.incident_id,
            stage=stage,
            reason_code=self.reason_code,
            next_action=action,
        )


class Anchor(Private):
    installation_id: UUID


class Journal(Private):
    installation_id: UUID
    environment_digest: Digest
    revision: Revision = 1
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)
    attempts: tuple[Attempt, ...] = Field(default=(), max_length=1000)

    @model_validator(mode="after")
    def consistent(self):
        """Reject duplicate IDs, foreign environments, and excessive unresolved attempts."""
        if (
            len({a.incident_id for a in self.attempts}) != len(self.attempts)
            or len({a.operation_id for a in self.attempts}) != len(self.attempts)
            or any(a.environment_digest != self.environment_digest for a in self.attempts)
            or sum(a.state != "resolved" for a in self.attempts) > 100
        ):
            raise ValueError("recovery_storage_error")
        return self


class OperationalView(Contract):
    authentication: StrictBool
    connection: Literal["unchecked", "observed", "blocked", "inconclusive"] = "unchecked"
    recovery: Literal["not_configured", "uninitialized", "clear", "blocked", "storage_error"] = (
        "not_configured"
    )
    active_work: StrictBool = False
    blocked_count: Annotated[StrictInt, Field(ge=0)] = 0
    checked_at: datetime | None = None
    reason_code: str | None = None
    next_action: str | None = None
    incidents: tuple[Summary, ...] = ()

    @model_validator(mode="after")
    def mapping(self):
        """Keep aggregate reasons and actions within the same closed public contract."""
        if self.reason_code is None:
            if self.next_action is not None:
                raise ValueError("recovery_evidence_invalid")
        elif self.reason_code not in REASONS or self.next_action != REASONS[self.reason_code][1]:
            raise ValueError("recovery_evidence_invalid")
        return self
