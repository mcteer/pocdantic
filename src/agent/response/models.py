"""Strict private incident contracts and closed, credential-free public projections.

Validated models are immutable. Raw signals, JWTs and provider credentials have no
storage field; exception messages use only the fixed reason catalog.
"""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from agent.recovery.models import Contract, Digest, Private, Revision, now
from agent.security import SecurityError

Definition = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")]
EventID = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
Milliseconds = Annotated[StrictInt, Field(ge=0)]
REASONS = {
    "source_invalid": "correct_request",
    "signal_invalid": "correct_request",
    "signal_stale": "correct_request",
    "target_unknown": "correct_request",
    "event_conflict": "correct_request",
    "response_uninitialized": "initialize_response",
    "response_migration_required": "migrate_recovery",
    "response_storage_error": "repair_storage",
    "response_policy_changed": "restore_configuration",
    "response_capacity": "resolve_incidents",
    "response_busy": "wait_for_owner",
    "contained": "inspect_incident",
    "owner_draining": "wait_for_owner",
    "legacy_unattributed": "review_recovery",
    "acquisition_uncertain": "review_recovery",
    "cleanup_denied": "recover_exact_lease",
    "cleanup_uncertain": "recover_exact_lease",
    "cleanup_failed": "recover_exact_lease",
    "release_unsafe": "inspect_hold",
    "revision_conflict": "inspect_hold",
    "timing_unavailable": "review_limitations",
    "external_control_not_performed": "review_limitations",
    "response_schema_migration_required": "migrate_response",
}


REASONS.update(
    {
        reason: "inspect_provider_response"
        for reason in (
            "not_enrolled",
            "mapping_missing",
            "missing_authority",
            "unsupported",
            "source_evidence_missing",
            "destination_invalid",
            "provider_unreachable",
            "proof_required",
            "provider_acknowledged",
            "provider_denied",
            "provider_uncertain",
            "provider_failed",
            "provider_state_observed",
            "provider_capacity",
            "provider_busy",
            "provider_policy_changed",
            "provider_evidence_invalid",
            "provider_dependency",
            "provider_timeout",
            "provider_retry_review",
            "old_credential_unsafe",
            "probe_ready",
            "probe_denied",
            "probe_issued",
            "probe_uncertain",
            "provider_reconciled",
            "notification_accepted",
            "notification_delivered",
        )
    }
)


class ResponseError(SecurityError):
    """Expose a closed response reason, never private inputs or filesystem details."""

    def __init__(self, reason="response_storage_error"):
        """Replace unknown failure text with the generic closed storage reason."""
        super().__init__(reason if reason in REASONS else "response_storage_error")


class RootTarget(Private):
    """An exact trusted root; child IDs are not independent response targets."""

    kind: Literal["root_run"] = "root_run"
    root_run_id: UUID


class DefinitionTarget(Private):
    """The configured stable definition, independent of telemetry UUIDs."""

    kind: Literal["definition"] = "definition"
    workload_definition: Definition


Target = Annotated[RootTarget | DefinitionTarget, Field(discriminator="kind")]


class RiskSignal(Private):
    """Normalized bounded relay input, without caller-selected remediation actions."""

    event_id: EventID
    occurred_at: datetime
    reason: Literal["suspected_compromise", "policy_violation"]
    target: Target


class Source(Private):
    """One exact verified automation identity and its allowed local target scopes."""

    alias: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")]
    issuer: Annotated[str, Field(min_length=1, max_length=2048)]
    subject: Annotated[str, Field(min_length=1, max_length=256)]
    allowed_scopes: frozenset[Literal["root_run", "definition"]] = Field(min_length=1, max_length=2)

    @model_validator(mode="after")
    def reserved(self):
        """Keep the OS operator namespace unavailable to remote credentials."""
        if self.alias == "local-operator":
            raise ValueError("source_invalid")
        return self


class SourcePolicy(Private):
    """Enrolled nonsecret mapping; cleanup authority remains in existing settings."""

    intake_mode: Literal["local_only", "relay"] = "local_only"
    sources: tuple[Source, ...] = Field(default=(), max_length=16)
    audience: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    workload_definition: Definition
    environment_digest: Digest
    issuer: Annotated[str, Field(min_length=1, max_length=2048)]
    automatic_cleanup: StrictBool = False

    @model_validator(mode="after")
    def mapping(self):
        """Reject incomplete modes, ambiguous sources and foreign issuer mappings."""
        if (
            self.intake_mode == "local_only"
            and (self.sources or self.audience is not None)
            or self.intake_mode == "relay"
            and (not self.sources or not self.audience)
            or len({s.alias for s in self.sources}) != len(self.sources)
            or len({(s.issuer, s.subject) for s in self.sources}) != len(self.sources)
            or any(s.issuer != self.issuer for s in self.sources)
        ):
            raise ValueError("source_invalid")
        return self


class RunBinding(Private):
    """Host-derived identity for a root and all descendants until actual drain."""

    root_run_id: UUID
    request_id: UUID
    workload_definition: Definition
    generation: Revision
    issuer: Annotated[str, Field(min_length=1, max_length=2048)]
    subject: Annotated[str, Field(min_length=1, max_length=256)]
    actor_issuer: str | None = Field(default=None, max_length=2048)
    actor_subject: str | None = Field(default=None, max_length=256)
    started_at: datetime = Field(default_factory=now)
    finished_at: datetime | None = None
    state: Literal["active", "terminal"] = "active"

    def ownership(self):
        """Return only immutable attribution fields for a prospective acquisition."""
        from agent.recovery.models import BoundOwnership

        return BoundOwnership(
            **{
                key: getattr(self, key)
                for key in (
                    "root_run_id",
                    "request_id",
                    "workload_definition",
                    "generation",
                    "issuer",
                    "subject",
                )
            }
        )


class ResponseAnchor(Private):
    """Enrollment identity; absent recovery is an explicit, non-repairable mode."""

    installation_id: UUID
    recovery_mode: Literal["configured", "not_configured"]
    recovery_installation_id: UUID | None = None

    @model_validator(mode="after")
    def recovery_binding(self):
        """Missing configured state cannot be interpreted as no database integration."""
        if (self.recovery_mode == "configured") != (self.recovery_installation_id is not None):
            raise ValueError("response_storage_error")
        return self


class ResponseAction(Private):
    """Durable exact action intent; a submitted effect may be uncertain after a crash."""

    action_id: UUID = Field(default_factory=uuid4)
    kind: Literal["cancel_local", "revoke_exact"]
    target_id: UUID
    status: Literal["planned", "submitted", "confirmed", "denied", "failed", "uncertain"] = (
        "planned"
    )
    intent_at: datetime = Field(default_factory=now)
    completed_at: datetime | None = None
    reason_code: str = "contained"

    @field_validator("reason_code")
    @classmethod
    def reason(cls, value):
        """Disallow arbitrary provider exception text in private or public action reports."""
        if value not in REASONS:
            raise ValueError("response_storage_error")
        return value


class Incident(Private):
    """Immutable event identity and target with independently persisted action outcomes."""

    incident_id: UUID = Field(default_factory=uuid4)
    source: Annotated[str, Field(min_length=1, max_length=32)]
    event_id: EventID
    payload_digest: Digest
    policy_digest: Digest
    target: Target
    revision: Revision = 1
    generation: Revision = 1
    source_at: datetime
    received_at: datetime = Field(default_factory=now)
    contained_at: datetime = Field(default_factory=now)
    phase: Literal["contained", "responding", "partial", "settled"] = "contained"
    reason_code: str = "contained"
    actions: tuple[ResponseAction, ...] = Field(min_length=1, max_length=101)
    cancel_ms: Milliseconds | None = None
    cleanup_ms: Milliseconds | None = None
    worker_ms: Milliseconds | None = None

    @field_validator("reason_code")
    @classmethod
    def reason(cls, value):
        """Keep incident failures within the same closed projection catalog."""
        if value not in REASONS:
            raise ValueError("response_storage_error")
        return value

    @model_validator(mode="after")
    def cancellation_target(self):
        """Every retained incident has exactly one cancellation action for itself."""
        cancellations = [a for a in self.actions if a.kind == "cancel_local"]
        if len(cancellations) != 1 or cancellations[0].target_id != self.incident_id:
            raise ValueError("response_storage_error")
        if len({a.action_id for a in self.actions}) != len(self.actions):
            raise ValueError("response_storage_error")
        return self

    def matches(self, run):
        """Match only trusted immutable root/definition attribution, never timestamps."""
        return (
            run.root_run_id == self.target.root_run_id
            if self.target.kind == "root_run"
            else run.workload_definition == self.target.workload_definition
            and run.generation <= self.generation
        )


class DefinitionHold(Private):
    """Current definition generation and its complete set of unresolved local holds."""

    workload_definition: Definition
    generation: Revision
    incident_ids: tuple[UUID, ...] = Field(min_length=1, max_length=1000)


class ReleaseRecord(Private):
    """Revision-bound local release provenance; it never changes provider state."""

    release_id: UUID = Field(default_factory=uuid4)
    workload_definition: Definition
    incident_ids: tuple[UUID, ...] = Field(min_length=1, max_length=1000)
    expected_revision: Revision
    new_generation: Revision
    released_at: datetime = Field(default_factory=now)
    operator: Annotated[str, Field(min_length=1, max_length=64)]

    @field_validator("operator")
    @classmethod
    def label(cls, value):
        """Reject blank provenance labels without pretending the label authenticates."""
        if not value.strip():
            raise ValueError("signal_invalid")
        return value


class ResponseJournal(Private):
    """One atomic bounded snapshot containing holds and the facts needed to enforce them."""

    installation_id: UUID
    environment_digest: Digest
    policy_digest: Digest
    revision: Revision = 1
    generation: Revision = 1
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)
    runs: tuple[RunBinding, ...] = Field(default=(), max_length=1000)
    incidents: tuple[Incident, ...] = Field(default=(), max_length=1000)
    holds: tuple[DefinitionHold, ...] = Field(default=(), max_length=1)
    root_holds: tuple[UUID, ...] = Field(default=(), max_length=1000)
    releases: tuple[ReleaseRecord, ...] = Field(default=(), max_length=1000)

    @model_validator(mode="after")
    def unique(self):
        """Reject collisions, dangling scope references and overfull response queues."""
        ids = {i.incident_id for i in self.incidents}
        run_ids = {r.root_run_id for r in self.runs}
        actions = [a.action_id for i in self.incidents for a in i.actions]
        if (
            len(ids) != len(self.incidents)
            or len(run_ids) != len(self.runs)
            or len({(i.source, i.event_id) for i in self.incidents}) != len(self.incidents)
            or len(set(actions)) != len(actions)
            or len(set(self.root_holds)) != len(self.root_holds)
            or not set(self.root_holds) <= run_ids
            or any(not set(h.incident_ids) <= ids for h in self.holds)
            or sum(i.phase != "settled" for i in self.incidents) > 16
        ):
            raise ValueError("response_storage_error")
        return self


class PublicTimingInterval(Contract):
    """An available cross-clock interval, explicitly bounded instead of presented as exact."""

    lower_ms: Milliseconds
    upper_ms: Milliseconds
    uncertainty_ms: Milliseconds

    @model_validator(mode="after")
    def ordered(self):
        """Reject inverted intervals before projecting a timing claim."""
        if self.upper_ms < self.lower_ms:
            raise ValueError("timing_unavailable")
        return self


class PublicProviderControl(Contract):
    """Owned additive control result containing only closed codes and opaque references."""

    action_id: UUID
    attempt_ms: Milliseconds | None = None
    source_to_loss: PublicTimingInterval | None = None
    kind: Literal[
        "block_registration",
        "revoke_native_token",
        "suspend_user",
        "revoke_user_sessions",
        "rotate_static",
        "terminate_static_sessions",
        "notify_teams",
    ]
    state: Literal[
        "planned", "submitted", "acknowledged", "denied", "failed", "uncertain", "reconciled"
    ]
    required: StrictBool
    reason_code: Literal[
        "not_enrolled",
        "mapping_missing",
        "missing_authority",
        "unsupported",
        "source_evidence_missing",
        "destination_invalid",
        "provider_unreachable",
        "proof_required",
        "provider_acknowledged",
        "provider_denied",
        "provider_uncertain",
        "provider_failed",
        "provider_state_observed",
        "provider_capacity",
        "provider_busy",
        "provider_policy_changed",
        "provider_evidence_invalid",
        "provider_dependency",
        "provider_timeout",
        "provider_retry_review",
        "old_credential_unsafe",
        "probe_ready",
        "probe_denied",
        "probe_issued",
        "probe_uncertain",
        "provider_reconciled",
        "notification_accepted",
        "notification_delivered",
        "timing_unavailable",
    ]
    paths: dict[
        Literal[
            "registration",
            "native_token",
            "native_token_readback",
            "tenant_session_readback",
            "static_session_readback",
            "tenant_user",
            "tenant_sessions",
            "same_jwt",
            "fresh_issuance",
            "static_old",
            "static_new",
            "static_session",
            "notification",
        ],
        Literal["not_run", "proven", "disproven", "inconclusive", "unsupported", "not_applicable"],
    ]
    provenance: Literal["local_only", "synthetic", "native"]


class PublicSummary(Contract):
    """Session/source-owned safe result with no native identifiers or mappings."""

    incident_id: UUID
    scope: Literal["root_run", "definition"]
    phase: Literal["contained", "responding", "partial", "settled"]
    contained: StrictBool
    provider_controls: tuple[PublicProviderControl, ...] = Field(default=(), max_length=16)
    database_checks: dict[
        Literal["dynamic_fresh", "dynamic_session"],
        Literal["not_run", "proven", "disproven", "inconclusive", "unsupported", "not_applicable"],
    ] = Field(default_factory=dict)
    cleanup: Literal["pending", "confirmed", "not_applicable"]
    reason_code: str
    next_action: str
    observed_at: datetime = Field(default_factory=now)

    @model_validator(mode="after")
    def reason_mapping(self):
        """Prevent arbitrary user-facing repair instructions from provider payloads."""
        if self.reason_code not in REASONS or self.next_action != REASONS[self.reason_code]:
            raise ValueError("response_storage_error")
        return self
