"""Versioned metadata contracts. No public model accepts arbitrary text."""

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from functools import lru_cache
from importlib.resources import files
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

Label = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,63}$")]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
TraceId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
SpanId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{16}$")]
Mode = Literal["offline", "live"]
Outcome = Literal["pass", "fail", "blocked", "interrupted"]
Strength = Literal["local", "live", "mixed"]
Source = Literal["vault", "verify", "logfire"]
Cleanup = Literal["not_acquired", "revoked", "failed", "unknown"]


class Reason(StrEnum):
    invalid_selection = "invalid_selection"
    prerequisite_missing = "prerequisite_missing"
    identity_expired = "identity_expired"
    policy_denied = "policy_denied"
    approval_invalid = "approval_invalid"
    agent_run_failed = "agent_run_failed"
    cleanup_failed = "cleanup_failed"
    interrupted = "interrupted"
    limits_exceeded = "limits_exceeded"
    storage_error = "storage_error"
    source_unsupported = "source_unsupported"
    evidence_missing = "evidence_missing"
    evidence_ambiguous = "evidence_ambiguous"
    evidence_outside_window = "evidence_outside_window"
    export_incomplete = "export_incomplete"
    evidence_contradicted = "evidence_contradicted"
    digest_mismatch = "digest_mismatch"
    review_stale = "review_stale"
    review_required = "review_required"
    telemetry_export_failed = "telemetry_export_failed"
    telemetry_receipt_missing = "telemetry_receipt_missing"
    schema_invalid = "schema_invalid"
    operation_uncertain = "operation_uncertain"
    effect_not_attempted = "effect_not_attempted"
    forbidden_effect = "forbidden_effect"
    provider_unavailable = "provider_unavailable"
    provider_denied = "provider_denied"
    scenario_timeout = "scenario_timeout"
    suite_timeout = "suite_timeout"
    live_mode_required = "live_mode_required"
    interactive_required = "interactive_required"


def now() -> datetime:
    return datetime.now(UTC)


def canonical(value) -> bytes:
    def encode(item):
        if isinstance(item, BaseModel):
            return item.model_dump(mode="json")
        if isinstance(item, UUID):
            return str(item)
        if isinstance(item, datetime):
            return item.isoformat()
        raise TypeError("schema_invalid")

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=encode,
    ).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


@lru_cache(maxsize=1)
def implementation_revision():
    root = files("agent")
    names = [
        "runtime.py",
        "capabilities.py",
        "approval.py",
        "broker.py",
        "vault.py",
        "verify.py",
        "services.py",
        "oauth.py",
        "security.py",
        "schemas.py",
        "settings.py",
        "telemetry.py",
    ]
    names += [
        "validation/" + n + ".py"
        for n in (
            "models",
            "catalog",
            "store",
            "runner",
            "scenarios",
            "importers",
            "correlation",
            "review",
            "report",
            "commands",
        )
    ]
    return digest(
        {name: hashlib.sha256(root.joinpath(name).read_bytes()).hexdigest() for name in names}
    )


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)
    schema_version: Literal[1] = 1

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value):
        if type(value) is not int or value != 1:
            raise ValueError("schema_invalid")
        return value

    @field_validator("*")
    @classmethod
    def utc_only(cls, value):
        if isinstance(value, datetime) and (
            value.tzinfo is None or value.utcoffset().total_seconds()
        ):
            raise ValueError("schema_invalid")
        return value


class Bounds(Contract):
    scenario_timeout: int = Field(default=30, ge=1, le=180, strict=True)
    suite_timeout: int = Field(default=300, ge=1, le=1800, strict=True)
    cleanup_timeout: int = Field(default=30, ge=1, le=30, strict=True)


class ScenarioDefinition(Contract):
    label: Label
    factory: Label
    expected_assertions: tuple[Label, ...]
    required_capabilities: tuple[Label, ...] = ()
    criteria: tuple[str, ...] = ()
    required_sources: tuple[Source, ...] = ()

    @property
    def revision(self):
        return digest({"definition": self, "implementation": implementation_revision()})


class SuiteDefinition(Contract):
    label: Label
    mode: Mode
    interactive: bool = False
    scenarios: tuple[ScenarioDefinition, ...] = Field(min_length=1, max_length=32)
    required_checks: tuple[Literal["execution", "integrity", "cleanup"], ...]

    @property
    def revision(self):
        return digest({"definition": self, "implementation": implementation_revision()})


class Catalog(Contract):
    suites: tuple[SuiteDefinition, ...]


class ValidationRun(Contract):
    validation_id: UUID = Field(default_factory=uuid4)
    suite: Label
    suite_revision: Digest
    mode: Mode
    selected: tuple[Label, ...] = Field(min_length=1, max_length=32)
    configuration_fingerprint: Digest = Field(repr=False)
    created_at: datetime = Field(default_factory=now)
    completed_at: datetime | None = None
    bounds: Bounds = Field(default_factory=Bounds)
    state: Literal["created", "running", "finalized", "interrupted"] = "created"

    @field_validator("selected")
    @classmethod
    def unique(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("invalid_selection")
        return value


class AssertionResult(Contract):
    label: Label
    outcome: Outcome
    reason: Reason | None = None
    strength: Strength = "local"
    effect_attempts: int = Field(default=0, ge=0, strict=True)
    forbidden_effects: int = Field(default=0, ge=0, strict=True)
    references: tuple[UUID, ...] = ()


class ScenarioObservation(Contract):
    observation_id: UUID = Field(default_factory=uuid4)
    validation_id: UUID
    scenario: Label
    scenario_revision: Digest
    request_id: UUID | None = None
    run_id: UUID | None = None
    started_at: datetime = Field(default_factory=now)
    finished_at: datetime = Field(default_factory=now)
    outcome: Outcome
    reason: Reason | None = None
    assertions: tuple[AssertionResult, ...] = ()
    cleanup: Cleanup = "not_acquired"
    operation_outcome: Outcome | None = None


class LifecycleEvent(Contract):
    event_id: UUID = Field(default_factory=uuid4)
    validation_id: UUID | None = None
    observation_id: UUID | None = None
    request_id: UUID
    run_id: UUID
    parent_run_id: UUID | None = None
    agent_ref: UUID
    workload_ref: UUID
    phase: Literal[
        "run",
        "delegation",
        "policy",
        "approval",
        "identity",
        "credential",
        "database",
        "cleanup",
        "telemetry",
        "report",
    ]
    detail: Literal[
        "started",
        "completed",
        "failed",
        "denied",
        "allowed",
        "pending",
        "contained",
        "interrupted",
        "acquired",
        "revoked",
        "verified",
        "attempted",
        "acknowledged",
        "received",
        "blocked",
    ]
    outcome: Outcome | None = None
    reason: Reason | None = None
    duration: float = Field(default=0, ge=0, allow_inf_nan=False)
    created_at: datetime = Field(default_factory=now)
    trace_id: TraceId | None = None
    span_id: SpanId | None = None
    operation_ref: UUID | None = None
    lease_ref: UUID | None = None
    approval_ref: UUID | None = None


class PrivateOperationBinding(Contract):
    operation_ref: UUID = Field(default_factory=uuid4)
    validation_id: UUID
    observation_id: UUID
    run_id: UUID
    parent_run_id: UUID | None = None
    phase: Literal["identity", "credential", "database", "cleanup", "approval", "telemetry"]
    source_kind: Source
    expected_outcome: Literal["success", "denied"] = "success"
    source_instance: str = Field(min_length=1, max_length=128, repr=False)
    native_request_id: str | None = Field(default=None, min_length=1, max_length=512, repr=False)
    native_transaction_id: str | None = Field(
        default=None, min_length=1, max_length=512, repr=False
    )
    native_lease_id: str | None = Field(default=None, min_length=1, max_length=512, repr=False)
    trace_id: TraceId | None = None
    span_id: SpanId | None = None
    parent_span_id: SpanId | None = None
    started_at: datetime = Field(default_factory=now)
    finished_at: datetime | None = None


class ImportManifest(Contract):
    source_kind: Source
    format_label: Literal["vault-jsonl", "verify-events", "logfire-rows"]
    format_version: Literal[1] = 1
    source_instance: str = Field(min_length=1, max_length=128, repr=False)
    window_start: datetime
    window_end: datetime
    completeness: Literal["complete", "partial", "unknown"]
    provenance: Literal["operator_export"] = "operator_export"
    audit_device_context: str | None = Field(default=None, min_length=1, max_length=512, repr=False)

    @model_validator(mode="after")
    def window(self):
        if self.window_start > self.window_end:
            raise ValueError("schema_invalid")
        expected = {"vault": "vault-jsonl", "verify": "verify-events", "logfire": "logfire-rows"}
        if expected[self.source_kind] != self.format_label:
            raise ValueError("source_unsupported")
        return self


NativeId = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class NormalizedSourceEvent(Contract):
    source_event_id: NativeId = Field(repr=False)
    source_kind: Source
    source_instance: str = Field(min_length=1, max_length=128, repr=False)
    observed_at: datetime
    kind: Literal["request", "response", "audit", "span"]
    native_request_id: NativeId | None = Field(default=None, repr=False)
    native_transaction_id: NativeId | None = Field(default=None, repr=False)
    native_correlation_id: NativeId | None = Field(default=None, repr=False)
    native_lease_id: NativeId | None = Field(default=None, repr=False)
    operation_ref: UUID | None = None
    validation_id: UUID | None = None
    run_id: UUID | None = None
    parent_run_id: UUID | None = None
    trace_id: TraceId | None = None
    span_id: SpanId | None = None
    parent_span_id: SpanId | None = None
    phase: Literal["credential", "cleanup", "approval", "identity", "telemetry"] | None = None
    outcome: Literal["success", "denied", "failed", "unknown"] = "unknown"


class SourceArtifact(Contract):
    artifact_id: UUID = Field(default_factory=uuid4)
    manifest: ImportManifest = Field(repr=False)
    raw_digest: Digest
    normalized_digest: Digest
    bytes_count: int = Field(ge=0, le=10 * 1024 * 1024)
    event_count: int = Field(ge=0, le=10_000)
    imported_at: datetime = Field(default_factory=now)
    events: tuple[NormalizedSourceEvent, ...] = Field(repr=False)


class CorrelationResult(Contract):
    correlation_id: UUID = Field(default_factory=uuid4)
    operation_ref: UUID
    artifact_refs: tuple[UUID, ...] = ()
    method: Literal["vault-request-v1", "verify-unsupported-v1", "logfire-trace-v1"]
    status: Literal[
        "matched",
        "missing",
        "unsupported",
        "ambiguous",
        "outside_window",
        "incomplete_export",
        "contradicted",
    ]
    reason: Reason | None = None

    @property
    def outcome(self):
        return (
            "pass"
            if self.status == "matched"
            else ("fail" if self.status == "contradicted" else "blocked")
        )


class TransactionEvidence(Contract):
    artifact_id: UUID = Field(default_factory=uuid4)
    validation_id: UUID
    observation_id: UUID
    run_id: UUID
    source_instance: str = Field(min_length=1, max_length=128, repr=False)
    native_transaction_id: NativeId = Field(repr=False)
    approval_ref: UUID
    action_digest: Digest
    decision: Literal["approved", "denied"]
    observed_at: datetime = Field(default_factory=now)
    raw_digest: Digest
    provenance: Literal["transaction_response"] = "transaction_response"
