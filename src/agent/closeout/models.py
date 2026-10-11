"""Strict, bounded closeout contracts and deterministic confidential evidence encoding.

JSON validation permits only JSON's UUID/time representations, never general Python coercion.
Private payloads stay behind explicit public projections; callers return closed failure codes.
"""

import hashlib
import json
import math
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator, model_validator

from agent.evidence import CRITERIA

ROLES = ("agent_engineering", "verify_owner", "vault_owner", "vip_owner", "customer_security")
SCENARIOS = ("agent-repeat", "agent-only-users", "agent-obo-users", "direct-users")
REASONS = frozenset(
    {
        "schema_invalid",
        "source_unsupported",
        "evidence_missing",
        "evidence_conflict",
        "context_mismatch",
        "input_changed",
        "review_stale",
        "review_conflict",
        "source_expired",
        "revision_conflict",
        "capacity_exceeded",
        "integrity_failed",
        "storage_invalid",
        "deadline_exceeded",
        "interrupted",
        "source_unreviewed",
        "proof_incomplete",
        "witness_missing",
        "approval_missing",
        "reporting_delay",
        "cohort_invalid",
        "baseline_invalid",
        "execution_surface_unavailable",
        "cleanup_outstanding",
    }
)
Reason = Literal[*sorted(REASONS)]
Role = Literal["agent_engineering", "verify_owner", "vault_owner", "vip_owner", "customer_security"]
Scenario = Literal["agent-repeat", "agent-only-users", "agent-obo-users", "direct-users"]
Outcome = Literal["pass", "fail", "blocked"]
Provenance = Literal["synthetic", "operator", "native"]
Applicability = Literal["current", "historical", "missing", "invalid"]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Private = Annotated[str, Field(min_length=1, max_length=256)]
Revision = Annotated[int, Field(ge=1, le=100)]
Count = Annotated[int, Field(ge=0, le=10000)]
Pointer = Annotated[str, Field(max_length=256, pattern=r"^(|/[^*]*)$")]
Format = Literal[
    "vault-audit-v1",
    "vault-audit-v2",
    "verify-events-v1",
    "logfire-v1",
    "logfire-v2",
    "native-facts-v1",
    "vault-activity-v1",
    "execution-roster-v1",
    "entity-mapping-v1",
    "attachment-v1",
]


class CloseoutError(ValueError):
    """Carry a closed error code without retaining source bytes or provider diagnostics."""

    def __init__(self, reason="schema_invalid"):
        """Normalize any internal error to a public code before exception formatting."""
        self.reason = reason if reason in REASONS else "schema_invalid"
        super().__init__(self.reason)


def require(condition, reason="schema_invalid"):
    """Reject a violated contract with a safe reason, never the offending value."""
    if not condition:
        raise CloseoutError(reason)


def now():
    """Return the actual UTC evaluation clock; source input cannot override this clock."""
    return datetime.now(UTC)


def canonical_uuid(value):
    """Reject noncanonical UUID text even when the UUID parser would normalize it."""
    if isinstance(value, UUID):
        return value
    require(isinstance(value, str) and str(UUID(value)) == value)
    return value


Id = Annotated[UUID, BeforeValidator(canonical_uuid)]


class Contract(BaseModel):
    """Forbid unknown fields and coercion at every maintained boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)

    @field_validator("schema_version", mode="before", check_fields=False)
    @classmethod
    def strict_version(cls, value):
        """Prevent bool/float equality from satisfying the literal version contract."""
        require(type(value) is int and value == 1)
        return value

    @field_validator("*", mode="after")
    @classmethod
    def valid_values(cls, value):
        """Reject naive times and nonfinite floats independent of their field names."""
        if isinstance(value, datetime):
            require(value.tzinfo is not None and value.utcoffset().total_seconds() == 0)
        if isinstance(value, float):
            require(math.isfinite(value))
        return value


def canonical(value):
    """Encode deterministic JSON bytes for hashes and sealed private records."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    """Hash structured content independently of formatting or mapping key order."""
    return hashlib.sha256(canonical(value)).hexdigest()


def byte_digest(data):
    """Hash original source or attachment bytes before normalization."""
    return hashlib.sha256(data).hexdigest()


def decode(raw):
    """Reject excessive JSON, duplicate keys, depth and nonfinite constants before models."""
    require(len(raw) <= 10 * 1024 * 1024, "capacity_exceeded")

    def pairs(items):
        """Detect duplicate fields before ordinary dictionary construction hides them."""
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def bad_constant(value):
        """Never accept nonstandard JSON constants."""
        raise CloseoutError()

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            require(depth <= 8, "capacity_exceeded")
            if isinstance(item, dict):
                pending.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, list):
                pending.extend((v, depth + 1) for v in item)
            elif isinstance(item, float):
                require(math.isfinite(item))
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise CloseoutError(getattr(error, "reason", "schema_invalid")) from None


def validate[T: BaseModel](model: type[T], value) -> T:
    """Validate JSON primitives strictly, converting only the schema's UUID/time fields."""
    try:
        return model.model_validate_json(canonical(value))
    except (ValueError, TypeError):
        raise CloseoutError() from None


class Fingerprint(Contract):
    """Private named configuration reference bound to exact content bytes."""

    reference: Private = Field(repr=False)
    digest: Digest


class Selector(Contract):
    """One bounded literal JSON Pointer for independently extracted source fields."""

    field: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    pointer: Pointer


class SourceProfile(Contract):
    """Frozen provider identity, capabilities and reviewed extraction contract."""

    profile_id: Id
    product: Literal["vault", "verify", "vip", "logfire", "application", "customer"]
    version: Private = Field(repr=False)
    edition: Private = Field(repr=False)
    instance: Private = Field(repr=False)
    cluster: Private = Field(repr=False)
    namespace: Private = Field(repr=False)
    format: Format
    schema_digest: Digest
    capabilities: Annotated[
        dict[str, Literal["supported", "unavailable", "unknown"]], Field(max_length=16)
    ]
    clock_uncertainty: Annotated[float, Field(ge=0, le=5)] | None = None
    reporting_delay: Annotated[int, Field(ge=0, le=86400)] | None = None
    records_pointer: Pointer = ""
    fact_kind: (
        Literal[
            "identity_mapping",
            "operation_result",
            "cleanup_result",
            "approval_result",
            "lineage",
            "session_result",
            "discovery_result",
            "registration_result",
            "jwt_validation",
            "timing",
            "witness",
        ]
        | None
    ) = None
    selectors: Annotated[list[Selector], Field(max_length=16)] = []
    proof_labels: Annotated[list[str], Field(max_length=16)] = []
    member_environment_digest: Digest | None = None

    @model_validator(mode="after")
    def unique_selectors(self):
        """Disallow ambiguous multiple extraction rules for the same field."""
        from .catalog import RULES

        require(len({s.field for s in self.selectors}) == len(self.selectors))
        require(set(self.proof_labels) <= {label for labels in RULES.values() for label in labels})
        require(len(set(self.proof_labels)) == len(self.proof_labels))
        return self


class Inventory(Contract):
    """Exact environment and five accountable owners frozen before evidence collection."""

    schema_version: Literal[1]
    implementation_digest: Digest
    dependency_digest: Digest
    definitions: Annotated[list[Fingerprint], Field(min_length=1, max_length=100)]
    policies: Annotated[list[Fingerprint], Field(min_length=1, max_length=100)]
    datasets: Annotated[list[Fingerprint], Field(min_length=1, max_length=100)]
    owners: Annotated[list[Role], Field(min_length=5, max_length=5)]
    sources: Annotated[list[SourceProfile], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def unique_inventory(self):
        """Require every owner and unique definitions/profiles rather than approximate counts."""
        require(set(self.owners) == set(ROLES))
        for entries in (self.definitions, self.policies, self.datasets):
            require(len({v.reference for v in entries}) == len(entries))
        require(len({p.profile_id for p in self.sources}) == len(self.sources))
        return self


class RecordRef(Contract):
    """Opaque immutable object identity, seal and environment binding."""

    object_id: Id
    kind: Literal[
        "inventory",
        "source",
        "experiment",
        "measurement",
        "assessment",
        "review",
        "package",
        "handoff",
    ]
    seal_digest: Digest
    environment_digest: Digest


class Head(Contract):
    """Compare-and-swap dossier revision indexing sealed records only."""

    schema_version: Literal[1] = 1
    dossier_id: Id
    revision: Revision
    inventory_id: Id
    records: Annotated[list[RecordRef], Field(max_length=500)]


class Correlation(Contract):
    """Private operation scope that prevents cross-identity or cross-generation joins."""

    scope: Id
    environment_digest: Digest
    operation: Private = Field(repr=False)
    actor: Private | None = Field(default=None, repr=False)
    subject: Private | None = Field(default=None, repr=False)
    resource: Private | None = Field(default=None, repr=False)
    generation: Annotated[int, Field(ge=1)] | None = None


class FactValues(Contract):
    """Closed fields shared by the eleven discriminated source fact kinds.

    The fact validator requires each kind's fields. Remaining absent values cannot satisfy proof.
    """

    issuer: Private | None = Field(default=None, repr=False)
    subject_ref: Private | None = Field(default=None, repr=False)
    entity_ref: Private | None = Field(default=None, repr=False)
    alias_ref: Private | None = Field(default=None, repr=False)
    mount_ref: Private | None = Field(default=None, repr=False)
    definition_ref: Private | None = Field(default=None, repr=False)
    category: Literal["agent", "human"] | None = None
    mapping_event: Private | None = Field(default=None, repr=False)
    operation: Literal["read", "write", "issue", "deny", "login"] | None = None
    target_ref: Private | None = Field(default=None, repr=False)
    request_digest: Digest | None = None
    policy_digest: Digest | None = None
    scope_digest: Digest | None = None
    result: Literal["success", "denied", "unknown"] | None = None
    mechanism: (
        Literal[
            "jwt_invalid",
            "policy_denied",
            "token_revoked",
            "lease_revoked",
            "db_privilege",
            "session_revoked",
            "local_containment",
            "unknown",
        ]
        | None
    ) = None
    issued: Count | None = None
    ttl_seconds: Annotated[float, Field(ge=0, le=86400)] | None = None
    permission_groups: Count | None = None
    embedded_secrets: Count | None = None
    adapter_isolated: bool | None = None
    deployment_digest: Digest | None = None
    lease_ref: Private | None = Field(default=None, repr=False)
    action: Literal["revoke", "rotate", "suspend", "login", "notify"] | None = None
    completion_event: Private | None = Field(default=None, repr=False)
    after_result: Literal["success", "denied", "unknown"] | None = None
    outstanding: Count | None = None
    action_digest: Digest | None = None
    resource_digest: Digest | None = None
    parameters_digest: Digest | None = None
    requester_digest: Digest | None = None
    transaction_ref: Private | None = Field(default=None, repr=False)
    decision: Literal["approve", "deny", "timeout"] | None = None
    decision_event: Private | None = Field(default=None, repr=False)
    issuance_event: Private | None = Field(default=None, repr=False)
    effects: Count | None = None
    parent_ref: Private | None = Field(default=None, repr=False)
    child_ref: Private | None = Field(default=None, repr=False)
    parent_policy: Digest | None = None
    child_policy: Digest | None = None
    child_read_event: Private | None = Field(default=None, repr=False)
    parent_write_event: Private | None = Field(default=None, repr=False)
    session_ref: Private | None = Field(default=None, repr=False)
    user_ref: Private | None = Field(default=None, repr=False)
    existing_session: Literal["denied", "allowed", "unknown"] | None = None
    new_session: Literal["denied", "allowed", "unknown"] | None = None
    automatic_event: Private | None = Field(default=None, repr=False)
    notification_ref: Private | None = Field(default=None, repr=False)
    candidate_ref: Private | None = Field(default=None, repr=False)
    source_object_ref: Private | None = Field(default=None, repr=False)
    classification: (
        Literal["unknown_agent", "user_compromise", "secret_misuse", "agent_compromise"] | None
    ) = None
    activity_event: Private | None = Field(default=None, repr=False)
    absent_event: Private | None = Field(default=None, repr=False)
    finding_event: Private | None = Field(default=None, repr=False)
    registration_event: Private | None = Field(default=None, repr=False)
    owner_ref: Private | None = Field(default=None, repr=False)
    ceiling_ref: Private | None = Field(default=None, repr=False)
    readback_digest: Digest | None = None
    bootstrap_ref: Private | None = Field(default=None, repr=False)
    issuance_ref: Private | None = Field(default=None, repr=False)
    relying_ref: Private | None = Field(default=None, repr=False)
    token_digest: Digest | None = None
    expires_at: datetime | None = None
    audience_ref: Private | None = Field(default=None, repr=False)
    verifier_ref: Private | None = Field(default=None, repr=False)
    trigger_event: Private | None = Field(default=None, repr=False)
    end_event: Private | None = Field(default=None, repr=False)
    trigger_at: datetime | None = None
    end_at: datetime | None = None
    trigger_uncertainty: Annotated[float, Field(ge=0, le=5)] | None = None
    end_uncertainty: Annotated[float, Field(ge=0, le=5)] | None = None
    meeting_at: datetime | None = None
    participants: Annotated[list[Role], Field(max_length=5)] = []
    witnessed_digest: Digest | None = None
    attestation_ref: Private | None = Field(default=None, repr=False)


FACT_FIELDS = {
    "identity_mapping": (
        "issuer",
        "subject_ref",
        "entity_ref",
        "alias_ref",
        "mount_ref",
        "category",
        "mapping_event",
    ),
    "operation_result": (
        "operation",
        "target_ref",
        "request_digest",
        "policy_digest",
        "scope_digest",
        "result",
        "mechanism",
        "issued",
    ),
    "cleanup_result": ("lease_ref", "action", "completion_event", "after_result", "outstanding"),
    "approval_result": (
        "action_digest",
        "resource_digest",
        "parameters_digest",
        "requester_digest",
        "transaction_ref",
        "decision",
        "decision_event",
        "issued",
        "effects",
    ),
    "lineage": (
        "parent_ref",
        "child_ref",
        "parent_policy",
        "child_policy",
        "child_read_event",
        "parent_write_event",
    ),
    "session_result": (
        "session_ref",
        "user_ref",
        "action",
        "existing_session",
        "new_session",
        "automatic_event",
        "notification_ref",
    ),
    "discovery_result": (
        "candidate_ref",
        "source_object_ref",
        "classification",
        "activity_event",
        "absent_event",
        "finding_event",
        "notification_ref",
        "registration_event",
    ),
    "registration_result": (
        "entity_ref",
        "owner_ref",
        "ceiling_ref",
        "registration_event",
        "readback_digest",
        "policy_digest",
        "bootstrap_ref",
        "issuance_ref",
        "relying_ref",
    ),
    "jwt_validation": (
        "token_digest",
        "expires_at",
        "issuer",
        "audience_ref",
        "subject_ref",
        "verifier_ref",
        "result",
        "mechanism",
    ),
    "timing": (
        "trigger_event",
        "end_event",
        "trigger_at",
        "end_at",
        "trigger_uncertainty",
        "end_uncertainty",
    ),
    "witness": ("meeting_at", "participants", "witnessed_digest", "attestation_ref"),
}


class Fact(Contract):
    """One typed original-source observation, with a precise record pointer and correlation."""

    fact_id: Id
    obligation: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
    kind: Literal[
        "identity_mapping",
        "operation_result",
        "cleanup_result",
        "approval_result",
        "lineage",
        "session_result",
        "discovery_result",
        "registration_result",
        "jwt_validation",
        "timing",
        "witness",
    ]
    source_event_id: Private = Field(repr=False)
    occurred_at: datetime
    correlation: Correlation
    values: FactValues = Field(repr=False)
    record_pointer: Pointer

    @model_validator(mode="after")
    def required_values(self):
        """Require all mandatory values for the discriminator and forbid unrelated values."""
        if self.kind == "witness":
            require(
                self.values.participants
                and len(set(self.values.participants)) == len(self.values.participants)
            )
        allowed = set(FACT_FIELDS[self.kind])
        optional = {
            "identity_mapping": {"definition_ref"},
            "operation_result": {
                "lease_ref",
                "ttl_seconds",
                "permission_groups",
                "embedded_secrets",
                "adapter_isolated",
                "deployment_digest",
            },
            "approval_result": {"issuance_event"},
        }.get(self.kind, set())
        for key in allowed:
            require(getattr(self.values, key) is not None)
        for key in self.values.model_fields_set:
            if getattr(self.values, key) not in (None, []):
                require(key in allowed | optional)
        return self


class ImportManifest(Contract):
    """Private acquisition metadata; completeness and native eligibility need separate review."""

    schema_version: Literal[1] = 1
    profile_id: Id
    format: Format
    provenance: Provenance
    input_digest: Digest
    observed_at: datetime
    environment_digest: Digest
    scope: Id
    complete: bool = False
    media_type: Literal["text/plain", "image/png", "image/jpeg"] | None = None
    first_use_field: Literal["client_first_used_time", "client_first_usage_time"] | None = None
    period_start: datetime | None = None
    period_end: datetime | None = None
    mounts: Annotated[list[Private], Field(max_length=16)] = []

    @model_validator(mode="after")
    def variant(self):
        """Forbid format-inapplicable options and require exact activity/attachment metadata."""
        if self.format == "attachment-v1":
            require(self.media_type is not None)
        else:
            require(self.media_type is None)
        if self.format == "vault-activity-v1":
            require(
                self.first_use_field is not None
                and self.period_start is not None
                and self.period_end is not None
                and self.mounts
            )
            require(len(set(self.mounts)) == len(self.mounts))
            require(self.period_start < self.period_end)
        else:
            require(
                self.first_use_field is None
                and self.period_start is None
                and self.period_end is None
                and not self.mounts
            )
        return self


class Source(Contract):
    """Sealed original-byte snapshot plus independently extracted facts or normalized records."""

    source_id: Id
    profile_id: Id
    format: Format
    provenance: Provenance
    environment_digest: Digest
    scope: Id
    captured_at: datetime
    observed_at: datetime
    raw_digest: Digest
    schema_digest: Digest
    facts: Annotated[list[Fact], Field(max_length=10000)] = []
    normalized: Annotated[list[dict], Field(max_length=10000)] = Field(default=[], repr=False)
    manifest: ImportManifest | None = None
    origin_kind: Literal["validation", "response", "governance", "regression", "import"] = "import"
    origin_id: Id | None = None
    origin_inventory: dict[str, Digest] = Field(default={}, repr=False)
    source_assessment: dict = Field(default={}, repr=False)
    implementation_digest: Digest


class Obligation(Contract):
    """Compiled proof requirement with opaque evidence references and closed reasons."""

    label: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
    outcome: Outcome
    references: list[Id] = []
    reason: Reason | None = None


class CriterionRow(Contract):
    """Original acceptance meaning and its conservative proof outcome."""

    criterion: Literal[*CRITERIA]
    owners: list[Role]
    operation: Outcome
    proof: Outcome
    obligations: list[Obligation]
    reason: Reason | None = None
    unsafe: bool = False


class Assessment(Contract):
    """Frozen fifteen-row evaluation with exact code, environment and dependency bindings."""

    assessment_id: Id
    environment_digest: Digest
    inventory_id: Id
    implementation_digest: Digest
    catalog_digest: Digest
    evaluated_at: datetime
    members: dict[str, Digest]
    rows: Annotated[list[CriterionRow], Field(min_length=15, max_length=15)]
    tests: dict[str, Outcome]
    gates: dict[str, Outcome]
    measurements: dict[str, Digest] = {}
    timing: dict[str, float] = {}
    review_dependencies: dict[str, Digest] = {}

    @model_validator(mode="after")
    def exact_rows(self):
        """Reject duplicate or omitted criterion rows even when the total is fifteen."""
        require({row.criterion for row in self.rows} == set(CRITERIA))
        require(set(self.tests) == {f"F13-T{i}" for i in range(1, 7)})
        require(set(self.gates) == {f"P4-G{i}" for i in range(1, 6)})
        return self


def fresh_id():
    """Reserve a new immutable object identity; retries always use a new identity."""
    return uuid4()


class Review(Contract):
    """Private explicit attestations; variant fields never act as authority overrides."""

    review_id: Id
    kind: Literal["source-profile", "source", "attachment", "criterion", "exception", "package"]
    subject_id: Id
    expected_digest: Digest
    reviewer: Annotated[str, Field(min_length=1, max_length=128)] = Field(repr=False)
    role: Role
    observed_at: datetime
    reviewed_at: datetime
    decision: Literal["approve", "reject", "blocked", "agree_exception"]
    rationale: Annotated[str, Field(min_length=1, max_length=2000)] = Field(repr=False)
    attestations: Annotated[list[Id], Field(min_length=1, max_length=32)]
    supersedes: Annotated[list[Id], Field(max_length=100)] = []
    criterion: Literal[*CRITERIA] | None = None
    extraction_digest: Digest | None = None
    sanitized: bool | None = None
    witnessed: bool | None = None
    alternative: Annotated[str, Field(min_length=1, max_length=2000)] | None = Field(
        default=None, repr=False
    )

    @model_validator(mode="after")
    def variant_contract(self):
        """Reject irrelevant fields, duplicates and fictitious future review times."""
        require(self.reviewer.strip() and self.rationale.strip())
        require(self.observed_at <= self.reviewed_at <= now())
        require(len(set(self.attestations)) == len(self.attestations))
        require(len(set(self.supersedes)) == len(self.supersedes))
        allowed = {
            "source-profile": set(),
            "source": {"extraction_digest"},
            "attachment": {"sanitized"},
            "criterion": {"criterion"},
            "exception": {"criterion", "alternative"},
            "package": {"witnessed"},
        }[self.kind]
        for name in {"criterion", "extraction_digest", "sanitized", "witnessed", "alternative"}:
            require((getattr(self, name) is not None) == (name in allowed))
        require((self.decision == "agree_exception") == (self.kind == "exception"))
        if self.kind == "attachment" and self.decision == "approve":
            require(self.sanitized is True)
        return self


class Activity(Contract):
    """One native activity identity; mount is scope, never part of deduplication key."""

    client_id: Private = Field(repr=False)
    client_type: Literal["entity", "non-entity-token", "acme", "secret-sync"]
    namespace_id: Private = Field(repr=False)
    mount_accessor: Private = Field(repr=False)
    first_used_at: datetime
    metadata: dict = Field(default={}, repr=False)


class Mapping(Contract):
    """Independently observed identity mapping, not an arithmetic token estimate."""

    issuer: Private = Field(repr=False)
    subject: Private = Field(repr=False)
    entity_id: Private = Field(repr=False)
    namespace_id: Private = Field(repr=False)
    mount_accessor: Private = Field(repr=False)
    category: Literal["agent", "human"]
    definition_ref: Private | None = Field(default=None, repr=False)
    observed_at: datetime
    verification_ref: Private = Field(repr=False)


class Execution(Contract):
    """Successful external operation with independent issuance, trace and verified identity."""

    execution_ref: Private = Field(repr=False)
    operation_ref: Private = Field(repr=False)
    issuance_ref: Private = Field(repr=False)
    trace_ref: Private = Field(repr=False)
    verification_ref: Private = Field(repr=False)
    occurred_at: datetime
    result: Literal["success"]
    mode: Scenario
    issuer: Private | None = Field(default=None, repr=False)
    subject: Private | None = Field(default=None, repr=False)
    agent_entity: Private | None = Field(default=None, repr=False)
    human_entity: Private | None = Field(default=None, repr=False)
    namespace_id: Private = Field(repr=False)
    mount_accessor: Private = Field(repr=False)


class ExperimentInput(Contract):
    """Controlled scenario and pre-operation baseline within one calendar period."""

    scenario: Scenario
    profile_id: Id
    baseline_id: Id
    mapping_id: Id
    cohort_id: Id
    mounts: Annotated[list[Private], Field(min_length=1, max_length=16)] = Field(repr=False)
    period_start: datetime
    period_end: datetime
    other_consumers: Annotated[list[Private], Field(max_length=100)] = Field(default=[], repr=False)

    @model_validator(mode="after")
    def period(self):
        """Require one complete calendar month and an exact unique mount scope."""
        start, end = self.period_start, self.period_end
        require(
            start.day == end.day == 1
            and start.hour == end.hour == 0
            and start.minute == end.minute == 0
            and start.second == end.second == 0
            and start.microsecond == end.microsecond == 0
        )
        require((end.year * 12 + end.month) - (start.year * 12 + start.month) == 1)
        require(len(set(self.mounts)) == len(self.mounts))
        return self


class Experiment(ExperimentInput):
    """Prepared experiment bound to original baseline and environment digests."""

    experiment_id: Id
    prepared_at: datetime
    environment_digest: Digest
    baseline_digest: Digest
    mapping_digest: Digest
    cohort_digest: Digest


class Delta(Contract):
    """Bounded explanation for one otherwise unexplained activity client."""

    client_id: Private = Field(repr=False)
    classification: Literal["unrelated", "non-entity"]
    references: Annotated[list[Id], Field(min_length=1, max_length=32)]


class MeasurementInput(Contract):
    """Final export, execution roster, entity mapping and evidence-backed delta explanations."""

    final_id: Id
    roster_id: Id
    mapping_id: Id
    explanations: Annotated[list[Delta], Field(max_length=100)] = []


class Measurement(MeasurementInput):
    """Frozen count result with exact source seals and source-review eligibility at measurement."""

    measurement_id: Id
    experiment_id: Id
    scenario: Scenario
    environment_digest: Digest
    measured_at: datetime
    implementation_digest: Digest
    review_dependencies: dict[str, Digest]
    dependencies: dict[str, Digest]
    outcome: Outcome
    provenance: Provenance
    reason: Reason | None
    counts: dict[str, Count]


class CorePackage(Contract):
    """Immutable proof/readout package; external role records do not enter its own seal."""

    package_id: Id
    assessment_id: Id
    assessment_digest: Digest
    environment_digest: Digest
    created_at: datetime
    review_dependencies: dict[str, Digest]
    attachment_dependencies: dict[str, Digest]


class Handoff(Contract):
    """A separately sealed final copy binds a core and exact external role records."""

    handoff_id: Id
    package_id: Id
    package_digest: Digest
    environment_digest: Digest
    created_at: datetime
    review_dependencies: dict[str, Digest]
    recorded_status: Literal[
        "failed", "blocked", "ready_for_review", "accepted_with_exceptions", "accepted"
    ]
