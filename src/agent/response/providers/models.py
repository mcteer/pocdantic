"""Strict private provider authority, action and observation records.

These records contain exact private target metadata, never bearer credentials or DB
passwords. Immutable plans pin authority to a reviewed enrollment and resource generation.
"""

from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import Field, SecretStr, StrictBool, StrictInt, field_serializer, model_validator

from agent.recovery.models import BoundOwnership, Digest, Private, Revision, now
from agent.response.models import Definition, ResponseError

Alias = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")]
Native = Annotated[str, Field(min_length=1, max_length=256)]
Pointer = Annotated[str, Field(max_length=256, pattern=r"^(?:/[^/~]*(?:~[01][^/~]*)*)*$")]
Kind = Literal[
    "block_registration",
    "revoke_native_token",
    "suspend_user",
    "revoke_user_sessions",
    "rotate_static",
    "terminate_static_sessions",
    "notify_teams",
]
Proof = Literal["not_run", "proven", "disproven", "inconclusive", "unsupported", "not_applicable"]
Scenario = Literal[
    "same_jwt",
    "fresh_issuance",
    "native_token",
    "user_sessions",
    "dynamic_database",
    "static_database",
    "notification_delivery",
]
REASONS = {
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
}


def https_origin(value):
    """Validate a pinned HTTPS authority; API paths and query strings are not origins."""
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise ValueError("destination_invalid")
    return value.rstrip("/")


class ResourceBinding(Private):
    """One exact enrolled resource; aliases never confer additional provider authority."""

    binding_id: UUID = Field(default_factory=uuid4)
    alias: Alias
    kind: Literal["registration", "native_token", "user", "static_role", "teams"]
    workload_definition: Definition
    origin: Annotated[str, Field(min_length=1, max_length=2048)]
    namespace: Annotated[str, Field(max_length=256)] = ""
    native_id: Native
    generation: Revision = 1
    enabled: StrictBool = False
    capability: Literal["supported", "missing_authority", "unsupported", "unverified"] = (
        "unverified"
    )
    capability_digest: Digest | None = None
    checked_at: datetime | None = None
    actor_issuer: Native | None = None
    actor_subject: Native | None = None
    entity_id: Native | None = None
    oauth_profile: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$", max_length=256)] | None = None
    user_issuer: Native | None = None
    user_subject: Native | None = None
    session_id_field: (
        Annotated[str, Field(pattern=r"^(?:@|[A-Za-z][A-Za-z0-9_]{0,31})$")] | None
    ) = None
    session_schema_digest: Digest | None = None
    root_run_id: UUID | None = None
    ownership: BoundOwnership | None = None
    token_type: Literal["service", "batch", "external"] | None = None
    exclusive_tree: StrictBool = False
    mount: (
        Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$", max_length=256)]
        | None
    ) = None
    database: Native | None = None
    username: Native | None = None
    isolated: StrictBool = False
    destination_digest: Digest | None = None
    secret_digest: Digest | None = None
    secret_alias: Alias | None = None
    proof_secret_digest: Digest | None = None
    healthy_secret_digest: Digest | None = None
    proof_secret_alias: Alias | None = None
    healthy_secret_alias: Alias | None = None
    entitlement_digest: Digest | None = None
    owner_confirmed: StrictBool = False
    revocation_review_digest: Digest | None = None

    @model_validator(mode="after")
    def authority(self):
        """Reject ambiguous native-token/user/static targets and malformed destinations."""
        https_origin(self.origin)
        if (
            self.native_id in {".", ".."}
            or any(c in self.native_id for c in ("/", "\\"))
            or any(ord(c) < 32 for c in self.native_id)
        ):
            raise ValueError("mapping_missing")
        if (
            self.kind == "native_token"
            and self.enabled
            and (
                self.token_type != "service"
                or not self.exclusive_tree
                or not self.ownership
                or self.root_run_id != self.ownership.root_run_id
            )
        ):
            raise ValueError("mapping_missing")
        if self.kind == "user" and self.enabled and not (self.user_issuer and self.user_subject):
            raise ValueError("mapping_missing")
        if (
            self.kind == "registration"
            and self.enabled
            and not (self.actor_issuer and self.actor_subject and self.entity_id)
        ):
            raise ValueError("mapping_missing")
        if (
            self.kind == "static_role"
            and self.enabled
            and not (self.isolated and self.mount and self.database and self.username)
        ):
            raise ValueError("mapping_missing")
        return self

    def key(self):
        """Return the private canonical identity used to fence duplicate resource aliases."""
        return (
            self.origin.rstrip("/"),
            self.namespace,
            self.kind,
            self.mount,
            self.destination_digest
            if self.kind == "teams" and self.destination_digest
            else self.native_id,
        )


class SourceProfile(Private):
    """Bounded native JSON projection, separately authenticated from normalized 006 intake."""

    alias: Alias
    issuer: Annotated[str, Field(min_length=1, max_length=2048)]
    subject: Native
    audience: Native
    schema_ref: Native
    fixture_digest: Digest
    collector_digest: Digest | None = None
    reviewed_by: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    reviewed_at: datetime | None = None
    clock_bound_seconds: Annotated[StrictInt, Field(ge=0, le=5)] | None = None
    provenance: Literal["synthetic", "native"] = "synthetic"
    pointers: dict[Literal["event_id", "occurred_at", "rule", "object", "request_id"], Pointer]
    predicates: dict[Pointer, str | int | bool] = Field(default_factory=dict, max_length=8)
    objects: dict[Native, Definition] = Field(default_factory=dict, max_length=64)
    object_bindings: dict[Native, UUID] = Field(default_factory=dict, max_length=64)
    allowed_scopes: frozenset[Literal["root_run", "definition"]] = frozenset({"definition"})
    ignored_fields: tuple[Native, ...] = Field(default=(), max_length=16)

    @field_serializer("allowed_scopes", when_used="json")
    def stable_scopes(self, value):
        """Keep unordered source scopes deterministic in enrollment bytes and digests."""
        return sorted(value)

    @model_validator(mode="after")
    def projection(self):
        """Require complete selectors and reviewed native provenance before activation."""
        if (
            not {"event_id", "occurred_at", "rule", "object"} <= self.pointers.keys()
            or len(self.pointers) > 8
            or not self.allowed_scopes
            or self.alias == "local-operator"
            or self.provenance == "native"
            and not (self.collector_digest and self.reviewed_by and self.reviewed_at)
        ):
            raise ValueError("source_evidence_missing")
        if not set(self.object_bindings) <= set(self.objects):
            raise ValueError("mapping_missing")
        if "root_run" in self.allowed_scopes and (
            "request_id" not in self.pointers or set(self.object_bindings) != set(self.objects)
        ):
            raise ValueError("mapping_missing")
        return self


class Rule(Private):
    """Fixed policy choice; events cannot insert kinds, paths, handles or credentials."""

    alias: Alias
    source: Alias | Literal["local-operator"] = "local-operator"
    native_rule: Native | None = None
    reason: Literal["suspected_compromise", "policy_violation"] = "suspected_compromise"
    scope: Literal["root_run", "definition"] = "definition"
    actions: tuple[Kind, ...] = Field(default=(), max_length=7)
    bindings: tuple[UUID, ...] = Field(default=(), max_length=16)
    required: frozenset[Kind] = frozenset()

    @field_serializer("required", when_used="json")
    def stable_required(self, value):
        """Sort unordered controls so equivalent policy roundtrips retain their fingerprint."""
        return sorted(value)

    @model_validator(mode="after")
    def scope_check(self):
        """Prevent root events from using security controls shared with healthy peers."""
        if (
            len(set(self.actions)) != len(self.actions)
            or len(set(self.bindings)) != len(self.bindings)
            or not self.required <= set(self.actions)
            or "notify_teams" in self.required
            or self.scope == "root_run"
            and set(self.actions) - {"revoke_native_token", "notify_teams"}
        ):
            raise ValueError("mapping_missing")
        return self


class Enrollment(Private):
    """Snapshot authority activated by the local operator, never by editing a draft."""

    installation_id: UUID
    environment_digest: Digest
    source_policy_digest: Digest
    workload_definition: Definition
    issuer: Annotated[str, Field(min_length=1, max_length=2048)]
    revision: Revision = 1
    bindings: tuple[ResourceBinding, ...] = Field(default=(), max_length=64)
    sources: tuple[SourceProfile, ...] = Field(default=(), max_length=16)
    rules: tuple[Rule, ...] = Field(default=(), max_length=32)
    dynamic_revocation_review_digest: Digest | None = None
    dynamic_healthy_secret_alias: Alias | None = None
    dynamic_healthy_secret_digest: Digest | None = None
    native_login_mount: (
        Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$", max_length=256)]
        | None
    ) = None
    native_login_role: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$", max_length=256)] | None = (
        None
    )
    native_exclusive_tree: StrictBool = False
    max_token_lifetime_seconds: Annotated[StrictInt, Field(gt=0, le=86400 * 30)] | None = None

    @model_validator(mode="after")
    def unambiguous(self):
        """Reject duplicate authority, dangling rules and resources from another definition."""
        if bool(self.native_login_mount) != bool(self.native_login_role) or (
            self.native_login_mount and not self.native_exclusive_tree
        ):
            raise ValueError("mapping_missing")
        ids = {b.binding_id for b in self.bindings}
        if (
            len(ids) != len(self.bindings)
            or len({b.key() for b in self.bindings}) != len(self.bindings)
            or len({b.alias for b in self.bindings}) != len(self.bindings)
            or len({s.alias for s in self.sources}) != len(self.sources)
            or len({s.audience for s in self.sources}) != len(self.sources)
            or len({r.alias for r in self.rules}) != len(self.rules)
            or any(b.workload_definition != self.workload_definition for b in self.bindings)
            or any(
                s.issuer != self.issuer or set(s.objects.values()) - {self.workload_definition}
                for s in self.sources
            )
        ):
            raise ValueError("mapping_missing")
        for source in self.sources:
            if not set(source.object_bindings.values()) <= ids:
                raise ValueError("mapping_missing")
        native_rules = [
            (r.source, r.native_rule) for r in self.rules if r.source != "local-operator"
        ]
        if len(set(native_rules)) != len(native_rules) or any(
            rule is None for _, rule in native_rules
        ):
            raise ValueError("mapping_missing")
        for rule in self.rules:
            if (
                not set(rule.bindings) <= ids
                or sum(b.kind == "user" for b in self.bindings if b.binding_id in rule.bindings) > 1
            ):
                raise ValueError("mapping_missing")
            if rule.source != "local-operator" and not any(
                s.alias == rule.source and rule.scope in s.allowed_scopes for s in self.sources
            ):
                raise ValueError("mapping_missing")
        return self


class Observation(Private):
    """One independently classified result, explicitly correlated and privately reviewed."""

    observation_id: UUID = Field(default_factory=uuid4)
    installation_id: UUID
    environment_digest: Digest
    implementation_digest: Digest
    enrollment_digest: Digest
    incident_id: UUID
    action_id: UUID
    binding_id: UUID
    resource_generation: Revision
    path: Literal[
        "native_intake",
        "registration",
        "native_token",
        "native_token_readback",
        "tenant_session_readback",
        "static_session_readback",
        "tenant_user",
        "tenant_sessions",
        "upstream_sessions",
        "same_jwt",
        "fresh_issuance",
        "dynamic_fresh",
        "dynamic_session",
        "static_old",
        "static_new",
        "static_session",
        "notification",
        "old_credential_safety",
    ]
    result: Proof
    source: Literal["synthetic", "live_probe", "provider_readback", "native_evidence"]
    source_digest: Digest
    event_digest: Digest | None = None
    observed_at: datetime = Field(default_factory=now)
    reviewer: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    reviewed_at: datetime | None = None
    clock_bound_seconds: Annotated[StrictInt, Field(ge=0, le=5)] | None = None
    credential_digest: Digest | None = None
    credential_expires_at: datetime | None = None
    before_succeeded: StrictBool = False
    healthy_control: StrictBool = False
    minting_stopped_at: datetime | None = None
    notice_id: UUID | None = None
    notice_revision: Revision | None = None
    maximum_lifetime_seconds: Annotated[StrictInt, Field(gt=0, le=86400 * 30)] | None = None

    @model_validator(mode="after")
    def evidence(self):
        """Native evidence needs review; negative probes need baseline and health controls."""
        if self.source == "native_evidence" and not (self.reviewer and self.reviewed_at):
            raise ValueError("provider_evidence_invalid")
        if (
            self.result == "proven"
            and self.path
            in {
                "same_jwt",
                "native_token",
                "tenant_sessions",
                "fresh_issuance",
                "dynamic_fresh",
                "dynamic_session",
                "static_old",
                "static_new",
                "static_session",
            }
            and not (self.before_succeeded and self.healthy_control)
        ):
            raise ValueError("provider_evidence_invalid")
        if (
            self.path == "same_jwt"
            and self.result == "proven"
            and not (
                self.credential_digest
                and self.credential_expires_at
                and self.credential_expires_at > self.observed_at
            )
        ):
            raise ValueError("provider_evidence_invalid")
        return self


class ProviderAction(Private):
    """Immutable exact plan plus durable lifecycle; acknowledgment is not proof."""

    action_id: UUID = Field(default_factory=uuid4)
    kind: Kind
    scope: Literal["root_run", "definition"] = "definition"
    binding: ResourceBinding
    enrollment_digest: Digest
    required: StrictBool = True
    incidents: tuple[UUID, ...] = Field(min_length=1, max_length=1000)
    dependencies: tuple[UUID, ...] = Field(default=(), max_length=16)
    predecessor: UUID | None = None
    notice_id: UUID | None = None
    notice_revision: Revision = 1
    state: Literal[
        "planned", "submitted", "acknowledged", "denied", "failed", "uncertain", "reconciled"
    ] = "planned"
    reason: Literal[tuple(sorted(REASONS))] = "proof_required"
    created_at: datetime = Field(default_factory=now)
    submitted_at: datetime | None = None
    completed_at: datetime | None = None
    attempt_ms: Annotated[StrictInt, Field(ge=0)] | None = None
    observations: tuple[Observation, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def identity(self):
        """Forbid dangling observation identity or duplicated dependency/incident references."""
        expected_binding = {
            "block_registration": "registration",
            "revoke_native_token": "native_token",
            "suspend_user": "user",
            "revoke_user_sessions": "user",
            "rotate_static": "static_role",
            "terminate_static_sessions": "static_role",
            "notify_teams": "teams",
        }
        if self.scope == "root_run" and self.kind not in {"revoke_native_token", "notify_teams"}:
            raise ValueError("mapping_missing")
        if self.binding.kind != expected_binding[self.kind]:
            raise ValueError("mapping_missing")
        if (
            len(set(self.incidents)) != len(self.incidents)
            or len(set(self.dependencies)) != len(self.dependencies)
            or len({o.observation_id for o in self.observations}) != len(self.observations)
            or any(
                o.incident_id not in self.incidents
                or o.action_id != self.action_id
                or o.binding_id != self.binding.binding_id
                or o.resource_generation != self.binding.generation
                or o.enrollment_digest != self.enrollment_digest
                for o in self.observations
            )
        ):
            raise ValueError("provider_evidence_invalid")
        return self


class SubjectHold(Private):
    """A tenant user's local execution restriction, independent of browser lifetime."""

    issuer: Native
    subject: Native
    workload_definition: Definition
    incident_id: UUID
    generation: Revision


class NativeTokenAcquisition(Private):
    """Prospective native login intent, retained when an unknown token might exist."""

    acquisition_id: UUID = Field(default_factory=uuid4)
    ownership: BoundOwnership
    actor_issuer: Native
    actor_subject: Native
    mount: Native
    role: Native
    enrollment_digest: Digest
    state: Literal["intent", "submitted", "bound", "denied", "uncertain"] = "intent"
    created_at: datetime = Field(default_factory=now)
    submitted_at: datetime | None = None
    binding: ResourceBinding | None = None

    @model_validator(mode="after")
    def acquisition_identity(self):
        """Require exact service-token ownership before a bound result can be exposed."""
        if self.state == "bound":
            binding = self.binding
            if not (
                binding
                and binding.kind == "native_token"
                and binding.enabled
                and binding.token_type == "service"
                and binding.exclusive_tree
                and binding.ownership == self.ownership
                and binding.root_run_id == self.ownership.root_run_id
                and binding.workload_definition == self.ownership.workload_definition
                and (binding.actor_issuer, binding.actor_subject)
                == (self.actor_issuer, self.actor_subject)
            ):
                raise ValueError("provider_evidence_invalid")
        elif self.binding is not None:
            raise ValueError("provider_evidence_invalid")
        if self.submitted_at is not None and self.submitted_at < self.created_at:
            raise ValueError("provider_evidence_invalid")
        return self


class ProbeAcquisition(Private):
    """Dedicated negative acquisition lifecycle; it cannot waive production recovery."""

    acquisition_id: UUID = Field(default_factory=uuid4)
    ownership: BoundOwnership
    credential_path: Annotated[
        str, Field(pattern=r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$", max_length=256)
    ]
    enrollment_digest: Digest
    scenario: Scenario
    state: Literal[
        "intent",
        "submitted",
        "denied_no_issuance",
        "issued",
        "cleanup_pending",
        "cleaned",
        "uncertain",
    ] = "intent"
    created_at: datetime = Field(default_factory=now)
    submitted_at: datetime | None = None
    lease_handle: Annotated[str, Field(max_length=1024)] | None = None
    recovery_incident_id: UUID | None = None
    observations: tuple[Observation, ...] = Field(default=(), max_length=16)
    credential_class: Literal["vault_lease", "oauth_jwt"] = "vault_lease"
    credential_digest: Digest | None = None
    credential_expires_at: datetime | None = None

    @model_validator(mode="after")
    def probe_identity(self):
        """Reject invented cleanup and inconsistent credential class/state combinations."""
        if self.submitted_at is not None and self.submitted_at < self.created_at:
            raise ValueError("provider_evidence_invalid")
        if self.credential_class == "oauth_jwt":
            if self.lease_handle or self.recovery_incident_id or self.state == "cleanup_pending":
                raise ValueError("provider_evidence_invalid")
            if self.state in {"issued", "cleaned"} and not (
                self.credential_digest and self.credential_expires_at
            ):
                raise ValueError("provider_evidence_invalid")
        else:
            from agent.recovery.models import valid_handle

            if self.credential_digest or self.credential_expires_at:
                raise ValueError("provider_evidence_invalid")
            if self.state in {"issued", "cleanup_pending", "cleaned"} and not valid_handle(
                self.credential_path, self.lease_handle
            ):
                raise ValueError("provider_evidence_invalid")
            if self.state in {"cleanup_pending", "cleaned"} and not self.recovery_incident_id:
                raise ValueError("provider_evidence_invalid")
        if self.state == "denied_no_issuance" and (
            self.lease_handle or self.recovery_incident_id or self.credential_digest
        ):
            raise ValueError("provider_evidence_invalid")
        return self


class ProofInput(Private):
    """Ephemeral private stdin authority for compiled validation; never journal this model."""

    delegated_token: SecretStr | None = None
    healthy_delegated_token: SecretStr | None = None
    subject_token: SecretStr | None = None
    actor_token: SecretStr | None = None
    native_token: SecretStr | None = None
    healthy_native_token: SecretStr | None = None
    healthy_root: UUID | None = None
    healthy_binding: UUID | None = None

    @model_validator(mode="after")
    def bounded_tokens(self):
        """Reject oversized/empty tokens before private subprocess or provider work."""
        for value in (
            self.delegated_token,
            self.healthy_delegated_token,
            self.subject_token,
            self.actor_token,
            self.native_token,
            self.healthy_native_token,
        ):
            if value is not None and not 0 < len(value.get_secret_value()) <= 65536:
                raise ValueError("provider_evidence_invalid")
        return self


class IncidentPlan(Private):
    """Plan reference reserved atomically alongside the original local containment."""

    incident_id: UUID
    mode: Literal["local_only", "synthetic", "native"] = "local_only"
    enrollment_digest: Digest
    action_ids: tuple[UUID, ...] = Field(default=(), max_length=16)
    native_token_authorized: StrictBool = False
    native_token_required: StrictBool = False
    missing_controls: tuple[Kind, ...] = Field(default=(), max_length=7)
    source_clock_bound_seconds: Annotated[StrictInt, Field(ge=0, le=5)] | None = None


def require(condition, reason="mapping_missing"):
    """Raise a closed operational error instead of leaking boundary validation details."""
    if not condition:
        raise ResponseError(reason)


class RecoveryDecision(Private):
    """Local revision-bound operator decision, retained without resetting prior effects."""

    decision_id: UUID = Field(default_factory=uuid4)
    operator: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]
    expected_revision: Revision
    enrollment_digest: Digest
    incident_ids: tuple[UUID, ...] = Field(max_length=1000)
    predecessor: UUID
    successor: UUID
    decision: Literal["retry", "resend"]
    reviewed_at: datetime = Field(default_factory=now)


class AuthorityReview(Private):
    """Sanitized local Verify permission/mapping review, avoiding secret-bearing client APIs."""

    tenant_origin: Native
    api_client_id: Native
    user_id: Native
    issuer: Native
    subject: Native
    entitlements: frozenset[Native] = Field(max_length=64)
    federation_scope: Literal["tenant_only"] = "tenant_only"
    source_digest: Digest
    reviewer: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]
    reviewed_at: datetime

    @field_serializer("entitlements", when_used="json")
    def stable_entitlements(self, value):
        """Serialize reviewed permission sets consistently without changing authority."""
        return sorted(value)


class ReadinessRecord(Private):
    """Private metadata-only review pinned to one unchanged draft and installation."""

    installation_id: UUID
    environment_digest: Digest
    draft_digest: Digest
    checked_at: datetime = Field(default_factory=now)
    bindings: tuple[ResourceBinding, ...] = Field(max_length=64)
    dynamic_reason: Literal[tuple(sorted(REASONS))] | None = None
