"""Strict deployment targets and sanitized capability reports.

These models describe configuration and observations; they grant no runtime authority.
"""

import re
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Mode = Literal["delegated-exchange", "user-jwt"]
Feature = Literal[
    "baseline-sign-in",
    "baseline-database",
    "delegated-exchange",
    "phone-approval",
    "remediation",
    "governance",
    "audit-export",
]


def hosts(value):
    """Validate a bounded unique DNS allowlist, never a URL, wildcard or implicit trust."""
    if len(value) > 16 or len(set(value)) != len(value):
        raise ValueError("invalid_trusted_hosts")
    result = []
    for host in value:
        if (
            not isinstance(host, str)
            or len(host) > 253
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host)
        ):
            raise ValueError("invalid_trusted_hosts")
        if any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in host.split(".")
        ):
            raise ValueError("invalid_trusted_hosts")
        result.append(host.lower())
    if len(set(result)) != len(result):
        raise ValueError("invalid_trusted_hosts")
    return tuple(result)


class DatabaseTarget(BaseModel):
    """One privately configured credential path used by acquisition, cleanup and evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    mount: str = Field(min_length=1, max_length=128, repr=False)
    role: str = Field(min_length=1, max_length=128, repr=False)

    @field_validator("mount", "role")
    @classmethod
    def path(cls, value):
        """Reject traversal, URI syntax and ambiguous path components."""
        if not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", value):
            raise ValueError("invalid_database_target")
        return value

    @property
    def credential_path(self):
        """Construct only the fixed database credentials operation."""
        return f"{self.mount}/creds/{self.role}"

    @classmethod
    def from_path(cls, value):
        """Parse an existing legacy target without changing its mount or role."""
        if value.count("/creds/") != 1:
            raise ValueError("invalid_database_target")
        mount, role = value.split("/creds/")
        return cls(mount=mount, role=role)


class DeploymentProfile(BaseModel):
    """Nonsecret selection and bounded endpoint trust for one deployment."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    authentication_mode: Mode = "delegated-exchange"
    target: DatabaseTarget
    trusted_hosts: tuple[str, ...] = ()
    requested_features: tuple[Feature, ...] = Field(
        default=("baseline-sign-in", "baseline-database"), max_length=7
    )

    @field_validator("requested_features")
    @classmethod
    def unique_features(cls, value):
        """Reject duplicates rather than making ambiguous repeated capability requests."""
        if len(set(value)) != len(value):
            raise ValueError("invalid_requested_features")
        return value

    @field_validator("trusted_hosts")
    @classmethod
    def trust(cls, value):
        """Use the same allowlist grammar as Settings."""
        return hosts(value)


class CapabilityObservation(BaseModel):
    """A closed public observation; raw identifiers and provider messages have no field."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    feature: Feature
    state: Literal["configured", "unverified", "supported", "unsupported", "blocked"]
    evidence_level: Literal["local", "advertised", "demonstrated"] = "local"
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    reason_code: Literal[
        "configuration_missing",
        "configuration_invalid",
        "external_unverified",
        "feature_unavailable",
        "dependency_unreachable",
        "provider_access_denied",
        "identity_expired",
        "recovery_blocked",
        "observed",
    ]
    repair_key: Literal[
        "configure", "check_network", "sign_in", "provider_review", "recover", "none"
    ]
    owner: Literal["operator", "provider-administrator", "integration-owner"] = "operator"

    @field_validator("observed_at")
    @classmethod
    def utc_time(cls, value):
        """Require an aware observation time so evidence age is unambiguous."""
        if value.tzinfo is None:
            raise ValueError("invalid_observation_time")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def proof(self):
        """Prevent advertisements or local settings from claiming demonstrated support."""
        if self.state == "supported" and self.evidence_level != "demonstrated":
            raise ValueError("demonstration_required")
        return self


class SetupReport(BaseModel):
    """Bounded sanitized readiness and fixed repair instructions."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    observations: tuple[CapabilityObservation, ...] = Field(max_length=32)
    missing_settings: tuple[str, ...] = ()
    instructions: tuple[str, ...] = ()
    exit_code: Literal[0, 2, 3] = 0


RecipeId = Literal["offline", "workspace-read", "workspace-analysis"]
Owner = Literal[
    "operator",
    "identity-administrator",
    "vault-administrator",
    "database-administrator",
    "integration-owner",
    "human-reviewer",
    "gateway-administrator",
]
ActionId = Literal[
    "use-root",
    "install-extras",
    "edit-settings",
    "check-local",
    "check-network",
    "init-recovery",
    "inspect-recovery",
    "prepare-policy",
    "review-policy",
    "enroll-response",
    "inspect-response",
    "launch-workspace",
    "sign-in",
    "validate-allow-deny",
    "check-cleanup",
    "run-offline",
    "integration-review",
    "gateway-review",
]
CommandId = Literal[
    "offline",
    "check-local",
    "check-network",
    "init-recovery",
    "inspect-recovery",
    "prepare-policy",
    "enroll-response",
    "inspect-response",
    "launch-workspace",
    "check-cleanup",
    "install-extras",
]
ProofScope = Literal["synthetic", "live-baseline"]
Effect = Literal[
    "none",
    "local-install",
    "local-configuration",
    "local-enrollment",
    "public-network",
    "live-read-and-cleanup",
    "human-action",
]
SETTING_NAMES = frozenset(
    {
        "OAUTH_DISCOVERY_URL",
        "OAUTH_ISSUER",
        "OAUTH_AUDIENCE",
        "OAUTH_CLIENT_ID",
        "OAUTH_CLIENT_SECRET",
        "LOGIN_CLIENT_ID",
        "LOGIN_CLIENT_SECRET",
        "LOGIN_SCOPES",
        "VAULT_ADDR",
        "VAULT_JWT_AUTH_ROLE",
        "VAULT_AUDIENCE",
        "ACTOR_AUDIENCE",
        "DATABASE_HOST",
        "DATABASE_NAME",
        "DATABASE_SSLROOTCERT",
        "OAUTH_CA_FILE",
        "VAULT_CA_FILE",
        "PROFILES_FILE",
        "TIMEOUT_SECONDS",
        "MODEL",
        "MODEL_MODE",
        "GATEWAY_REGION",
        "GATEWAY_ROUTE",
        "GATEWAY_MODELS",
        "GATEWAY_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "SERVER_EXTRA",
        "POSTGRES_EXTRA",
        "GOOGLE_EXTRA",
        "OPENAI_EXTRA",
        "ANTHROPIC_EXTRA",
        "SANDBOX_EXTRA",
        "BEARER_TOKEN",
        "PORTABILITY_DENIED_TOKEN",
    }
)


class DemoRecipe(BaseModel):
    """Immutable reviewed recipe; no command text or provider authority is stored."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    id: RecipeId
    profile: Literal["database-reader", "database-analyst"] | None = None
    extras: tuple[
        Literal["server", "postgres", "sandbox", "google", "openai", "anthropic"], ...
    ] = Field(default=(), max_length=6)
    required_capabilities: tuple[Literal["database-read", "sandbox-python"], ...] = Field(
        default=(), max_length=4
    )
    steps: tuple[ActionId, ...] = Field(default=(), max_length=16)
    proof_scope: ProofScope = "synthetic"

    @field_validator("extras", "required_capabilities", "steps")
    @classmethod
    def unique(cls, value):
        """Reject duplicate requirements rather than silently changing recipe ordering."""
        if len(set(value)) != len(value):
            raise ValueError("duplicate_recipe_member")
        return value


class PrerequisiteFinding(BaseModel):
    """Closed names-only local finding; external error bodies cannot enter the report."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    id: Literal[
        "configuration-missing",
        "identity-missing",
        "vault-missing",
        "database-missing",
        "model-missing",
        "configuration-invalid",
        "dependency-missing",
        "model-unsupported",
        "root-invalid",
        "budget-exhausted",
        "recovery-state",
        "response-state",
        "policy-review",
        "local-ready",
        "gateway-review",
    ]
    boundary: Literal[
        "project",
        "configuration",
        "dependency",
        "identity",
        "model",
        "database",
        "sandbox",
        "recovery",
        "response",
        "workspace",
    ]
    state: Literal["ready", "missing", "invalid", "blocked", "unverified"]
    setting_names: tuple[str, ...] = Field(default=(), max_length=32)
    owner: Owner = "operator"
    action_id: ActionId

    @field_validator("setting_names")
    @classmethod
    def names(cls, value):
        """Allow only reviewed short names, never values or arbitrary diagnostics."""
        if len(set(value)) != len(value) or any(
            name not in SETTING_NAMES or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name)
            for name in value
        ):
            raise ValueError("invalid_setting_names")
        return value


class DeploymentObservation(BaseModel):
    """Ephemeral read-only store classification; no lifecycle journal is introduced."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    root_state: Literal["valid", "wrong-directory", "unavailable"] = "valid"
    recovery_state: Literal[
        "not-applicable", "absent", "clear", "busy", "blocked", "mismatch", "invalid"
    ] = "not-applicable"
    response_state: Literal[
        "not-applicable", "absent", "draft", "enrolled", "busy", "held", "mismatch", "invalid"
    ] = "not-applicable"


class SetupAction(BaseModel):
    """A suggestion with explicit ownership and dependencies, never execution permission."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    id: ActionId
    effect: Effect = "none"
    disposition: Literal["available", "after-prerequisites", "blocked"] = "available"
    requires: tuple[ActionId, ...] = Field(default=(), max_length=16)
    owner: Owner = "operator"
    command_id: CommandId | None = None

    @model_validator(mode="after")
    def dependencies(self):
        """Reject self-reference and duplicates before graph validation."""
        if self.id in self.requires or len(set(self.requires)) != len(self.requires):
            raise ValueError("invalid_action_dependencies")
        return self


class SetupGuide(BaseModel):
    """Bounded public guidance, separate from the compatible SetupReport v1."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    recipe: RecipeId
    state: Literal[
        "needs-input",
        "needs-enrollment",
        "needs-review",
        "ready-to-launch",
        "blocked",
        "offline-ready",
    ]
    proof_scope: ProofScope
    findings: tuple[PrerequisiteFinding, ...] = Field(default=(), max_length=32)
    actions: tuple[SetupAction, ...] = Field(default=(), max_length=16)
    exit_code: Literal[0, 2, 3] = 0

    @model_validator(mode="after")
    def graph(self):
        """Reject duplicate IDs, dangling dependencies and cycles in the emitted graph."""
        for collection in (self.findings, self.actions):
            if len({item.id for item in collection}) != len(collection):
                raise ValueError("duplicate_guide_id")
        actions = {item.id: item for item in self.actions}
        visited, active = set(), set()

        def visit(identifier):
            """Traverse a graph bounded to sixteen actions without executing anything."""
            if identifier in active or identifier not in actions:
                raise ValueError("invalid_action_graph")
            if identifier in visited:
                return
            active.add(identifier)
            for dependency in actions[identifier].requires:
                visit(dependency)
            active.remove(identifier)
            visited.add(identifier)

        for identifier in actions:
            visit(identifier)
        if len(self.model_dump_json().encode()) > 32768:
            raise ValueError("guide_output_exceeded")
        return self
