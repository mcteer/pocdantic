"""Strict content-free boundaries for model routing, evidence and control reviews."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent.security import SecurityError

Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Protocol = Literal["google-cloud", "openai-chat", "openai-responses", "anthropic"]
CODES = frozenset(
    {
        "model_mode_required",
        "gateway_configuration_invalid",
        "gateway_model_denied",
        "gateway_review_required",
        "gateway_payload_unsupported",
        "gateway_guardrail_denied",
        "gateway_budget_denied",
        "gateway_auth_denied",
        "gateway_rate_limited",
        "gateway_request_failed",
        "gateway_dispatch_unknown",
        "gateway_observation_failed",
    }
)


def now() -> datetime:
    """Return aware UTC for expiry and evidence observations."""
    return datetime.now(UTC)


class GatewayError(SecurityError):
    """Expose only a closed reason; never retain native exception bodies as arguments."""

    def __init__(self, code: str = "gateway_request_failed"):
        super().__init__(code if code in CODES else "gateway_request_failed")


class Boundary(BaseModel):
    """Immutable, extra-forbidding base for private and public metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class RoutePolicy(Boundary):
    """One admitted native model and exact hosted destination; no credentials."""

    region: Literal["us", "eu"]
    route: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    protocol: Protocol
    model: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
    allowed_models: tuple[str, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def admitted(self):
        """Require exact selection and validate every list member, including dormant ones."""
        import re

        if len(set(self.allowed_models)) != len(self.allowed_models):
            raise ValueError("gateway_configuration_invalid")
        for name in self.allowed_models:
            prefix, sep, model = name.partition(":")
            if (
                prefix not in {"google-cloud", "openai-chat", "openai-responses", "anthropic"}
                or not sep
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", model)
                or ".." in model
            ):
                raise ValueError("gateway_configuration_invalid")
        if f"{self.protocol}:{self.model}" not in self.allowed_models or ".." in self.model:
            raise ValueError("gateway_model_denied")
        return self

    @property
    def base_url(self) -> str:
        """Use vendor HTTPS hosts only; never interpret route as a URL."""
        return f"https://gateway-{self.region}.pydantic.dev"


class SpendControl(Boundary):
    """Administrator-observed remote limits, not local billing authority."""

    daily_usd: int = Field(ge=0, strict=True)
    monthly_usd: int = Field(ge=0, strict=True)
    require_pricing: Literal[True]
    blocking: Literal[True]
    currency: Literal["USD"] = "USD"


class Observation(Boundary):
    """Fixed probe or administrative control observation, without payload text."""

    case_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9_-]+$")
    disposition: Literal["pass", "fail", "blocked", "unknown"]
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def aware(cls, value):
        """Refuse ambiguous/future evidence timestamps."""
        if value.tzinfo is None or value > now():
            raise ValueError("gateway_review_required")
        return value.astimezone(UTC)


class ErrorSignature(Boundary):
    """Exact reviewed vendor code or response fingerprint; status alone never proves denial."""

    status: int = Field(ge=400, le=599)
    field: Literal["code", "error.code", "error.type", "response_sha256"]
    value: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    reason: Literal[
        "gateway_guardrail_denied",
        "gateway_budget_denied",
        "gateway_model_denied",
        "gateway_auth_denied",
        "gateway_rate_limited",
    ]

    @model_validator(mode="after")
    def fingerprint(self):
        """Require a full lowercase digest for exact native-response matching."""
        import re

        if self.field == "response_sha256" and not re.fullmatch(r"[0-9a-f]{64}", self.value):
            raise ValueError("gateway_review_required")
        return self

    def matches(self, status, raw):
        """Match reviewed codes or exact bounded response bytes without exporting raw errors.

        Some native protocols expose only a generic numeric code and a fixed refusal
        body. A reviewed fingerprint handles that shape without classifying arbitrary
        INVALID_ARGUMENT responses or searching untrusted message text for keywords.
        Formatting changes intentionally stop matching until evidence is reviewed again.
        """
        import hashlib

        if status != self.status or len(raw) > 16384:
            return False
        if self.field == "response_sha256":
            return hashlib.sha256(raw).hexdigest() == self.value
        import json

        try:
            data = json.loads(raw)
            for part in self.field.split("."):
                data = data[part]
            return status == self.status and data == self.value
        except (ValueError, KeyError, TypeError, RecursionError):
            return False


class EvidenceBundle(Boundary):
    """Operator-supplied private source manifest; only live complete evidence can approve."""

    schema_version: Literal[1] = 1
    source: Literal["live", "synthetic"]
    administration: Literal["reviewed", "operator-owned"] = "reviewed"
    policy_digest: Digest
    credential_digest: Digest
    implementation_digest: Digest
    control_revision: Digest
    controls: dict[Literal["routing", "protection", "spending", "privacy"], Observation]
    observations: tuple[Observation, ...] = Field(max_length=4096)
    manifest: dict[str, Digest] = Field(min_length=1, max_length=1024)
    error_signatures: tuple[ErrorSignature, ...] = Field(default=(), max_length=16)
    spend: SpendControl | None = None

    @model_validator(mode="after")
    def control_scope(self):
        """Keep owner-managed administration explicit without relaxing required controls.

        Legacy bundles require actual spend evidence. Owner-managed bundles make no
        spending or internal-retention acceptance claim; routing, blocking and visible
        telemetry privacy still require complete live evidence and explicit review.
        """
        required = {"routing", "protection", "privacy"}
        if self.administration == "reviewed":
            required.add("spending")
        if set(self.controls) != required or (self.spend is None) != (
            self.administration == "operator-owned"
        ):
            raise ValueError("gateway_review_required")
        return self

    @field_validator("manifest")
    @classmethod
    def basenames(cls, values):
        """Keep source references under the selected private directory."""
        from .config import safe_name

        if any(not safe_name(name) or name == "bundle.json" for name in values):
            raise ValueError("gateway_review_required")
        return values


class ControlReview(Boundary):
    """Immutable approval or unconditional rejection of further model dispatch."""

    schema_version: Literal[1] = 1
    review_id: UUID = Field(default_factory=uuid4)
    decision: Literal["approved", "rejected"]
    administration: Literal["reviewed", "operator-owned"] = "reviewed"
    reviewer: str = Field(min_length=1, max_length=128, repr=False)
    reviewed_at: datetime = Field(default_factory=now)
    observed_at: datetime | None = None
    expires_at: datetime | None = None
    policy_digest: Digest | None = None
    credential_digest: Digest | None = None
    implementation_digest: Digest | None = None
    evidence_digest: Digest | None = None
    control_revision: Digest | None = None
    evidence_directory: str | None = Field(default=None, repr=False)
    error_signatures: tuple[ErrorSignature, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def approval(self):
        """Rejection cannot be blocked by absent/stale evidence; approval is always bounded."""
        if self.reviewed_at.tzinfo is None or self.reviewed_at > now():
            raise ValueError("gateway_review_required")
        if self.decision == "approved":
            values = (
                self.policy_digest,
                self.credential_digest,
                self.implementation_digest,
                self.evidence_digest,
                self.control_revision,
                self.evidence_directory,
            )
            if not all(values) or self.observed_at is None or self.expires_at is None:
                raise ValueError("gateway_review_required")
            if (
                self.observed_at.tzinfo is None
                or self.expires_at.tzinfo is None
                or not self.observed_at
                <= self.reviewed_at
                < self.expires_at
                <= self.observed_at + timedelta(hours=24)
            ):
                raise ValueError("gateway_review_required")
        return self


class ReviewPointer(Boundary):
    """Atomic selection of one immutable decision; no filename sorting."""

    schema_version: Literal[1] = 1
    review_id: UUID


class ModelAttempt(Boundary):
    """Content-free model attempt with explicit uncertainty and opaque model references."""

    attempt_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    request_id: UUID
    definition_ref: UUID
    workload_ref: UUID
    parent_run_id: UUID | None = None
    sequence: int = Field(gt=0)
    route_ref: UUID
    model_ref: UUID
    protocol: Protocol
    stage: Literal[
        "admitted", "dispatched", "completed", "denied", "failed", "cancelled", "unknown"
    ]
    reason: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    cost_usd: str | None = None
    cost_state: Literal["known", "unknown"] = "unknown"
    cost_source: Literal["gateway", "provider", "unavailable"] = "unavailable"
    telemetry_state: Literal["ok", "degraded"] = "ok"

    @model_validator(mode="after")
    def closed(self):
        """Reject arbitrary reasons and misleading missing-price zeroes."""
        if self.reason is not None and self.reason not in CODES:
            raise ValueError("gateway_configuration_invalid")
        if self.cost_state == "unknown":
            if self.cost_usd is not None or self.cost_source != "unavailable":
                raise ValueError("gateway_configuration_invalid")
        elif (
            self.cost_usd is None
            or self.cost_source == "unavailable"
            or not Decimal(self.cost_usd).is_finite()
            or Decimal(self.cost_usd) < 0
        ):
            raise ValueError("gateway_configuration_invalid")
        return self
