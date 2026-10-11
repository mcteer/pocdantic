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
