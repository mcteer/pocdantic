"""Strict bounded records and safe errors for synthetic regression evidence."""

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
CaseID = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,47}$")]
Count = Annotated[int, Field(strict=True, ge=0, le=10000)]
Profile = Literal["baseline", "restricted"]
Outcome = Literal["pass", "fail", "blocked", "incomplete"]
Phase = Literal["pass", "fail", "skip", "xfail", "xpass", "missing"]
Reason = Literal[
    "catalog_invalid",
    "unknown_selection",
    "empty_selection",
    "selection_incomplete",
    "collection_failed",
    "test_failed",
    "test_skipped",
    "expected_failure",
    "unexpected_pass",
    "phase_missing",
    "protocol_invalid",
    "content_changed",
    "timeout",
    "interrupted",
    "child_failed",
    "storage_error",
    "limits_exceeded",
    "unsafe_path",
    "run_busy",
    "incomplete_run",
    "not_selected",
    "native_evidence_required",
    "audit_unavailable",
    "dependency_missing",
    "isolation_failed",
    "cleanup_unknown",
    "artifact_mismatch",
    "current_content_unavailable",
    "internal_error",
]
GROUPS = tuple(f"F12-T{i}" for i in range(1, 11))
BUILDS = tuple(f"F12.{i:02}" for i in range(1, 15))
VERSION_KEYS = (
    "python",
    "pytest",
    "pytest-asyncio",
    "pydantic",
    "pydantic-ai-slim",
    "pydantic-settings",
    "httpx",
    "pyjwt",
    "cryptography",
    "psycopg",
    "fastapi",
    "uvicorn",
    "logfire",
    "opentelemetry-api",
    "opentelemetry-sdk",
)


class RegressionError(ValueError):
    """Carry only a compiled reason; upstream diagnostic text must never escape."""

    def __init__(self, code="internal_error"):
        """Normalize unexpected reasons to the safe internal-error disposition."""
        self.code = code if code in Reason.__args__ else "internal_error"
        super().__init__(self.code)


def canonical(value):
    """Serialize normalized records deterministically for integrity hashing."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    """Hash a normalized record without relying on labels or cached revisions."""
    return hashlib.sha256(canonical(value)).hexdigest()


def now():
    """Return an unambiguous UTC timestamp suitable for immutable records."""
    return datetime.now(UTC).isoformat()


def decode(raw, limit=8 * 1024 * 1024):
    """Reject duplicate keys, nonfinite numbers and JSON deeper than eight levels."""
    if len(raw) > limit:
        raise RegressionError("limits_exceeded")

    def pairs(items):
        """Preserve object semantics by rejecting duplicate keys."""
        result = {}
        for key, value in items:
            if key in result:
                raise RegressionError("protocol_invalid")
            result[key] = value
        return result

    def invalid(_):
        """Reject nonstandard numeric constants."""
        raise RegressionError("protocol_invalid")

    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
        pending = [(result, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > 8:
                raise RegressionError("limits_exceeded")
            if isinstance(value, dict):
                pending.extend((v, depth + 1) for v in value.values())
            elif isinstance(value, list):
                pending.extend((v, depth + 1) for v in value)
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise RegressionError("protocol_invalid") from None


class StrictRecord(BaseModel):
    """Forbid coercion and extra fields at every persisted boundary."""

    model_config = ConfigDict(extra="forbid", strict=True)


class Case(StrictRecord):
    """Bind fixed test functions to reviewed security expectations and ownership."""

    case_id: CaseID
    groups: list[str] = Field(min_length=1, max_length=10)
    build_items: list[str] = Field(min_length=1, max_length=14)
    selectors: list[str] = Field(min_length=1, max_length=32)
    boundary: Literal[
        "model",
        "tool",
        "identity",
        "approval",
        "vault",
        "database",
        "incident",
        "governance",
        "publication",
        "reporting",
    ]
    severity: Literal["critical", "high", "medium", "low"]
    owner: Literal["agent", "identity", "vault", "database", "security", "integration"]
    configuration_applicability: Literal["fixed", "profile-sensitive"] = "fixed"
    expectations: list[Annotated[str, Field(pattern=r"^[a-z0-9-]{1,48}$")]] = Field(
        min_length=1, max_length=16
    )
    rationale: str = Field(min_length=1, max_length=512)

    @field_validator("groups", "build_items", "selectors", "expectations")
    @classmethod
    def unique(cls, values, info):
        """Reject duplicate mappings and executable selector expressions."""
        if len(set(values)) != len(values):
            raise ValueError("duplicate")
        allowed = {"groups": GROUPS, "build_items": BUILDS}.get(info.field_name)
        if allowed and any(v not in allowed for v in values):
            raise ValueError("unknown")
        if info.field_name == "selectors" and any(
            len(v) > 256
            or not re.fullmatch(r"tests/test_[a-z0-9_]+\.py::(?:Test\w+::)?test_\w+", v)
            for v in values
        ):
            raise ValueError("selector")
        return values


class IdentityRecord(StrictRecord):
    """Identify one run and its exact selected source snapshot."""

    schema_version: Literal[1] = 1
    run_id: str
    content_digest: Digest
    selection_digest: Digest

    @field_validator("schema_version", mode="before")
    @classmethod
    def schema(cls, value):
        """A boolean must not masquerade as schema version one."""
        if type(value) is not int or value != 1:
            raise ValueError("schema")
        return value

    @field_validator("started_at", "finished_at", check_fields=False)
    @classmethod
    def finished_utc(cls, value):
        """Terminal timestamps must remain timezone-aware UTC."""
        if value is None:
            return value
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() != UTC.utcoffset(parsed):
            raise ValueError("utc")
        return value

    @field_validator("run_id")
    @classmethod
    def uuid(cls, value):
        """Require canonical UUID text; never accept paths as run identifiers."""
        if str(UUID(value)) != value:
            raise ValueError("uuid")
        return value


class Manifest(IdentityRecord):
    """Freeze the complete selection, policy identities and deadline before execution."""

    state: Literal["running"] = "running"
    started_at: str
    deadline_at: str
    cases: list[CaseID] = Field(min_length=1, max_length=256)
    profiles: list[Profile] = Field(min_length=1, max_length=2)
    complete_catalog: bool
    catalog_digest: Digest
    profile_digests: dict[Profile, Digest]
    versions: dict[str, str]
    base_digest: Digest
    platform: Literal["macOS", "Linux"]

    @field_validator("started_at", "deadline_at")
    @classmethod
    def utc(cls, value):
        """Reject ambiguous local timestamps."""
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() != UTC.utcoffset(parsed):
            raise ValueError("utc")
        return value

    @field_validator("cases", "profiles")
    @classmethod
    def unique(cls, values):
        """Selections are sets with deterministic ordering, never repeated execution."""
        if len(set(values)) != len(values):
            raise ValueError("duplicate")
        return values

    @field_validator("versions")
    @classmethod
    def versions_safe(cls, values):
        """Version metadata accepts known packages and printable bounded version labels."""
        if len(values) > 32 or any(
            k not in VERSION_KEYS or not re.fullmatch(r"[A-Za-z0-9.+!_-]{1,128}", v)
            for k, v in values.items()
        ):
            raise ValueError("versions")
        return values


class Frame(IdentityRecord):
    """One bounded protocol event; node IDs are represented only by hashes."""

    seq: Annotated[int, Field(strict=True, ge=1)]
    kind: Literal["collection", "item", "terminal", "error"]
    profile: Profile
    selector: str | None = None
    node_digest: Digest | None = None
    ordinal: Annotated[int, Field(strict=True, ge=1, le=10000)] | None = None
    started_at: str | None = None
    finished_at: str | None = None
    phases: list[Phase] = Field(default_factory=list, max_length=3)
    counters: dict[Literal["attempted", "issued", "completed", "forbidden"], Count] = Field(
        default_factory=dict
    )
    count: Count = 0
    inventory_digest: Digest | None = None
    exit_code: Annotated[int, Field(strict=True, ge=0, le=255)] | None = None
    reason: Reason | None = None


class Seal(IdentityRecord):
    """Bind final artifacts to exact ownership, process completion and result count."""

    artifacts: dict[str, Digest]
    profile_digests: dict[Profile, Digest]
    count: Count
    state: Literal["completed", "failed", "interrupted", "incomplete"]
    finished_at: str
    exit_code: Annotated[int, Field(strict=True, ge=0, le=255)] | None
    cleanup: Literal["drained", "unknown"]
    reason: Reason | None = None

    @model_validator(mode="after")
    def terminal_consistency(self):
        """A completed seal requires clean exit, drain and no operational failure."""
        if self.state == "completed" and (
            self.exit_code != 0
            or self.cleanup != "drained"
            or self.reason is not None
            or self.count == 0
        ):
            raise ValueError("terminal")
        return self


class NativeDisposition(StrictRecord):
    """Compiled provider prerequisites can describe only a blocked native outcome."""

    group: str
    outcome: Literal["blocked"]
    owner: Literal["agent", "identity", "vault", "database", "security", "integration"]
    reason: Literal["native_evidence_required", "audit_unavailable"]
    prerequisite: str = Field(min_length=1, max_length=512)
    action: str = Field(min_length=1, max_length=512)
    recheck: str = Field(min_length=1, max_length=512)

    @field_validator("group")
    @classmethod
    def known_group(cls, value):
        """Only the ten reviewed security groups can claim a prerequisite disposition."""
        if value not in GROUPS:
            raise ValueError("group")
        return value


class Integrity(IdentityRecord):
    """Bind the terminal seal and derived report without a self-referential hash."""

    artifacts: dict[Literal["seal.json", "report.json"], Digest]
