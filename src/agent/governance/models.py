"""Strict private governance contracts and closed, credential-free outcome vocabulary.

A finding is not an authenticated workload. Bindings and trust profiles are host-reviewed;
effect records contain intent, digests and times rather than bearer credentials.
"""

import math
import re
from collections import Counter
from datetime import datetime
from typing import Annotated, Literal, get_args
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from agent.recovery.models import Digest, Private, Revision, now
from agent.security import SecurityError

Alias = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,30}$")]
Native = Annotated[str, Field(min_length=1, max_length=256)]
Outcome = Literal["pass", "fail", "blocked", "inconclusive"]
Provenance = Literal["synthetic", "operator", "native"]
AttemptState = Literal["prepared", "submitted", "confirmed", "denied", "uncertain", "conflict"]
PATHS = {"preregistration", "obo_allowed", "obo_beyond_ceiling", "direct_allowed", "direct_denied"}
REASONS = {
    "ok",
    "not_initialized",
    "invalid_input",
    "sign_in_required",
    "source_not_ready",
    "source_invalid",
    "replay_conflict",
    "registry_conflict",
    "review_stale",
    "contained",
    "workspace_busy",
    "creation_uncertain",
    "bootstrap_mismatch",
    "trust_unavailable",
    "identity_rejected",
    "proof_inconclusive",
    "native_evidence_missing",
    "audit_unavailable",
    "issuance_unresolved",
    "capacity_exhausted",
    "storage_error",
    "configuration_changed",
    "missing_authority",
    "unsupported",
    "provider_denied",
    "effect_uncertain",
    "challenge_invalid",
    "closed",
}
Reason = Literal[tuple(sorted(REASONS))]


class GovernanceError(SecurityError):
    """Expose a fixed code only; private identifiers and upstream errors never escape."""

    def __init__(self, code="storage_error", *, effect=False):
        """Coerce unexpected failures to the closed storage error category."""
        self.effect = effect is True
        super().__init__(code if code in REASONS else "storage_error")


def require(condition, code="invalid_input"):
    """Reject a false trusted-boundary predicate using a safe public code."""
    if not condition:
        raise GovernanceError(code)


def https(value, origin=False):
    """Validate an exact HTTPS target, rejecting credentials, query and path tricks."""
    p = urlsplit(value)
    port = p.port
    if (
        (port is not None and not 1 <= port <= 65535)
        or p.scheme != "https"
        or not p.hostname
        or p.username
        or p.password
        or p.query
        or p.fragment
        or "?" in value
        or "#" in value
        or any(ord(c) < 33 or ord(c) > 126 for c in value)
        or (origin and p.path not in {"", "/"})
        or any(x in {".", ".."} for x in p.path.split("/"))
        or "%" in value
        or "\\" in value
    ):
        raise ValueError("invalid_input")
    return value.rstrip("/") if origin else value


def path(value):
    """Permit only unambiguous Vault path components, never arbitrary URLs or traversal."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", value):
        raise ValueError("invalid_input")
    return value


def segment_id(value):
    """Constrain Vault-native path IDs to one literal component, never encoded traversal."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", value):
        raise ValueError("invalid_input")
    return value


def spiffe(value):
    """Require an exact canonical SPIFFE ID with no URI authority/path ambiguity."""
    p = urlsplit(value)
    if (
        len(value) > 255
        or p.scheme != "spiffe"
        or not p.hostname
        or p.netloc != p.hostname
        or not re.fullmatch(r"[a-z0-9._-]+", p.hostname)
        or not re.fullmatch(r"/[A-Za-z0-9._/-]+", p.path)
        or "?" in value
        or "#" in value
        or not p.path.startswith("/")
        or p.query
        or p.fragment
        or "%" in value
        or "\\" in value
        or any(x in {"", ".", ".."} for x in p.path[1:].split("/"))
    ):
        raise ValueError("identity_rejected")
    return value


class Record(Private):
    """Common frozen, no-extra-fields private boundary with canonical UUID input."""

    @field_validator("*", mode="before")
    @classmethod
    def canonical_uuid(cls, value, info):
        """Refuse alternate UUID spellings rather than silently normalizing native input."""
        annotation = cls.model_fields[info.field_name].annotation
        if isinstance(value, str) and (annotation is UUID or UUID in get_args(annotation)):
            if str(UUID(value)) != value:
                raise ValueError("invalid_input")
        return value


class Trust(Record):
    """One approved Vault identity and independently pinned public verification source."""

    issuer: Native
    subject: Annotated[str, Field(min_length=1, max_length=255)]
    audience: Native
    entity_id: Native
    namespace: Annotated[str, Field(max_length=256)] = ""
    mount: Native
    role: Native
    discovery_url: Native
    jwks_url: Native
    algorithm: Literal["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"] = "RS256"
    max_ttl: StrictInt = Field(default=300, ge=1, le=300)
    oauth_max_ttl: StrictInt | None = Field(default=None, ge=1, le=86400)
    server_completion_bound: StrictInt | None = Field(default=None, ge=1, le=120)
    role_digest: Digest
    config_digest: Digest

    _urls = field_validator("issuer", "discovery_url", "jwks_url")(https)
    _subject = field_validator("subject")(spiffe)
    _paths = field_validator("mount", "role")(path)


class Binding(Record):
    """Exact reviewed actor/entity/owner/policy join, independent of source claims."""

    owner_issuer: Native
    owner_subject: Native
    owner: Native
    purpose: Native
    definition: Alias
    actor_issuer: Native
    actor_subject: Native
    source_object: Native
    client: Alias
    healthy_client: Alias
    entity_id: Native
    alias_id: Native
    oauth_profile: Native
    registry_name: Native
    vault_origin: Native
    namespace: Annotated[str, Field(max_length=256)] = ""
    ceiling_policies: tuple[Native, ...] = Field(min_length=1, max_length=8)
    policies: dict[Native, Digest] = Field(min_length=1, max_length=16)
    paths: dict[str, Native]
    trust: Trust
    exclusive: Literal[True]
    entitlement_digest: Digest
    registry_clock_bound: StrictInt | None = Field(default=None, ge=0, le=5)
    no_default_ceiling_policy: Literal[True] = True
    optional_authorization_details: Literal[False] = False

    @field_validator("vault_origin")
    @classmethod
    def origin(cls, value):
        """Pin one origin; requests cannot inherit path/query authority from configuration."""
        return https(value, origin=True)

    _issuer = field_validator("actor_issuer", "owner_issuer")(https)

    @field_validator("namespace")
    @classmethod
    def exact_namespace(cls, value):
        """Accept only exact namespace components; HTTP header text cannot hide traversal."""
        if value:
            if not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*/?", value):
                raise ValueError("invalid_input")
        return value

    _components = field_validator("oauth_profile")(path)
    _ids = field_validator("entity_id", "alias_id", "registry_name")(segment_id)

    @field_validator(
        "exclusive", "no_default_ceiling_policy", "optional_authorization_details", mode="before"
    )
    @classmethod
    def exact_flag(cls, value):
        """Reject numeric equivalents of security-sensitive boolean flags."""
        if type(value) is not bool:
            raise ValueError("invalid_input")
        return value

    @model_validator(mode="after")
    def narrow(self):
        """Require exact fixture paths, distinct control and complete ceiling/trust binding."""
        if (
            set(self.paths) != PATHS
            or "root" in self.ceiling_policies
            or len(set(self.ceiling_policies)) != len(self.ceiling_policies)
            or not set(self.ceiling_policies) <= self.policies.keys()
            or self.client == self.healthy_client
            or self.entity_id != self.trust.entity_id
            or self.namespace != self.trust.namespace
            or self.exclusive is not True
        ):
            raise ValueError("invalid_input")
        for p in self.paths.values():
            path(p)
            if not re.fullmatch(r"[A-Za-z0-9_-]+/data/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", p):
                raise ValueError("invalid_input")
        return self


class Source(Record):
    """Reviewed scalar projection and separate relay authority, with no action fields."""

    alias: Alias
    generation: Revision = 1
    model_config = {"populate_by_name": True, "serialize_by_alias": True}

    product: Native
    product_version: Native = Field(alias="version")
    instance: Native
    issuer: Native
    subject: Native
    audience: Native
    schema_digest: Digest
    fixture_digest: Digest
    collector_digest: Digest
    pointers: dict[str, str] = Field(min_length=4, max_length=12)
    predicates: dict[str, str | StrictInt | StrictBool] = Field(default_factory=dict, max_length=8)
    kinds: dict[Native, Literal["unknown", "managed", "triaged", "notification"]]
    provenance: Provenance = "operator"
    clock_bound: StrictInt | None = Field(default=None, ge=0, le=5)

    _issuer = field_validator("issuer")(https)

    @model_validator(mode="after")
    def projection(self):
        """Only reviewed observation fields and restricted JSON Pointers are executable."""
        allowed = {"event", "object", "kind", "time", "first_seen", "confidence", "correlation"}
        if not {"event", "object", "kind", "time"} <= self.pointers.keys() <= allowed:
            raise ValueError("invalid_input")
        for p in (*self.pointers.values(), *self.predicates.keys()):
            if len(p) > 256 or not p.startswith("/") or re.search(r"~(?![01])", p):
                raise ValueError("invalid_input")
        return self


class Observation(Record):
    """Immutable selected-content record, never an authentication or enrollment grant."""

    observation_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    source: Alias
    source_generation: Revision
    source_digest: Digest
    event: Native
    object: Native
    kind: Literal["unknown", "managed", "triaged", "notification"]
    occurred_at: datetime
    received_at: datetime = Field(default_factory=now)
    first_seen: datetime | None = None
    confidence: str | float | None = None
    correlation: UUID | None = None
    selected_digest: Digest
    provenance: Provenance

    @field_validator("confidence", mode="before")
    @classmethod
    def confidence_shape(cls, v):
        """Keep bounded source confidence without assuming cross-source comparability."""
        if v is None or type(v) is str and 1 <= len(v) <= 64:
            return v
        if type(v) in (float, int) and math.isfinite(v):
            return float(v)
        raise ValueError("invalid_input")


class Readiness(Record):
    """A fresh private metadata snapshot bound to a single candidate draft."""

    checked_at: datetime = Field(default_factory=now)
    binding_digest: Digest
    metadata_digest: Digest
    ready: StrictBool
    reason: Reason
    fingerprints: dict[Native, Digest] = Field(default_factory=dict, max_length=32)
    checks: dict[
        Literal[
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
            "configuration",
        ],
        Reason,
    ] = Field(default_factory=dict)


class Candidate(Record):
    """Local case lifecycle, immutable discovery links and reviewed provider mapping."""

    candidate_id: UUID = Field(default_factory=uuid4)
    case_id: UUID = Field(default_factory=uuid4)
    alias: Alias
    source: Alias
    source_generation: Revision
    source_snapshot: Source | None = None
    revision: Revision = 1
    generation: Revision = 1
    state: Literal[
        "prepared", "observed", "reviewed", "enrolling", "registered", "blocked", "closed"
    ] = "prepared"
    created_at: datetime = Field(default_factory=now)
    closed_at: datetime | None = None
    binding: Binding | None = None
    readiness: Readiness | None = None
    registration_id: Native | None = None
    registration_digest: Digest | None = None
    registered_at: datetime | None = None
    reason: Reason = "ok"

    @model_validator(mode="after")
    def lifecycle(self):
        """Reject lifecycle claims that omit their corresponding durable timestamps/binding."""
        if self.state == "closed" and self.closed_at is None:
            raise ValueError("closed")
        if self.state == "registered" and not all(
            (self.binding, self.registration_id, self.registration_digest, self.registered_at)
        ):
            raise ValueError("creation_uncertain")
        if self.state in {"reviewed", "enrolling"} and not (self.binding and self.readiness):
            raise ValueError("review_stale")
        return self


class Review(Record):
    """One-use exact enrollment decision, invalidated by any input revision change."""

    review_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    candidate_revision: Revision
    journal_revision: Revision
    binding_digest: Digest
    metadata_digest: Digest
    evidence_digest: Digest
    implementation: Digest
    operator: Alias
    created_at: datetime = Field(default_factory=now)
    consumed: StrictBool = False


class RegistrationAttempt(Record):
    """Durable registration intent; readback presence does not establish creation ownership."""

    attempt_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    generation: Revision
    review_id: UUID
    binding_digest: Digest
    state: AttemptState = "prepared"
    submitted_at: datetime | None = None
    finished_at: datetime | None = None
    registration_id: Native | None = None
    readback_digest: Digest | None = None
    source_digest: Digest | None = None
    reason: Reason = "ok"

    @model_validator(mode="after")
    def lifecycle(self):
        """An acknowledged ID alone is insufficient to represent confirmed enrollment."""
        if (
            self.state in {"submitted", "confirmed", "uncertain", "conflict"}
            and self.submitted_at is None
        ):
            raise ValueError("creation_uncertain")
        if self.state == "confirmed" and not all(
            (self.finished_at, self.registration_id, self.readback_digest, self.source_digest)
        ):
            raise ValueError("creation_uncertain")
        return self


class CredentialIntent(Record):
    """Possible credential issuance without retaining any token; unknown bounds pin state."""

    intent_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    generation: Revision
    profile_digest: Digest
    kind: Literal["actor_oauth", "obo_oauth", "svid"]
    state: AttemptState = "prepared"
    submitted_at: datetime | None = None
    finished_at: datetime | None = None
    token_digest: Digest | None = None
    expires_at: datetime | None = None
    safe_after: datetime | None = None
    reason: Reason = "ok"

    @property
    def unresolved(self):
        """Unknown issuance pins capacity until a reviewed last-possible-use bound passes."""
        return self.state in {"prepared", "submitted"} or (
            self.state in {"uncertain", "conflict"}
            and (self.safe_after is None or self.safe_after > now())
        )

    @model_validator(mode="after")
    def lifetime(self):
        """A confirmed credential needs signed expiry and a conservative last-use bound."""
        if self.state == "confirmed" and (
            self.token_digest is None
            or self.expires_at is None
            or self.safe_after is None
            or self.safe_after < self.expires_at
            or self.submitted_at is None
            or self.finished_at is None
        ):
            raise ValueError("issuance_unresolved")
        if self.state in {"submitted", "uncertain"} and self.submitted_at is None:
            raise ValueError("issuance_unresolved")
        return self


class Facts(Record):
    """Structured private attribution; freeform artifact text cannot establish a pass."""

    status: StrictInt | None = Field(default=None, ge=100, le=599)
    control_status: StrictInt | None = Field(default=None, ge=100, le=599)
    baseline_status: StrictInt | None = Field(default=None, ge=100, le=599)
    proof_id: UUID | None = None
    completed_at: datetime | None = None
    no_issuance: StrictBool = False
    vault_audit_digest: Digest | None = None
    source_audit_digest: Digest | None = None
    negative_classes: tuple[Literal["signature", "audience", "expiry", "trust", "entity"], ...] = ()


class Evidence(Record):
    """Strict correlated private proof metadata, source artifacts and explicit review."""

    evidence_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    case_id: UUID
    generation: Revision
    environment: Digest
    implementation: Digest
    binding_digest: Digest
    source_digest: Digest
    artifact_digest: Digest
    kind: Literal[
        "discovery",
        "notification",
        "registry_absence",
        "registration",
        "identity",
        "preregistration",
        "obo_allowed",
        "obo_beyond_ceiling",
        "direct_allowed",
        "direct_denied",
        "unauthenticated_mint",
        "verifier_negatives",
        "triage",
        "audit",
        "resolution",
    ]
    outcome: Outcome
    provenance: Provenance
    observed_at: datetime
    received_at: datetime = Field(default_factory=now)
    clock_bound: StrictInt | None = Field(default=None, ge=0, le=5)
    independent: StrictBool = False
    healthy: StrictBool = False
    attributed: StrictBool = False
    reviewed_by: Alias | None = None
    reviewed_at: datetime | None = None
    facts: Facts | None = None
    observation_id: UUID | None = None
    attempt_id: UUID | None = None

    @model_validator(mode="after")
    def review_pair(self):
        """Require review identity and timestamp together without promoting provenance."""
        if (self.reviewed_by is None) != (self.reviewed_at is None):
            raise ValueError("invalid_input")
        return self


class Challenge(Record):
    """One-time proof nonce digest tied to current enrollment and a specific mint intent."""

    challenge_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    generation: Revision
    intent_id: UUID
    binding_digest: Digest
    implementation: Digest
    nonce_digest: Digest
    created_at: datetime = Field(default_factory=now)
    consumed: StrictBool = False


class Verification(Record):
    """Safe relying result with private fingerprints, never the original credential."""

    proof_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    generation: Revision
    challenge_id: UUID
    token_digest: Digest
    trust_digest: Digest
    result: Outcome
    reason: Reason
    expires_at: datetime | None = None
    observed_at: datetime = Field(default_factory=now)


class Journal(Record):
    """One bounded atomic authority/evidence snapshot with cross-reference validation."""

    installation_id: UUID
    environment: Digest
    revision: Revision = 1
    sources: tuple[Source, ...] = Field(default=(), max_length=16)
    candidates: tuple[Candidate, ...] = Field(default=(), max_length=1000)
    observations: tuple[Observation, ...] = Field(default=(), max_length=10000)
    reviews: tuple[Review, ...] = ()
    registrations: tuple[RegistrationAttempt, ...] = ()
    credentials: tuple[CredentialIntent, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    challenges: tuple[Challenge, ...] = ()
    verifications: tuple[Verification, ...] = ()

    @model_validator(mode="after")
    def references(self):
        """Reject dangling, duplicate and cross-candidate records before committing state."""
        candidates = {c.candidate_id: c for c in self.candidates}
        if len(candidates) != len(self.candidates) or len({s.alias for s in self.sources}) != len(
            self.sources
        ):
            raise ValueError("storage_error")
        for name, key in (
            ("observations", "observation_id"),
            ("reviews", "review_id"),
            ("registrations", "attempt_id"),
            ("credentials", "intent_id"),
            ("evidence", "evidence_id"),
            ("challenges", "challenge_id"),
            ("verifications", "proof_id"),
        ):
            values = getattr(self, name)
            if len({getattr(v, key) for v in values}) != len(values):
                raise ValueError("storage_error")
            if any(v.candidate_id not in candidates for v in values):
                raise ValueError("storage_error")
        if len({c.case_id for c in self.candidates}) != len(self.candidates) or len(
            {c.alias for c in self.candidates}
        ) != len(self.candidates):
            raise ValueError("storage_error")
        if len({c.intent_id for c in self.challenges}) != len(self.challenges) or len(
            {v.challenge_id for v in self.verifications}
        ) != len(self.verifications):
            raise ValueError("challenge_invalid")
        sources = {s.alias: s for s in self.sources}
        if any(
            (c.source not in sources or c.source_generation != sources[c.source].generation)
            and not (
                c.state == "closed"
                and c.source_snapshot
                and c.source_snapshot.alias == c.source
                and c.source_snapshot.generation == c.source_generation
            )
            for c in self.candidates
        ):
            raise ValueError("storage_error")
        if len({(o.source, o.source_generation, o.event) for o in self.observations}) != len(
            self.observations
        ):
            raise ValueError("replay_conflict")
        credentials = {i.intent_id: i for i in self.credentials}
        challenges = {c.challenge_id: c for c in self.challenges}
        reviews = {r.review_id: r for r in self.reviews}
        observations = {o.observation_id: o for o in self.observations}
        attempts = {a.attempt_id: a for a in self.registrations}
        for attempt in self.registrations:
            if (
                attempt.review_id not in reviews
                or reviews[attempt.review_id].candidate_id != attempt.candidate_id
            ):
                raise ValueError("storage_error")
        for challenge in self.challenges:
            intent = credentials.get(challenge.intent_id)
            if (
                intent is None
                or intent.candidate_id != challenge.candidate_id
                or intent.generation != challenge.generation
            ):
                raise ValueError("storage_error")
        for verification in self.verifications:
            challenge = challenges.get(verification.challenge_id)
            if (
                challenge is None
                or challenge.candidate_id != verification.candidate_id
                or challenge.generation != verification.generation
            ):
                raise ValueError("storage_error")
        for evidence in self.evidence:
            if evidence.case_id != candidates[evidence.candidate_id].case_id:
                raise ValueError("storage_error")
            for key, records in (
                (evidence.observation_id, observations),
                (evidence.attempt_id, attempts | credentials),
            ):
                if key is not None and (
                    key not in records or records[key].candidate_id != evidence.candidate_id
                ):
                    raise ValueError("storage_error")
        if sum(i.unresolved for i in self.credentials) > 16:
            raise ValueError("capacity_exhausted")
        if any(count > 32 for count in Counter(e.candidate_id for e in self.evidence).values()):
            raise ValueError("capacity_exhausted")
        return self
