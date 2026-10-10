"""Strict request contracts and credential-free browser projections.

The closed error catalog tells the UI a stage and next action without provider
responses. JobView is mutable only through validated assignments in trusted code.
"""

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator

from agent.recovery.models import REASONS
from agent.response.models import REASONS as RESPONSE_REASONS
from agent.response.models import PublicSummary
from agent.schemas import StrictModel

ERRORS = {
    "sign_in_required": ("identity", "sign_in"),
    "login_cancelled": ("identity", "sign_in"),
    "login_invalid": ("identity", "sign_in"),
    "identity_unavailable": ("identity", "retry_sign_in"),
    "token_lifetime_short": ("identity", "configuration"),
    "configuration_missing": ("configuration", "configuration"),
    "invalid_request": ("request", "edit_task"),
    "request_forbidden": ("request", "reload"),
    "submission_conflict": ("request", "new_submission"),
    "workspace_busy": ("request", "wait"),
    "capacity_exceeded": ("request", "new_session"),
    "run_not_found": ("request", "reload"),
    "workspace_unavailable": ("cleanup", "inspect_cleanup"),
    "profile_unavailable": ("configuration", "configuration"),
    "model_unavailable": ("model", "inspect_configuration"),
    "task_failed": ("runtime", "inspect_result"),
    "policy_denied": ("policy", "check_permissions"),
    "database_unavailable": ("database", "inspect_configuration"),
    "approval_denied": ("approval", "none"),
    "approval_unconfirmed": ("approval", "inspect_result"),
    "approval_invalid": ("approval", "inspect_configuration"),
    "approval_unavailable": ("approval", "inspect_configuration"),
    "retry_unavailable": ("approval", "inspect_result"),
    "cleanup_failed": ("cleanup", "inspect_cleanup"),
    "interrupted": ("runtime", "new_submission"),
}


ERRORS.update(REASONS)
ERRORS.update({reason: ("containment", action) for reason, action in RESPONSE_REASONS.items()})


def now():
    """Return an aware UTC timestamp for public job lifecycle fields."""
    return datetime.now(UTC)


class Versioned(StrictModel):
    schema_version: Literal[1] = 1

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value):
        """Reject coercion or unsupported browser contract versions."""
        if type(value) is not int or value != 1:
            raise ValueError("Schema version must be integer 1")
        return value


class WorkflowError(StrictModel):
    code: str
    stage: str
    next_action: str

    @model_validator(mode="after")
    def closed_mapping(self):
        """Require stage and next action to match the maintained error-code catalog."""
        if (self.stage, self.next_action) != ERRORS[self.code]:
            raise ValueError("Invalid workspace error mapping")
        return self

    @classmethod
    def of(cls, code):
        """Construct the canonical public projection for a supported safe error code."""
        if code not in ERRORS:
            raise ValueError("Unknown workspace error")
        return cls(code=code, stage=ERRORS[code][0], next_action=ERRORS[code][1])

    @field_validator("code")
    @classmethod
    def closed_code(cls, value):
        """Reject arbitrary error text outside the public catalog."""
        if value not in ERRORS:
            raise ValueError("Unknown workspace error")
        return value


class EmptyRequest(Versioned):
    pass


class TaskSubmission(Versioned):
    submission_id: UUID
    task: str = Field(min_length=1, max_length=8000)
    profile: str = Field(default="parent", pattern=r"^[a-z][a-z0-9-]{1,63}$")


class RetrySubmission(Versioned):
    submission_id: UUID


class LoginStart(Versioned):
    authorization_url: str


class SessionView(Versioned):
    signed_in: bool
    requires_sign_in: bool
    csrf_token: str
    profiles: list[str]
    configuration_issues: list[str] = Field(default_factory=list)
    login_error: WorkflowError | None = None


class JobView(Versioned):
    model_config = ConfigDict(frozen=False, validate_assignment=True)
    job_id: UUID
    request_id: UUID
    run_id: UUID | None = None
    parent_job_id: UUID | None = None
    kind: Literal["task", "approval_retry"] = "task"
    state: Literal[
        "accepted",
        "running",
        "waiting_for_approval",
        "cleaning_up",
        "completed",
        "denied",
        "failed",
        "interrupted",
    ] = "accepted"
    created_at: AwareDatetime = Field(default_factory=now)
    started_at: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None
    result: str | None = Field(default=None, max_length=32000)
    truncated: bool = False
    approval_status: Literal["not_requested", "pending", "approved", "denied", "unconfirmed"] = (
        "not_requested"
    )
    action_summary: str | None = None
    cleanup_status: Literal["not_acquired", "pending", "revoked", "failed", "unknown"] = (
        "not_acquired"
    )
    retry_available: bool = False
    containment: tuple[PublicSummary, ...] = ()
    error: WorkflowError | None = None

    @field_validator("created_at", "started_at", "finished_at")
    @classmethod
    def utc(cls, value):
        """Require public job timestamps to be expressed in UTC."""
        if value is not None and value.utcoffset().total_seconds() != 0:
            raise ValueError("UTC time required")
        return value
