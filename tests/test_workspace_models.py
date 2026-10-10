from uuid import uuid4

import pytest
from pydantic import ValidationError

from agent.workspace.models import JobView, TaskSubmission, WorkflowError


def test_request_limits_and_untrusted_fields():
    for change in (
        {"schema_version": 2},
        {"task": ""},
        {"task": "a" * 8001},
        {"subject": "forged"},
        {"profile": "../parent"},
    ):
        with pytest.raises(ValidationError):
            TaskSubmission.model_validate({"submission_id": str(uuid4()), "task": "read"} | change)


def test_closed_error_projection():
    error = WorkflowError.of("approval_unconfirmed")
    assert error.stage == "approval"
    with pytest.raises(ValueError):
        WorkflowError.of("private provider response")
    with pytest.raises(ValidationError):
        JobView.model_validate({"job_id": str(uuid4()), "state": "unknown"})


def test_projection_limits_and_closed_error_tuple():
    from datetime import datetime, timedelta, timezone

    for change in (
        {"result": "x" * 32001},
        {"approval_status": "FAILED"},
        {"cleanup_status": "success"},
        {"created_at": datetime.now(timezone(timedelta(hours=1)))},
    ):
        with pytest.raises(ValidationError):
            JobView(job_id=uuid4(), request_id=uuid4(), **change)
    with pytest.raises(ValidationError):
        WorkflowError(code="approval_denied", stage="model", next_action="retry_sign_in")


@pytest.mark.parametrize("version", [True, 1.0, "1"])
def test_schema_version_is_exact_integer(version):
    with pytest.raises(ValidationError):
        TaskSubmission(schema_version=version, submission_id=uuid4(), task="hi")
