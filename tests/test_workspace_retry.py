from uuid import uuid4

import httpx
import pytest
from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel
from test_workspace_auth import login

from agent.approval import ApprovalOutcome
from agent.runtime import Runtime
from agent.security import SecurityError
from agent.workspace.models import RetrySubmission, TaskSubmission
from agent.workspace.runs import RunsManager


@pytest.mark.parametrize("first", ["approved", "denied", "unconfirmed"])
async def test_retry_no_model_replay_and_fresh_authority(
    workspace_settings, identity_provider, first
):
    models = []
    prompts = []

    def respond(messages, info):
        models.append(True)
        if not any(isinstance(p, ToolReturnPart) for m in messages for p in m.parts):
            return ModelResponse(parts=[ToolCallPart("request_infrastructure_restart", {})])
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"summary": "done"})])

    async def backend(deps, approval, action):
        prompts.append((deps.run_id, approval.id, action.model_dump_json()))
        decision = first if len(prompts) == 1 else "approved"
        if decision in {"approved", "denied"}:
            deps.approvals.record_decision(
                approval.id,
                approved=decision == "approved",
                approver=deps.principal.subject,
                source_event="controlled",
            )
        return ApprovalOutcome(decision)

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        runtime = Runtime(workspace_settings, model=FunctionModel(respond))
        manager = RunsManager(runtime, auth, store, approval_backend=backend)
        original = await manager.submit(
            session, TaskSubmission(submission_id=uuid4(), task="restart")
        )
        await manager.worker
        assert original.view.retry_available == (first == "unconfirmed")
        before = len(models)
        if first != "unconfirmed":
            with pytest.raises(SecurityError, match="retry_unavailable"):
                await manager.retry(
                    session, original.view.job_id, RetrySubmission(submission_id=uuid4())
                )
            assert len(prompts) == 1
            return
        key = RetrySubmission(submission_id=uuid4())
        child = await manager.retry(session, original.view.job_id, key)
        assert (await manager.retry(session, original.view.job_id, key)) is child
        assert (
            await manager.retry(
                session, original.view.job_id, RetrySubmission(submission_id=uuid4())
            )
        ) is child
        await manager.worker
        assert child.view.state == "completed"
        assert len(models) == before and len(prompts) == 2
        assert prompts[0][0] != prompts[1][0] and prompts[0][1] != prompts[1][1]
        assert prompts[0][2] == prompts[1][2]
        assert child.writes == 1 and original.writes == 0
        with pytest.raises(SecurityError):
            runtime.approvals.record_decision(
                prompts[0][1], approved=True, approver="user", source_event="late"
            )


async def test_retry_scope_identity_and_frozen_action(workspace_settings, identity_provider):
    async def backend(deps, approval, action):
        # A backend cannot mutate the action frozen for a later retry.
        action.parameters["change"] = "tampered"
        return ApprovalOutcome("unconfirmed")

    def respond(messages, info):
        return ModelResponse(parts=[ToolCallPart("request_infrastructure_restart", {})])

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        runtime = Runtime(workspace_settings, model=FunctionModel(respond))
        manager = RunsManager(runtime, auth, store, approval_backend=backend)
        original = await manager.submit(
            session, TaskSubmission(submission_id=uuid4(), task="restart")
        )
        await manager.worker
        assert original.view.retry_available
        assert b"tampered" not in original.candidates[0].action
        import time

        session.credentials = session.credentials.with_expiry(time.time() + 1)
        identity_provider.scopes = "tickets:read"
        with pytest.raises(SecurityError, match="policy_denied"):
            await manager.retry(
                session, original.view.job_id, RetrySubmission(submission_id=uuid4())
            )
        assert original.view.retry_available and original.candidates[0].child is None


async def test_alias_capacity_preserves_existing_successor(workspace_settings, identity_provider):
    prompts = []

    async def backend(deps, approval, action):
        prompts.append(approval)
        return ApprovalOutcome("unconfirmed")

    def respond(messages, info):
        return ModelResponse(parts=[ToolCallPart("request_infrastructure_restart", {})])

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        manager = RunsManager(
            Runtime(workspace_settings, model=FunctionModel(respond)),
            auth,
            store,
            approval_backend=backend,
        )
        original = await manager.submit(
            session, TaskSubmission(submission_id=uuid4(), task="restart")
        )
        await manager.worker
        key = RetrySubmission(submission_id=uuid4())
        child = await manager.retry(session, original.view.job_id, key)
        for _ in range(18):
            assert (
                await manager.retry(
                    session, original.view.job_id, RetrySubmission(submission_id=uuid4())
                )
                is child
            )
        with pytest.raises(SecurityError, match="capacity_exceeded"):
            await manager.retry(
                session, original.view.job_id, RetrySubmission(submission_id=uuid4())
            )
        assert await manager.retry(session, original.view.job_id, key) is child
        await manager.worker
        assert len(prompts) == 2


async def test_model_failure_after_write_cannot_retry(workspace_settings, identity_provider):
    calls = []

    async def backend(deps, approval, action):
        deps.approvals.record_decision(
            approval.id, approved=True, approver="user", source_event="native"
        )
        return ApprovalOutcome("approved")

    def respond(messages, info):
        calls.append(True)
        if len(calls) > 1:
            raise RuntimeError("private model failure")
        return ModelResponse(parts=[ToolCallPart("request_infrastructure_restart", {})])

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        manager = RunsManager(
            Runtime(workspace_settings, model=FunctionModel(respond)),
            auth,
            store,
            approval_backend=backend,
        )
        original = await manager.submit(
            session, TaskSubmission(submission_id=uuid4(), task="restart")
        )
        await manager.worker
        assert original.writes == 1 and original.view.state == "failed"
        assert not original.view.retry_available


async def test_binding_failure_never_offers_retry(workspace_settings, identity_provider):
    async def backend(deps, approval, action):
        raise SecurityError("verify_approval_binding")

    def respond(messages, info):
        return ModelResponse(parts=[ToolCallPart("request_infrastructure_restart", {})])

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        manager = RunsManager(
            Runtime(workspace_settings, model=FunctionModel(respond)),
            auth,
            store,
            approval_backend=backend,
        )
        job = await manager.submit(session, TaskSubmission(submission_id=uuid4(), task="restart"))
        await manager.worker
        assert job.view.error.code == "approval_invalid" and not job.view.retry_available
        assert job.writes == 0


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ReadTimeout("private upstream"),
        SecurityError("verify_request_failed"),
        SecurityError("verify_http_503"),
    ],
)
async def test_uncertain_transport_is_not_a_native_denial(
    workspace_settings, identity_provider, failure
):
    async def backend(deps, approval, action):
        raise failure

    def respond(messages, info):
        return ModelResponse(parts=[ToolCallPart("request_infrastructure_restart", {})])

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        manager = RunsManager(
            Runtime(workspace_settings, model=FunctionModel(respond)),
            auth,
            store,
            approval_backend=backend,
        )
        job = await manager.submit(session, TaskSubmission(submission_id=uuid4(), task="restart"))
        await manager.worker
        assert job.view.state == "failed" and job.view.approval_status == "unconfirmed"
        assert job.view.retry_available and job.writes == 0
        assert "upstream" not in job.view.model_dump_json()


async def test_revoked_profile_and_multiple_candidates_are_ineligible(
    workspace_settings, identity_provider
):
    async def backend(deps, approval, action):
        return ApprovalOutcome("unconfirmed")

    def respond(messages, info):
        return ModelResponse(parts=[ToolCallPart("request_infrastructure_restart", {})])

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        runtime = Runtime(workspace_settings, model=FunctionModel(respond))
        manager = RunsManager(runtime, auth, store, approval_backend=backend)
        job = await manager.submit(session, TaskSubmission(submission_id=uuid4(), task="restart"))
        await manager.worker
        runtime.definitions.pop("parent")
        with pytest.raises(SecurityError, match="retry_unavailable"):
            await manager.retry(session, job.view.job_id, RetrySubmission(submission_id=uuid4()))
        assert job.view.retry_available and job.candidates[0].child is None
        job.candidates.append(job.candidates[0])
        with pytest.raises(SecurityError, match="retry_unavailable"):
            await manager.retry(session, job.view.job_id, RetrySubmission(submission_id=uuid4()))
