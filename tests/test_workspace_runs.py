import asyncio
from uuid import uuid4

import httpx
import pytest
from pydantic_ai.models.test import TestModel
from test_workspace_auth import login

from agent.runtime import Runtime
from agent.security import SecurityError
from agent.workspace.runs import RunsManager


async def test_idempotency_ownership_and_capacity(workspace_settings, identity_provider):
    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        runtime = Runtime(workspace_settings, model=TestModel(call_tools=[]))
        manager = RunsManager(runtime, auth, store)
        from agent.workspace.models import TaskSubmission

        value = TaskSubmission(submission_id=uuid4(), task="read", profile="ticket-reader")
        job = await manager.submit(session, value)
        assert (await manager.submit(session, value)) is job
        with pytest.raises(SecurityError, match="submission_conflict"):
            await manager.submit(session, value.model_copy(update={"task": "other"}))
        await manager.worker
        assert job.view.state == "completed"
        foreign = store.authenticate(store.bootstrap(None), session.credentials)
        with pytest.raises(SecurityError, match="run_not_found"):
            manager.get(foreign, job.view.job_id)
        for _ in range(19):
            await manager.submit(
                session, TaskSubmission(submission_id=uuid4(), task="read", profile="ticket-reader")
            )
            await manager.worker
        assert (await manager.submit(session, value)) is job
        with pytest.raises(SecurityError, match="capacity_exceeded"):
            await manager.submit(session, TaskSubmission(submission_id=uuid4(), task="read"))


async def test_global_admission_includes_renewal(workspace_settings, identity_provider):
    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        gate = asyncio.Event()
        original = auth.admit

        async def delayed(s):
            await gate.wait()
            return await original(s)

        auth.admit = delayed
        manager = RunsManager(
            Runtime(workspace_settings, model=TestModel(call_tools=[])), auth, store
        )
        from agent.workspace.models import TaskSubmission

        first = asyncio.create_task(
            manager.submit(session, TaskSubmission(submission_id=uuid4(), task="one"))
        )
        await asyncio.sleep(0)
        with pytest.raises(SecurityError, match="workspace_busy"):
            await manager.submit(session, TaskSubmission(submission_id=uuid4(), task="two"))
        gate.set()
        await first
        await manager.worker


async def test_signout_contains_before_start_and_drains_snapshot(
    workspace_settings, identity_provider
):
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import FunctionModel

    from agent.workspace.models import TaskSubmission

    started = asyncio.Event()
    finish = asyncio.Event()

    async def respond(messages, info):
        started.set()
        try:
            await finish.wait()
        finally:
            finish.set()
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"summary": "done"})])

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        runtime = Runtime(workspace_settings, model=FunctionModel(respond))
        manager = RunsManager(runtime, auth, store)
        job = await manager.submit(session, TaskSubmission(submission_id=uuid4(), task="wait"))
        await started.wait()
        snapshot = job.snapshot
        store.close(session)
        assert session.state == "closing"
        assert snapshot is not None and job.context.run_id in runtime.containment.blocked_runs
        with pytest.raises(SecurityError):
            await manager.submit(session, TaskSubmission(submission_id=uuid4(), task="new"))
        await store.shutdown()
        assert session.state == "closed" and session.credentials is None
        assert job.view.state == "interrupted" and not manager.busy
        assert not runtime.containment.blocked_runs and not runtime.approvals._items


async def test_memory_sink_is_bounded_and_uncertainty_quarantines(
    workspace_settings, identity_provider
):
    from agent.validation.models import LifecycleEvent
    from agent.workspace.models import TaskSubmission
    from agent.workspace.runs import MemorySink

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        manager = RunsManager(
            Runtime(workspace_settings, model=TestModel(call_tools=[])), auth, store
        )
        job = await manager.submit(session, TaskSubmission(submission_id=uuid4(), task="read"))
        await manager.worker
        sink = MemorySink(manager, job)
        event = LifecycleEvent(
            request_id=job.view.request_id,
            run_id=job.view.run_id,
            agent_ref=uuid4(),
            workload_ref=uuid4(),
            phase="run",
            detail="started",
        )
        for _ in range(1100):
            sink.emit(event)
        assert len(job.events) == 1000
        sink.fact("cleanup_unknown")
        assert manager.quarantined and not job.view.retry_available
        with pytest.raises(SecurityError, match="workspace_unavailable"):
            await manager.submit(session, TaskSubmission(submission_id=uuid4(), task="new"))


async def test_model_claim_cannot_establish_database_success(workspace_settings, identity_provider):
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import FunctionModel

    from agent.workspace.models import TaskSubmission

    def respond(messages, info):
        return ModelResponse(
            parts=[
                ToolCallPart(
                    info.output_tools[0].name, {"summary": "Read succeeded and credentials revoked"}
                )
            ]
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        manager = RunsManager(
            Runtime(workspace_settings, model=FunctionModel(respond)), auth, store
        )
        job = await manager.submit(
            session, TaskSubmission(submission_id=uuid4(), task="read", profile="database-reader")
        )
        await manager.worker
        assert job.view.state == "failed"
        assert job.view.cleanup_status == "not_acquired"
        assert job.acquired == job.revoked == 0


async def test_token_snapshot_is_immutable_during_read(workspace_settings, identity_provider):
    from dataclasses import replace

    from pydantic import SecretStr
    from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart
    from pydantic_ai.models.function import FunctionModel

    from agent.validation.models import LifecycleEvent
    from agent.workspace.models import TaskSubmission

    entered = asyncio.Event()
    release = asyncio.Event()
    seen = []

    def respond(messages, info):
        if not any(
            isinstance(part, ToolReturnPart) for message in messages for part in message.parts
        ):
            return ModelResponse(parts=[ToolCallPart("read_database", {"record_id": 1})])
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"summary": "done"})])

    def factory(snapshot, sink):
        async def read(record):
            entered.set()
            await release.wait()
            seen.append(snapshot.access_token)
            job = sink.job
            sink.emit(
                LifecycleEvent(
                    request_id=job.view.request_id,
                    run_id=job.view.run_id,
                    agent_ref=uuid4(),
                    workload_ref=uuid4(),
                    phase="database",
                    detail="completed",
                )
            )
            return [{"id": 1, "status": "healthy"}]

        return read

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        original = session.credentials.access_token
        manager = RunsManager(
            Runtime(workspace_settings, model=FunctionModel(respond)),
            auth,
            store,
            database_reader_factory=factory,
        )
        job = await manager.submit(
            session, TaskSubmission(submission_id=uuid4(), task="read", profile="database-reader")
        )
        await entered.wait()
        session.credentials = replace(
            session.credentials, access_token=SecretStr("replacement-private")
        )
        release.set()
        await manager.worker
        assert seen == [original]
        assert job.view.state == "completed"
        assert "replacement-private" not in job.view.model_dump_json()
