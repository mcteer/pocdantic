"""Root containment isolates siblings and survives durable-state restart."""

from uuid import uuid4

import pytest
from response_support import enrolled, principal, signal

from agent.response.coordinator import Coordinator
from agent.response.guard import root_scope
from agent.response.models import ResponseError


async def test_root_scope_and_sibling(tmp_path, workspace_settings):
    store = enrolled(workspace_settings, tmp_path)
    async with root_scope(
        store, uuid4(), uuid4(), principal(workspace_settings), lambda _: None
    ) as one:
        async with root_scope(
            store, uuid4(), uuid4(), principal(workspace_settings), lambda _: None
        ) as two:
            Coordinator(store).submit(signal(workspace_settings, root=one.binding.root_run_id))
            with pytest.raises(ResponseError, match="contained"):
                one.check()
            two.check()
    assert all(r.state == "terminal" for r in store.read().runs)


async def test_definition_blocks_new_root(tmp_path, workspace_settings):
    store = enrolled(workspace_settings, tmp_path)
    Coordinator(store).submit(signal(workspace_settings))
    with pytest.raises(ResponseError, match="contained"):
        store.register(uuid4(), uuid4(), principal(workspace_settings))


async def test_watcher_cancels_awaited_execution_under_two_seconds(tmp_path, workspace_settings):
    """An external durable signal interrupts an await without process-local callbacks."""
    import asyncio
    import time

    store = enrolled(workspace_settings, tmp_path)
    ready = asyncio.Event()
    root = uuid4()
    cancelled = []

    async def operation():
        """Stand in for a blocked model/provider await under trusted root ownership."""
        async with root_scope(
            store, uuid4(), root, principal(workspace_settings), cancelled.append
        ):
            ready.set()
            await asyncio.Future()

    task = asyncio.create_task(operation())
    await ready.wait()
    start = time.monotonic()
    Coordinator(store).submit(signal(workspace_settings, root=root))
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    assert time.monotonic() - start < 2 and cancelled == [root]
    assert not store.busy(root)
    with pytest.raises(ResponseError, match="contained"):
        store.register(uuid4(), root, principal(workspace_settings))


@pytest.mark.parametrize("profile", ["parent", "ticket-reader"])
async def test_live_runtime_hold_precedes_model_dispatch(tmp_path, workspace_settings, profile):
    """Every shared runtime ingress checks its durable definition before contacting a model."""
    from pydantic_ai.models.function import FunctionModel

    from agent.runtime import Runtime
    from agent.schemas import RequestEnvelope

    store = enrolled(workspace_settings, tmp_path)
    Coordinator(store).submit(signal(workspace_settings))

    def forbidden(messages, info):
        """Fail if a contained live ingress dispatches a model request."""
        pytest.fail("model dispatched for a held definition")

    runtime = Runtime(workspace_settings, model=FunctionModel(forbidden), response_store=store)
    result = await runtime.run(
        RequestEnvelope(task="Read a ticket", profile=profile), principal(workspace_settings)
    )
    assert result.error_code == "contained"
    assert store.read().runs == ()


async def test_generation_and_storage_changes_reject_existing_guard(tmp_path, workspace_settings):
    """A fresh check never trusts an old process-local registration after state damage."""
    from agent.response.models import RunBinding

    store = enrolled(workspace_settings, tmp_path)
    async with root_scope(
        store, uuid4(), uuid4(), principal(workspace_settings), lambda _: None
    ) as guard:
        forged = RunBinding.model_validate(guard.binding.model_dump() | {"generation": 2})
        with pytest.raises(ResponseError):
            store.check(forged)
        (store.root / "state.json").chmod(0o644)
        with pytest.raises(ResponseError):
            guard.check()
        (store.root / "state.json").chmod(0o600)
