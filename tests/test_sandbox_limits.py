"""Actual interpreter resource failures cannot resume authority or leak session state."""

import asyncio

import pytest

from agent.sandbox.runner import SandboxExecution
from agent.security import SecurityError


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["while True: pass", '"x" * 100000000', 'print("x" * 20000)'])
async def test_limits(code):
    async def handler(plan):
        raise AssertionError("unexpected database dispatch")

    run = SandboxExecution(handler, lambda: None)
    with pytest.raises(SecurityError):
        await run.execute(code)
    assert run.closed and not run.completed and not run.reads


@pytest.mark.asyncio
async def test_new_run_has_no_old_variables():
    async def handler(plan):
        return {"rows": [], "row_count": 0, "truncated": False}

    first = SandboxExecution(handler, lambda: None)
    await first.execute('secret_canary = "private"\n1')
    second = SandboxExecution(handler, lambda: None)
    with pytest.raises(SecurityError):
        await second.execute("secret_canary")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code",
    [
        "def recurse():\n return recurse()\nrecurse()",
        "import time\ntime.sleep(1)",
    ],
)
async def test_recursion_and_sleep_have_no_host_effect(code):
    """Unsupported sleep and bounded recursion fail before any query dispatch."""

    async def handler(plan):
        raise AssertionError("unexpected database dispatch")

    run = SandboxExecution(handler, lambda: None)
    with pytest.raises(SecurityError):
        await run.execute(code)
    assert run.closed and not run.reads and not run.completed


@pytest.mark.asyncio
async def test_worker_slot_stays_owned_until_callback_drains():
    """A second session cannot start while the first owns a live host callback."""
    started = asyncio.Event()

    async def handler(plan):
        started.set()
        await asyncio.sleep(30)

    first = SandboxExecution(handler, lambda: None)
    task = asyncio.create_task(
        first.execute('await query_database("SELECT COUNT(*) FROM poc_records", [])')
    )
    try:
        await asyncio.wait_for(started.wait(), 3)
        second = SandboxExecution(handler, lambda: None)
        with pytest.raises(SecurityError, match="sandbox_busy"):
            await second.execute("42")
        assert not second.exercised
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert first.closed and not first.tasks
