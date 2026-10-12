"""Cancellation drains callback-owned cleanup even after the interpreter stops."""

import asyncio

import pytest

from agent.sandbox.runner import SandboxExecution
from agent.security import SecurityError


@pytest.mark.asyncio
async def test_callback_cleanup_is_owned_until_drained():
    started, closed = asyncio.Event(), asyncio.Event()

    async def handler(plan):
        started.set()
        try:
            await asyncio.sleep(30)
        finally:
            await asyncio.sleep(0.05)
            closed.set()

    run = SandboxExecution(handler, lambda: None)
    task = asyncio.create_task(
        run.execute('await query_database("SELECT id FROM poc_records", [])')
    )
    await asyncio.wait_for(started.wait(), 3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert closed.is_set() and run.closed and not run.tasks and not run.completed


@pytest.mark.asyncio
async def test_guard_change_after_read_never_resumes_generated_code():
    """Sign-out/containment during a callback invalidates authority before row resume."""
    revoked = False

    def guard():
        if revoked:
            raise SecurityError("contained")

    async def handler(plan):
        nonlocal revoked
        revoked = True
        return {"rows": [{"count": 4}], "row_count": 1, "truncated": False}

    run = SandboxExecution(handler, guard)
    with pytest.raises(SecurityError, match="contained"):
        await run.execute('r = await query_database("SELECT COUNT(*) FROM poc_records", [])\n42')
    assert run.closed and not run.completed and run.reads == 0 and not run.tasks
