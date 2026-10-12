"""Actual Monty computation receives rows, never trusted connection authority."""

import pytest

from agent.sandbox.runner import SandboxExecution
from agent.security import SecurityError


@pytest.mark.asyncio
async def test_compute_and_host_access_denial():
    async def handler(plan):
        return {
            "rows": [{"status": "open", "count": 2}, {"status": "closed", "count": 2}],
            "row_count": 2,
            "truncated": False,
        }

    run = SandboxExecution(handler, lambda: None)
    result = await run.execute(
        'r = await query_database("SELECT status, COUNT(*) FROM poc_record'
        's GROUP BY status", [])\ntotal = sum(x["count"] for x in r["rows"]'
        ')\n{x["status"]: 100*x["count"]/total for x in r["rows"]}'
    )
    assert result == {"open": 50.0, "closed": 50.0} and run.completed and run.reads == 1
    bad = SandboxExecution(handler, lambda: None)
    with pytest.raises(SecurityError, match="sandbox_execution_failed"):
        await bad.execute("import subprocess\nsubprocess.run(['ssh'])")
    assert bad.reads == 0


@pytest.mark.asyncio
async def test_caught_policy_denial_latches_authority():
    calls = []

    async def handler(plan):
        calls.append(plan)
        return {"rows": [], "row_count": 0, "truncated": False}

    run = SandboxExecution(handler, lambda: None)
    with pytest.raises(SecurityError):
        await run.execute(
            'try:\n await query_database("DELETE FROM poc_records", [])\nexcept '
            'Exception:\n pass\nawait query_database("SELECT id FROM poc_records'
            '", [])'
        )
    assert calls == [] and not run.completed


@pytest.mark.asyncio
async def test_caught_forged_callback_arguments_close_admission():
    calls = []

    async def handler(plan):
        calls.append(plan)
        return {"rows": [], "row_count": 0, "truncated": False}

    run = SandboxExecution(handler, lambda: None)
    code = (
        'try:\n await query_database("SELECT id FROM poc_records", [], token="forged")\n'
        'except Exception:\n pass\nawait query_database("SELECT id FROM poc_records", [])'
    )
    with pytest.raises(SecurityError):
        await run.execute(code)
    assert not calls and run.failure == "sandbox_query_denied"


@pytest.mark.asyncio
async def test_standard_mixed_keyword_call_is_supported():
    async def handler(plan):
        return {"rows": [{"count": 4}], "row_count": 1, "truncated": False}

    run = SandboxExecution(handler, lambda: None)
    value = await run.execute(
        'r = await query_database("SELECT COUNT(*) FROM poc_records", parameters=[])\n'
        'r["rows"][0]["count"]'
    )
    assert value == 4 and run.completed
