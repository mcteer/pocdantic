"""Closed SQL admission rejects unsupported syntax before credential dispatch."""

import asyncio
import sys

import pytest

from agent.sandbox.models import QueryRequest
from agent.sandbox.sql import admit, compile_plan
from agent.security import SecurityError


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM poc_records",
        "SELECT * FROM poc_records",
        "SELECT id FROM pg_catalog.pg_tables",
        "SELECT pg_sleep(1) FROM poc_records",
        "SELECT id FROM poc_records; SELECT status FROM poc_records",
        "SELECT id FROM poc_records FOR UPDATE",
        "WITH x AS (SELECT id FROM poc_records) SELECT id FROM x",
        "SELECT id FROM poc_records -- comment",
        "SELECT id AS alias FROM poc_records",
        "SELECT id FROM poc_records WHERE id = 1",
        "SELECT id FROM poc_records LIMIT 101",
        'SELECT "id" FROM poc_records',
        "SELECT status FROM poc_records WHERE status > $1",
    ],
)
async def test_rejected(sql):
    with pytest.raises(SecurityError, match="sandbox_query_denied"):
        await admit(QueryRequest(sql=sql, parameters=["open"] if "$1" in sql else []))


@pytest.mark.asyncio
async def test_parameterized_projection_and_grouping():
    plan = await admit(
        QueryRequest(
            sql="SELECT id, status FROM public.poc_records WHERE id > $1 ORDER BY id LIMIT 10",
            parameters=[2],
        )
    )
    sql, values = compile_plan(plan)
    assert "ONLY public.poc_records" in sql and "id > %s" in sql
    assert values == (2, 11)
    grouped = await admit(
        QueryRequest(sql="SELECT status, COUNT(*) FROM poc_records GROUP BY status")
    )
    assert grouped.kind == "grouped_count" and "pg_catalog.count(*)" in compile_plan(grouped)[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", ["hang", "oversized", "forged"])
async def test_untrusted_worker_is_killed_or_rejected(monkeypatch, payload):
    """Exercise the parent protocol against a real hostile/hung child, not a parser mock."""
    create = asyncio.create_subprocess_exec
    children = []
    source = {
        "hang": "import time; time.sleep(30)",
        "oversized": "print('x' * 20000)",
        "forged": 'print(\'{"kind":"count","executor":"forged"}\')',
    }[payload]

    async def child(*args, **kwargs):
        process = await create(sys.executable, "-I", "-c", source, **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", child)
    with pytest.raises(SecurityError, match="sandbox_query_denied"):
        await asyncio.wait_for(admit(QueryRequest(sql="SELECT COUNT(*) FROM poc_records")), 3)
    assert children and all(p.returncode is not None for p in children)
