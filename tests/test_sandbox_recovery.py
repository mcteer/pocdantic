"""Interrupted and uncertain query custody blocks replay independently of Monty."""

import asyncio

import pytest

from agent.sandbox.models import ReadPlan
from agent.security import SecurityError
from tests.portability_support import deployment


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["lease", "token", "cancel"])
async def test_query_failure_preserves_exact_custody(tmp_path, monkeypatch, failure):
    _, store, state, create, http = deployment(tmp_path)

    async def read(*args, **kwargs):
        if failure == "cancel":
            raise asyncio.CancelledError
        return {"rows": [{"count": 4}], "row_count": 1, "truncated": False}

    monkeypatch.setattr("agent.vault.read_admitted_postgres", read)
    if failure == "lease":
        state["revoke_status"] = 500
    if failure == "token":
        state["token_status"] = 500
    async with http:
        with pytest.raises((SecurityError, asyncio.CancelledError)):
            await create().query(ReadPlan(kind="count"))
        if failure == "cancel":
            assert all(a.state == "resolved" for a in store.read().attempts)
        else:
            assert any(a.state != "resolved" for a in store.read().attempts)
            before = len(state["calls"])
            with pytest.raises(SecurityError):
                await create().query(ReadPlan(kind="count"))
            assert len(state["calls"]) == before
    assert ("POST", "/v1/auth/token/revoke-self") in state["calls"]
