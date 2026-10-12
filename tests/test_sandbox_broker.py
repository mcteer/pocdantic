"""Generated plans reuse actual verified JWT and native custody with mocked providers."""

import pytest

from agent.sandbox.models import ReadPlan
from tests.portability_support import deployment


@pytest.mark.asyncio
async def test_admitted_query_cleans_both_credentials(tmp_path, monkeypatch):
    settings, store, state, create, http = deployment(tmp_path)
    seen = []

    async def read(lease, *, plan, **kwargs):
        seen.append(plan)
        return {"rows": [{"count": 4}], "row_count": 1, "truncated": False}

    monkeypatch.setattr("agent.vault.read_admitted_postgres", read)
    async with http:
        value = await create().query(ReadPlan(kind="count"))
    assert value["rows"] == [{"count": 4}] and len(seen) == 1
    assert all(a.state == "resolved" for a in store.read().attempts)
    assert ("PUT", "/v1/sys/leases/revoke") in state["calls"]
    assert ("POST", "/v1/auth/token/revoke-self") in state["calls"]


from tests.test_broker import chain as chain  # noqa: E402


@pytest.mark.asyncio
async def test_delegated_admitted_query_keeps_exact_cleanup(chain, monkeypatch):
    state, create = chain

    async def read(lease, *, plan, **kwargs):
        assert plan.kind == "count"
        return {"rows": [{"count": 4}], "row_count": 1, "truncated": False}

    monkeypatch.setattr("agent.vault.read_admitted_postgres", read)
    value = await create().query(ReadPlan(kind="count"))
    assert value["rows"] == [{"count": 4}] and len(state["exchanges"]) == 2
    cleanup = state["exchanges"][1][0]
    assert cleanup["path"] == "sys/leases/revoke" and cleanup["allowed_parameters"]["sync"] == [
        True
    ]
