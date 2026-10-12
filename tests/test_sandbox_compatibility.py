"""Real installed-engine probes; no providers, credentials or remote operations."""

import importlib.metadata

import pytest


@pytest.mark.asyncio
async def test_installed_worker_async_callback_and_denied_import():
    """The pinned worker resumes a host call and denies an unexposed remote library."""
    monty = pytest.importorskip("pydantic_monty")
    dist = importlib.metadata.distribution("pydantic-monty-runtime")
    binary = next(dist.locate_file(p).resolve() for p in dist.files if str(p).endswith("/monty"))
    calls = []

    async def query(sql, parameters):
        calls.append((sql, parameters))
        return {"rows": [{"count": 4}]}

    async with monty.AsyncMonty(binary_path=str(binary), max_processes=1) as pool:
        async with pool.checkout() as session:
            value = await session.feed_run(
                '(await query_database("fixture", []))["rows"][0]["count"] * 2',
                external_lookup={"query_database": query},
                print_callback=lambda *_: None,
            )
            assert value == 8 and len(calls) == 1
        async with pool.checkout() as session:
            with pytest.raises(monty.MontyError):
                await session.feed_run("import subprocess\nsubprocess.run(['ssh'])")
    assert len(calls) == 1
