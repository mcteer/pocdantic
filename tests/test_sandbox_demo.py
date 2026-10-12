"""The showcase distinguishes actual sandbox rejection from model refusal."""

import pytest

from agent.sandbox.demo import demonstration


@pytest.mark.asyncio
async def test_fixed_catalog():
    report = await demonstration()
    assert report["passed"], report
    remote = next(c for c in report["cases"] if c["case_id"] == "remote-ssh")
    assert remote["boundary"] == "sandbox" and remote["query_attempted"] == 0
