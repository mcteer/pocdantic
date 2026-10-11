"""Maximum report size, effect reservations and complete-reference retention."""

import time
from datetime import timedelta
from uuid import uuid4

import pytest
from governance_support import installed, source

from agent.governance.bootstrap import update_intent
from agent.governance.models import Candidate, GovernanceError, Journal, Observation, now
from agent.governance.report import summary
from agent.governance.store import RESERVE


def test_thousand_cases_ten_thousand_observations_report_under_five_seconds():
    """Reporting scales linearly and exposes only generated labels and aggregate counts."""
    profile = source()
    cases = tuple(
        Candidate(alias=f"case-{i}", source=profile.alias, source_generation=1) for i in range(1000)
    )
    observations = tuple(
        Observation(
            candidate_id=cases[i % 1000].candidate_id,
            source=profile.alias,
            source_generation=1,
            source_digest="0" * 64,
            event=f"event-{i}",
            object="private-object",
            kind="unknown",
            occurred_at=now(),
            selected_digest="0" * 64,
            provenance="synthetic",
        )
        for i in range(10000)
    )
    state = Journal(
        installation_id=uuid4(),
        environment="0" * 64,
        sources=(profile,),
        candidates=cases,
        observations=observations,
    )
    started = time.monotonic()
    result = summary(state)
    assert time.monotonic() - started < 5
    assert len(result["candidates"]) == 1000
    assert all(c["observations"] == 10 for c in result["candidates"])
    assert "private-object" not in str(result)


def test_reservation_rejects_other_work_but_terminal_result_is_writable(tmp_path):
    """A pending intent reserves enough space for its own bounded result before dispatch."""
    store = installed(tmp_path)
    store.configure((source(),), 1)
    item = store.case("fixture")
    store.max_bytes = len(store.serialized(store.read())) + RESERVE + 4096
    intent = store.intent(item.candidate_id, "svid")
    with pytest.raises(GovernanceError, match="capacity_exhausted"):
        store.intent(item.candidate_id, "svid")
    update_intent(store, intent, state="submitted", submitted_at=now())
    update_intent(
        store,
        intent,
        state="confirmed",
        finished_at=now(),
        token_digest="0" * 64,
        expires_at=now() + timedelta(seconds=60),
        safe_after=now() + timedelta(seconds=90),
    )
    assert store.read().credentials[0].state == "confirmed"


def test_expired_bound_is_pruned_with_complete_closed_case(tmp_path):
    """A reviewed finite issuance bound permits retention expiry; unknown bounds do not."""
    store = installed(tmp_path)
    store.configure((source(),), 1)
    item = store.case("fixture")
    intent = store.intent(item.candidate_id, "svid")
    update_intent(
        store,
        intent,
        state="uncertain",
        submitted_at=now() - timedelta(days=40),
        safe_after=now() - timedelta(days=39),
    )
    closed = item.model_copy(update={"state": "closed", "closed_at": now() - timedelta(days=31)})
    store.change(lambda state: state.model_copy(update={"candidates": (closed,)}))
    store.prune()
    assert not store.read().candidates
    assert not store.read().credentials


def test_slow_drip_has_whole_call_deadline(tmp_path, monkeypatch):
    """Periodic chunks must not reset the ten-second total provider bound."""
    import asyncio

    import httpx

    from agent.governance import network

    class Drip(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(10):
                await asyncio.sleep(0.02)
                yield b" "

    monkeypatch.setattr(network, "BUDGET", 0.01)

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=Drip()))
        ) as http:
            with pytest.raises(GovernanceError, match="effect_uncertain"):
                await network.request(http, "GET", "https://vault.example/v1/proof/data/fixture")

    asyncio.run(exercise())
