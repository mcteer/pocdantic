"""Exact enrollment and containment use actual anchored stores with fake providers."""

import asyncio

import pytest
from governance_support import FakeRegistry, anchors, binding, source
from response_support import signal

from agent.governance.config import readiness
from agent.governance.coordinator import Coordinator
from agent.governance.enrollment import enroll, review
from agent.governance.models import GovernanceError
from agent.response.coordinator import Coordinator as ResponseCoordinator


@pytest.mark.parametrize("hold_after_dispatch", [False, True])
def test_one_create_is_confirmed_or_retained_uncertain(tmp_path, hold_after_dispatch):
    """A hold arriving after acknowledgement stops readback promotion without replay."""
    settings, store, response, recovery = anchors(tmp_path)
    store.configure((source(),), 1)
    item = store.case("fixture")
    b = binding()
    adapter = FakeRegistry()
    snapshot = asyncio.run(readiness(b, adapter))
    item = item.model_copy(update={"binding": b, "readiness": snapshot, "state": "observed"})
    store.change(lambda j: j.model_copy(update={"candidates": (item,)}))
    decision = review(
        store, item.candidate_id, store.read().revision, "reviewer", qualifies=lambda *_: True
    )
    original = adapter.create

    async def dispatch(binding):
        """Model a real acknowledged provider write before a concurrent local hold."""
        result = await original(binding)
        if hold_after_dispatch:
            ResponseCoordinator(response).submit(signal(settings))
        return result

    adapter.create = dispatch
    coordinator = Coordinator(store, response, recovery)
    with coordinator.ownership():
        if hold_after_dispatch:
            with pytest.raises(GovernanceError, match="creation_uncertain"):
                asyncio.run(
                    enroll(
                        store, decision.review_id, store.read().revision, adapter, coordinator.check
                    )
                )
        else:
            asyncio.run(
                enroll(store, decision.review_id, store.read().revision, adapter, coordinator.check)
            )
    current = store.read()
    assert adapter.posts == 1
    assert current.registrations[0].registration_id == "fixture-registration"
    assert current.reviews[0].consumed
    assert current.candidates[0].state == ("blocked" if hold_after_dispatch else "registered")
    with pytest.raises(GovernanceError, match="review_stale"):
        asyncio.run(enroll(store, decision.review_id, current.revision, adapter, lambda: None))
    assert adapter.posts == 1
