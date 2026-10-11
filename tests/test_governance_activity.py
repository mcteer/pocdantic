"""Chronology requires captured receipt and bounded clocks, not a backdated timestamp."""

from datetime import timedelta
from types import SimpleNamespace

import pytest

from agent.governance.models import now


def test_late_receipt_cannot_fabricate_discovery():
    from agent.governance.evidence import before_registration

    t = now()
    good = SimpleNamespace(
        observed_at=t - timedelta(seconds=20),
        received_at=t - timedelta(seconds=10),
        clock_bound=1,
        provenance="native",
        independent=True,
        attributed=True,
    )
    assert before_registration(good, t, 1)
    late = SimpleNamespace(**(vars(good) | {"received_at": t + timedelta(seconds=1)}))
    assert not before_registration(late, t, 1)
    for changes in (
        {"clock_bound": None},
        {"provenance": "synthetic"},
        {"independent": False},
        {"observed_at": t},
    ):
        assert not before_registration(SimpleNamespace(**(vars(good) | changes)), t, 1)


@pytest.mark.parametrize("control_status, expected", [(403, "inconclusive"), (200, "pass")])
def test_control_gates_registration_denial(tmp_path, monkeypatch, control_status, expected):
    """A provider outage cannot masquerade as Agent Registry enforcement."""
    import asyncio

    from governance_support import binding, installed, source
    from pydantic import SecretStr

    from agent.governance import activity

    store = installed(tmp_path)
    store.configure((source(),), 1)
    candidate = store.case("fixture")
    b = binding()
    candidate = candidate.model_copy(update={"binding": b})
    store.change(lambda j: j.model_copy(update={"candidates": (candidate,)}))

    class Registry:
        async def metadata(self, _binding):
            return {"policy": "same"}

        async def absence(self, _binding):
            return {"digest": "0" * 64}

    async def acquire(*args):
        return SecretStr("not-a-live-token")

    decisions = iter((control_status, 403))

    async def read(*args):
        return {"status": next(decisions), "digest": "0" * 64}

    monkeypatch.setattr(activity, "acquire", acquire)
    monkeypatch.setattr(activity, "read", read)
    result = asyncio.run(
        activity.observe(
            store,
            candidate,
            b,
            registry=Registry(),
            oauth=None,
            verifier=None,
            healthy_oauth=None,
            healthy_verifier=None,
            healthy_binding=b.model_copy(update={"actor_subject": "control"}),
            audience="test",
            http=None,
            check=lambda: None,
        )
    )
    assert result["outcome"] == expected
    assert result["attributed"] is (expected == "pass")
    assert not store.read().observations
