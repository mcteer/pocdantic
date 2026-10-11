"""A submitted create is never replayed after loss of its result or matching readback."""

import asyncio

import pytest
from governance_support import binding, installed, source

from agent.governance.models import GovernanceError, Readiness


def prepared(tmp_path):
    from agent.governance.config import binding_digest
    from agent.governance.enrollment import review

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture")
    b = binding()
    ready = Readiness(
        binding_digest=binding_digest(b), metadata_digest="0" * 64, ready=True, reason="ok"
    )
    c = c.model_copy(update={"state": "observed", "binding": b, "readiness": ready})
    s.change(lambda j: j.model_copy(update={"candidates": (c,)}))
    r = review(s, c.candidate_id, s.read().revision, "operator", qualifies=lambda *_: True)
    return s, r


def test_lost_create_result_stays_uncertain_and_consumes_review(tmp_path):
    from agent.governance.enrollment import enroll

    s, r = prepared(tmp_path)

    class Adapter:
        posts = 0

        async def metadata(self, b):
            return {}

        async def absence(self, b):
            return {}

        async def create(self, b):
            self.posts += 1
            raise TimeoutError("upstream private")

    adapter = Adapter()

    async def run():
        with pytest.raises(GovernanceError):
            await enroll(
                s,
                r.review_id,
                s.read().revision,
                adapter,
                lambda: None,
                metadata_check=lambda *_: True,
            )
        with pytest.raises(GovernanceError):
            await enroll(
                s,
                r.review_id,
                s.read().revision,
                adapter,
                lambda: None,
                metadata_check=lambda *_: True,
            )

    asyncio.run(run())
    assert adapter.posts == 1
    assert s.read().registrations[0].state == "uncertain"
    assert s.read().reviews[0].consumed


def test_restart_never_reissues_submitted_registration(tmp_path):
    """Abandoned submission is normalized as uncertainty; its consumed review survives."""
    from agent.governance.enrollment import enroll
    from agent.governance.store import GovernanceStore

    s, r = prepared(tmp_path)

    class Adapter:
        async def metadata(self, _b):
            return {}

        async def absence(self, _b):
            return {}

        async def create(self, _b):
            raise TimeoutError()

    with pytest.raises(GovernanceError):
        asyncio.run(
            enroll(
                s,
                r.review_id,
                s.read().revision,
                Adapter(),
                lambda: None,
                metadata_check=lambda *_: True,
            )
        )
    restarted = GovernanceStore(project=tmp_path, environment=s.environment)
    with restarted.lock("effect.lock"):
        restarted.recover_submissions()
    assert restarted.read().registrations[0].state == "uncertain"
    assert restarted.read().reviews[0].consumed
    with pytest.raises(GovernanceError, match="review_stale"):
        asyncio.run(
            enroll(restarted, r.review_id, restarted.read().revision, Adapter(), lambda: None)
        )


def test_post_submit_persistence_loss_cannot_replay_create(tmp_path, monkeypatch):
    """An acknowledged POST remains submitted/uncertain if its next local commit fails."""
    from governance_support import FakeRegistry

    from agent.governance.enrollment import enroll
    from agent.governance.store import GovernanceStore

    store, decision = prepared(tmp_path)
    adapter = FakeRegistry()
    original = store.change

    def fail_ack(operation, **kwargs):
        if operation.__name__ == "update" and adapter.posts:
            raise GovernanceError("storage_error")
        return original(operation, **kwargs)

    monkeypatch.setattr(store, "change", fail_ack)
    with pytest.raises(GovernanceError):
        asyncio.run(
            enroll(
                store,
                decision.review_id,
                store.read().revision,
                adapter,
                lambda: None,
                metadata_check=lambda *_: True,
            )
        )
    assert adapter.posts == 1
    restarted = GovernanceStore(project=tmp_path, environment=store.environment)
    with restarted.lock("effect.lock"):
        restarted.recover_submissions()
    assert restarted.read().registrations[0].state == "uncertain"
    with pytest.raises(GovernanceError, match="review_stale"):
        asyncio.run(
            enroll(restarted, decision.review_id, restarted.read().revision, adapter, lambda: None)
        )
    assert adapter.posts == 1
