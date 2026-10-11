"""Private drafts cannot redirect trust or bypass fresh metadata review."""

import pytest
from governance_support import binding, installed, source

from agent.governance.models import GovernanceError


def test_draft_rejects_public_permissions(tmp_path):
    from agent.governance.config import read_private

    s = installed(tmp_path)
    target = s.root / "config.draft.json"
    target.write_text('{"sources":[]}')
    with pytest.raises(GovernanceError):
        read_private(s, "config.draft.json")


def test_readiness_expires_and_binding_changes():
    from datetime import timedelta

    from agent.governance.config import binding_digest, fresh
    from agent.governance.models import Readiness, now

    b = binding()
    ready = Readiness(
        binding_digest=binding_digest(b), metadata_digest="0" * 64, ready=True, reason="ok"
    )
    assert fresh(b, ready)
    assert not fresh(binding(purpose="changed"), ready)
    assert not fresh(b, ready.model_copy(update={"checked_at": now() - timedelta(seconds=301)}))


def test_activation_cannot_overwrite_open_case(tmp_path):
    s = installed(tmp_path)
    s.configure((source(),), 1)
    s.case("fixture")
    with pytest.raises(GovernanceError, match="configuration_changed"):
        s.configure((), s.read().revision)


def test_closed_source_generation_can_change_without_erasing_history(tmp_path):
    """Only closed, credential-free cases retain their previous immutable source snapshot."""
    from agent.governance.models import now

    s = installed(tmp_path)
    first = source()
    s.configure((first,), 1)
    item = s.case("fixture")
    s.change(
        lambda j: j.model_copy(
            update={
                "candidates": (item.model_copy(update={"state": "closed", "closed_at": now()}),)
            }
        )
    )
    updated = first.model_copy(update={"generation": 2, "fixture_digest": "1" * 64})
    s.configure((updated,), s.read().revision)
    assert s.read().sources[0].generation == 2
    assert s.read().candidates[0].source_snapshot == first
