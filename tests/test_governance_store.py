"""Durability, unsafe-file and capacity boundaries fail before dispatch."""

import os

import pytest
from governance_support import installed, source


def test_prepare_never_resets(tmp_path):
    from agent.governance.models import GovernanceError

    s = installed(tmp_path)
    before = (s.root / "anchor.json").read_bytes()
    with pytest.raises(GovernanceError):
        s.prepare()
    assert (s.root / "anchor.json").read_bytes() == before


def test_unsafe_replacement(tmp_path):
    from agent.governance.models import GovernanceError

    s = installed(tmp_path)
    os.chmod(s.root / "state.json", 0o644)
    with pytest.raises(GovernanceError):
        s.read()


def test_stale_revision_and_reservation(tmp_path):
    from agent.governance.models import GovernanceError

    s = installed(tmp_path)
    s.configure((source(),), 1)
    with pytest.raises(GovernanceError):
        s.configure((), 1)
    c = s.case("fixture")
    s.max_bytes = len(s.serialized(s.read())) + 100
    with pytest.raises(GovernanceError):
        s.intent(c.candidate_id, "svid")
    assert not s.read().credentials


def test_inode_replacement_rejected(tmp_path):
    from agent.governance.models import GovernanceError

    s = installed(tmp_path)
    s.read()
    target = s.root / "state.json"
    replacement = s.root / "replacement"
    replacement.write_bytes(target.read_bytes())
    replacement.chmod(0o600)
    replacement.replace(target)
    with pytest.raises(GovernanceError):
        s.read()


def test_anchor_environment_cannot_be_rebound(tmp_path):
    from agent.governance.models import GovernanceError
    from agent.governance.store import GovernanceStore

    installed(tmp_path)
    with pytest.raises(GovernanceError, match="configuration_changed"):
        GovernanceStore(project=tmp_path, environment="1" * 64).read()


def test_file_hardlink_is_rejected(tmp_path):
    from agent.governance.models import GovernanceError

    s = installed(tmp_path)
    os.link(s.root / "state.json", tmp_path / "copy")
    with pytest.raises(GovernanceError):
        s.read()


def test_failed_durability_does_not_admit_intent(tmp_path, monkeypatch):
    from agent.governance.models import GovernanceError

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture")
    before = (s.root / "state.json").read_bytes()

    def fail(_fd):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(GovernanceError):
        s.intent(c.candidate_id, "svid")
    assert (s.root / "state.json").read_bytes() == before


def test_prune_retains_unknown_credentials_and_reference_closure(tmp_path):
    from datetime import timedelta

    from agent.governance.models import now

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture")
    s.intent(c.candidate_id, "svid")

    def close(journal):
        return journal.model_copy(
            update={
                "candidates": (
                    c.model_copy(
                        update={"state": "closed", "closed_at": now() - timedelta(days=31)}
                    ),
                )
            }
        )

    s.change(close)
    s.prune()
    assert len(s.read().candidates) == len(s.read().credentials) == 1


def test_valid_commit_is_visible_to_another_process_store(tmp_path):
    from agent.governance.store import GovernanceStore

    s = installed(tmp_path)
    other = GovernanceStore(project=tmp_path, environment="0" * 64)
    other.read()
    s.configure((source(),), 1)
    assert other.read().revision == 2
    other.case("fixture")
    assert len(s.read().candidates) == 1


def test_rollback_is_rejected_after_restart(tmp_path):
    from agent.governance.models import GovernanceError
    from agent.governance.store import GovernanceStore

    s = installed(tmp_path)
    old = (s.root / "state.json").read_bytes()
    s.configure((source(),), 1)
    (s.root / "state.json").write_bytes(old)
    with pytest.raises(GovernanceError, match="storage_error"):
        GovernanceStore(project=tmp_path, environment="0" * 64).read()
