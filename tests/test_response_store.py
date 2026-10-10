"""Control state durability, private paths and explicit enrolled recovery modes."""

import pytest
from response_support import enrolled

from agent.response.models import ResponseError


def test_explicit_enrollment_and_no_reset(tmp_path, workspace_settings):
    store = enrolled(workspace_settings, tmp_path)
    assert store.read().revision == 1
    assert store.initialize() is False
    assert store.anchor().recovery_mode == "not_configured"
    (store.root / "state.json").unlink()
    with pytest.raises(ResponseError):
        store.initialize()


@pytest.mark.parametrize("damage", ["mode", "symlink", "hardlink", "control"])
def test_unsafe_files_fail_closed(tmp_path, workspace_settings, damage):
    import os

    store = enrolled(workspace_settings, tmp_path)
    path = store.root / "state.json"
    if damage == "mode":
        path.chmod(0o644)
    if damage == "hardlink":
        os.link(path, store.root / "copy")
    if damage == "symlink":
        path.rename(store.root / "original")
        path.symlink_to(store.root / "original")
    if damage == "control":
        (store.root / "control.lock").unlink()
    with pytest.raises(ResponseError):
        store.read()


def test_capacity_reserves_completion_space_before_acceptance(
    tmp_path, workspace_settings, monkeypatch
):
    """A full queue rejects intake atomically instead of accepting unfinishable work."""
    from response_support import signal

    import agent.response.store as implementation
    from agent.response.coordinator import Coordinator

    store = enrolled(workspace_settings, tmp_path)
    before = (store.root / "state.json").read_bytes()
    monkeypatch.setattr(implementation, "MAX_BYTES", implementation.RESERVE - 1)
    with pytest.raises(ResponseError, match="response_capacity"):
        Coordinator(store).submit(signal(workspace_settings))
    assert (store.root / "state.json").read_bytes() == before


def test_policy_change_and_missing_configured_recovery_fail_closed(tmp_path, recovery_settings):
    """A configured installation cannot silently become a no-database installation."""
    from agent.recovery.store import RecoveryStore
    from agent.validation.models import canonical

    recovery = RecoveryStore(recovery_settings, project=tmp_path)
    recovery.initialize()
    store = enrolled(recovery_settings, tmp_path, recovery=recovery)
    policy = store.policy()
    (store.root / "policy.json").write_bytes(
        canonical(policy.model_copy(update={"automatic_cleanup": True}))
    )
    with pytest.raises(ResponseError, match="response_policy_changed"):
        store.read()
    (store.root / "policy.json").write_bytes(canonical(policy))
    (recovery.root / "anchor.json").unlink()
    with pytest.raises(ResponseError):
        store.read()


def test_unsettled_scope_pins_recovery_before_actions_exist(tmp_path, recovery_settings):
    """Intake itself pins attributable evidence, before a worker builds cleanup actions."""
    from response_support import signal
    from test_response_coordinator import setup_attempt

    from agent.response.coordinator import Coordinator

    store, recovery, run, attempt = setup_attempt(tmp_path, recovery_settings)
    item, _ = Coordinator(store).submit(signal(recovery_settings, root=run.root_run_id))
    assert len(item.actions) == 1
    assert attempt.incident_id in store.pinned_recovery(recovery.read())


def test_fsync_failure_never_acknowledges_and_latches_failure(
    tmp_path, workspace_settings, monkeypatch
):
    """Failed durability leaves no successful acknowledgement and prevents later effects."""
    import os

    from response_support import signal

    from agent.response.coordinator import Coordinator

    store = enrolled(workspace_settings, tmp_path)

    def failed(fd):
        """Inject a storage failure at a real persistence boundary."""
        raise OSError("synthetic-fsync-failure")

    monkeypatch.setattr(os, "fsync", failed)
    with pytest.raises(ResponseError):
        Coordinator(store).submit(signal(workspace_settings))
    assert store.failed
