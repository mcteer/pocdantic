"""Guidance observes durable state without repairing, replaying or approving it."""

import socket

import pytest
from pydantic import SecretStr

from agent.settings import synthetic_settings
from agent.setup.guidance import guide, observe, render
from tests.portability_support import deployment


def test_offline_never_reads_private_state(tmp_path, monkeypatch):
    """Offline guidance works with arbitrary broken private files and no network."""
    monkeypatch.setattr(socket.socket, "connect", lambda *a: pytest.fail("network"))
    (tmp_path / ".env.local").write_text("broken")
    result = guide(None, recipe="offline", project=tmp_path)
    assert result.state == "offline-ready" and result.exit_code == 0
    assert len(render(result)) < 32768


def test_absent_is_different_from_partial(tmp_path):
    """Partial journals never produce enrollment/init shortcuts."""
    settings = synthetic_settings()
    assert observe(settings, project=tmp_path).recovery_state == "absent"
    root = tmp_path / ".local/recovery"
    root.mkdir(parents=True)
    (root / "state.json").write_text("{}")
    assert observe(settings, project=tmp_path).recovery_state == "invalid"


def test_repeat_clear_keeps_bytes(tmp_path, monkeypatch):
    """Three clear-state observations retain every private byte and offer launch."""
    settings, _, _, _, _ = deployment(tmp_path)
    settings = settings.model_copy(
        update={
            "model": "openai:synthetic",
            "openai_api_key": SecretStr("synthetic"),
            "login_client_id": "synthetic",
            "login_client_secret": SecretStr("synthetic"),
            "login_scopes": "openid database:read",
        }
    )
    monkeypatch.setattr(socket.socket, "connect", lambda *a: pytest.fail("network"))
    before = {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    for _ in range(3):
        result = guide(settings, project=tmp_path)
        assert result.state == "ready-to-launch"
        assert "init-recovery" not in {a.id for a in result.actions}
        assert "enroll-response" not in {a.id for a in result.actions}
    assert before == {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


def test_draft_needs_human_review(tmp_path):
    """A valid prepared policy is not a review receipt or response enrollment."""
    from agent.recovery.store import RecoveryStore
    from agent.response.store import ResponseStore

    settings = synthetic_settings().model_copy(
        update={
            "database_auth_mode": "user-jwt",
            "database_host": "db.example",
            "database_name": "records",
            "vault_addr": "https://vault.example",
            "oauth_audience": "records",
            "vault_jwt_auth_role": "human",
        }
    )
    recovery = RecoveryStore(settings, project=tmp_path)
    recovery.initialize()
    response = ResponseStore(settings, project=tmp_path, recovery=recovery)
    response.prepare()
    assert observe(settings, project=tmp_path).response_state == "draft"


@pytest.mark.parametrize("damage", ["symlink", "partial", "mismatch"])
def test_damage_never_suggests_initialization(tmp_path, damage):
    """Corruption or changed contexts cannot be repaired by re-enrollment suggestions."""
    settings, _, _, _, _ = deployment(tmp_path)
    settings = settings.model_copy(
        update={
            "model": "openai:synthetic",
            "openai_api_key": SecretStr("synthetic"),
            "login_client_id": "synthetic",
            "login_client_secret": SecretStr("synthetic"),
            "login_scopes": "openid database:read",
        }
    )
    if damage == "partial":
        (tmp_path / ".local/response/anchor.json").unlink()
    elif damage == "symlink":
        path = tmp_path / ".local/response/policy.json"
        content = path.read_bytes()
        path.unlink()
        target = tmp_path / "policy-target"
        target.write_bytes(content)
        path.symlink_to(target)
    else:
        settings = settings.model_copy(update={"database_host": "changed.example"})
    result = guide(settings, project=tmp_path)
    assert result.state == "blocked" and result.exit_code == 3
    assert not {"init-recovery", "prepare-policy", "enroll-response", "launch-workspace"} & {
        a.id for a in result.actions
    }


def test_live_workspace_owner_is_busy(tmp_path):
    """An active owner is an inspection handoff even with a clear durable journal."""
    from agent.recovery.store import RecoveryStore

    settings, _, _, _, _ = deployment(tmp_path)
    recovery = RecoveryStore(settings, project=tmp_path)
    with recovery.workspace():
        assert observe(settings, project=tmp_path).recovery_state == "busy"


def test_input_failure_has_no_enrollment_actions(tmp_path):
    """Missing configuration precedes enrollment and retains a names-only report."""
    result = guide(synthetic_settings(), project=tmp_path)
    assert result.exit_code == 2
    assert {a.id for a in result.actions} <= {"edit-settings", "install-extras", "check-local"}
    assert "google-gla" not in render(result, format="json")


def test_held_response_and_stale_observation(tmp_path):
    """A previously clear suggestion grants no authority after a new durable hold."""
    from agent.response.coordinator import Coordinator
    from agent.response.store import ResponseStore
    from tests.response_support import signal

    settings, _, _, _, _ = deployment(tmp_path)
    settings = settings.model_copy(
        update={
            "model": "openai:synthetic",
            "openai_api_key": SecretStr("synthetic"),
            "login_client_id": "synthetic",
            "login_client_secret": SecretStr("synthetic"),
            "login_scopes": "openid database:read",
        }
    )
    assert guide(settings, project=tmp_path).state == "ready-to-launch"
    store = ResponseStore(settings, project=tmp_path)
    Coordinator(store).submit(signal(settings))
    assert observe(settings, project=tmp_path).response_state == "held"
    result = guide(settings, project=tmp_path)
    assert result.state == "blocked" and result.exit_code == 3
    assert "launch-workspace" not in {a.id for a in result.actions}


def test_time_budget_cannot_promote_readiness(tmp_path, monkeypatch):
    """Exhausted local observation budgets return a closed failure, never launch."""
    from agent.setup import guidance

    original = guidance.observe

    def exhausted(settings, **kwargs):
        """Advance the clock after a bounded real observation without sleeping."""
        result = original(settings, **kwargs)
        monkeypatch.setattr(guidance.time, "monotonic", lambda: started + 3)
        return result

    started = guidance.time.monotonic()
    monkeypatch.setattr(guidance, "observe", exhausted)
    result = guide(synthetic_settings(), project=tmp_path)
    assert result.exit_code == 2 and result.state == "blocked"
    assert result.findings[0].id == "budget-exhausted"
    assert not result.actions
