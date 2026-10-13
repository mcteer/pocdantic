"""Setup can be repeated without provider effects, private-file replacement or leakage."""

import os

import pytest

from agent.security import SecurityError
from agent.setup.commands import initialize


def test_template_is_private_and_repeat_preserves_original(tmp_path):
    """Existing credentials and inode survive repeated setup."""
    assert initialize("user-jwt", project=tmp_path)["status"] == "created"
    file = tmp_path / ".env.local"
    assert file.stat().st_mode & 0o777 == 0o600
    original, inode = file.read_bytes(), file.stat().st_ino
    assert initialize("delegated-exchange", project=tmp_path)["status"] == "unchanged"
    assert file.read_bytes() == original and file.stat().st_ino == inode
    assert "OAUTH_CLIENT_SECRET=" not in file.read_text()
    assert "GOOGLE_API_KEY=" in file.read_text()


def test_symlink_is_not_followed_or_overwritten(tmp_path):
    """Setup must not change a linked configuration target."""
    target = tmp_path / "private"
    target.write_text("preserve")
    os.symlink(target, tmp_path / ".env.local")
    assert initialize("user-jwt", project=tmp_path)["status"] == "unchanged"
    assert target.read_text() == "preserve"


def test_unknown_mode_creates_nothing(tmp_path):
    """Invalid selection fails before local effects."""
    with pytest.raises(SecurityError):
        initialize("unknown", project=tmp_path)
    assert not list(tmp_path.iterdir())


def test_empty_generated_template_reports_exact_missing_settings(tmp_path, monkeypatch):
    """Fresh setup check guides input collection instead of failing on empty role syntax."""
    from agent.settings import Settings
    from agent.setup.readiness import local_check

    initialize("user-jwt", project=tmp_path)
    # Explicit field values remove ambient environment authority from this file-reading test.
    settings = Settings(
        _env_file=tmp_path / ".env.local",
        oauth_issuer="",
        oauth_audience="",
        oauth_discovery_url="",
        login_client_id="",
        login_client_secret="",
        vault_addr="",
        vault_jwt_auth_role="",
        database_host="",
        database_name="",
        google_api_key="",
    )
    report = local_check(settings, project=tmp_path)
    assert report.exit_code == 2
    assert "VAULT_JWT_AUTH_ROLE" in report.missing_settings
    assert "LOGIN_CLIENT_SECRET" in report.missing_settings
    assert "BEARER_TOKEN" not in report.missing_settings
    assert not (tmp_path / ".local").exists()


async def test_offline_network_rejected_without_settings(monkeypatch, capsys):
    """A forbidden offline network flag cannot load configuration or issue a request."""
    from argparse import Namespace

    from agent.settings import Settings
    from agent.setup.commands import execute_setup

    def denied(*args, **kwargs):
        """Any settings construction would violate the offline entry-point boundary."""
        pytest.fail("live settings loaded")

    monkeypatch.setattr(Settings, "__init__", denied)
    assert (
        await execute_setup(Namespace(setup_command="check", recipe="offline", network=True)) == 2
    )
    assert "configuration_invalid" in capsys.readouterr().out


async def test_invalid_guide_has_closed_v1_shape(tmp_path, monkeypatch, capsys):
    """Invalid private input still yields a guide schema without raw validation values."""
    import json
    from argparse import Namespace

    from agent.setup.commands import execute_setup
    from agent.setup.models import SetupGuide

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env.local").write_text("TIMEOUT_SECONDS=synthetic-private-canary\n")
    assert (
        await execute_setup(
            Namespace(setup_command="guide", recipe="workspace-read", format="json")
        )
        == 2
    )
    output = capsys.readouterr().out
    assert "synthetic-private-canary" not in output
    assert SetupGuide.model_validate(json.loads(output)).state == "needs-input"
