import socket
import time

import pytest
from pydantic import SecretStr

from agent.settings import Settings
from agent.validation.readiness import ready


def test_selected_readiness_never_networks_or_creates_runs(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(socket.socket, "connect", lambda *a: pytest.fail("network attempted"))
    start = time.monotonic()
    for suite, names in [
        ("live-database", None),
        ("live-phone", ["phone-approved"]),
        ("live-phone", ["phone-denied"]),
    ]:
        report = ready(
            suite, names, settings=Settings.model_construct(bearer_token=SecretStr("secret-canary"))
        )
        assert not report.execution_ready and not report.external_verified
        assert "canary" not in report.model_dump_json()
        assert any(c.state == "unverified" for c in report.checks)
    assert time.monotonic() - start < 2
    assert not (tmp_path / ".local").exists()


def test_selection_precedes_settings(monkeypatch):
    monkeypatch.setenv("TIMEOUT_SECONDS", "private-canary")
    for suite, names in [
        ("offline-security", None),
        ("live-phone", None),
        ("live-phone", ["phone-approved", "phone-denied"]),
        ("live-database", ["actor-only-denial"] * 2),
    ]:
        with pytest.raises(ValueError, match="invalid_selection"):
            ready(suite, names)


def test_invalid_settings_are_sanitized(monkeypatch):
    monkeypatch.setenv("TIMEOUT_SECONDS", "private-canary")
    report = ready("live-database")
    assert not report.execution_ready
    assert report.exit_code() == 2
    assert "canary" not in report.model_dump_json()


def test_execution_separate_from_evidence():
    s = Settings.model_construct(
        bearer_token=SecretStr("opaque"),
        oauth_client_id="client",
        oauth_client_secret=SecretStr("secret"),
        oauth_audience="api",
        verify_tenant_url="https://synthetic.invalid",
        verify_push_enabled=True,
        verify_api_client_id="api-client",
        verify_api_client_secret=SecretStr("secret"),
        verify_user_id="user",
        verify_authenticator_id="device",
    )
    report = ready("live-phone", ["phone-approved"], settings=s)
    assert report.execution_ready and not report.evidence_ready
    assert report.exit_code() == 2
    assert not report.external_verified
