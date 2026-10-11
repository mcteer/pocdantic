"""Local capability checks never issue credentials or infer optional provider support."""

import json
import socket
import time

import pytest
from pydantic import SecretStr

from agent.setup.readiness import check, local_check, required
from tests.portability_support import deployment


def configured(settings):
    """Supply browser-only prerequisites using synthetic values."""
    return settings.model_copy(
        update={
            "model": "test",
            "login_scopes": "openid database:read",
            "login_client_id": "login",
            "login_client_secret": SecretStr("synthetic"),
        }
    )


def test_local_has_no_network_and_optional_features_do_not_block(tmp_path, monkeypatch):
    """Baseline requires neither pre-saved bearer nor agent/admin client credentials."""
    settings, _, _, _, _ = deployment(tmp_path)
    monkeypatch.setattr(socket.socket, "connect", lambda *a: pytest.fail("unexpected network"))
    start = time.monotonic()
    report = local_check(configured(settings), project=tmp_path)
    assert time.monotonic() - start < 2
    assert report.exit_code == 0 and not report.missing_settings
    assert [o.state for o in report.observations[:2]] == ["configured", "configured"]
    assert all(o.state == "unverified" for o in report.observations[2:])
    assert "synthetic" not in report.model_dump_json()


def test_empty_secret_is_missing(tmp_path):
    """An empty generated template cannot pass because SecretStr wrappers are truthy."""
    settings, _, _, _, _ = deployment(tmp_path)
    settings = configured(settings).model_copy(update={"login_client_secret": SecretStr("")})
    assert required(settings) == ("LOGIN_CLIENT_SECRET",)


async def test_public_network_failure_never_uses_credentials(tmp_path, monkeypatch):
    """Public observations carry no bearer, login body or Vault authority."""
    import httpx

    settings, _, _, _, _ = deployment(tmp_path)
    seen = []

    def handle(request):
        seen.append(request)
        assert request.method == "GET" and not request.content
        assert "authorization" not in request.headers and "x-vault-token" not in request.headers
        return httpx.Response(403)

    async def reachable(*args):
        return "observed"

    monkeypatch.setattr("agent.workspace.diagnostics.Diagnostics._tcp", reachable)
    report = await check(
        configured(settings), project=tmp_path, network=True, transport=httpx.MockTransport(handle)
    )
    assert seen and report.exit_code != 0
    assert all(o.state != "supported" for o in report.observations)
    assert "https://" not in json.dumps(report.model_dump(mode="json"))


def test_old_cli_token_does_not_block_fresh_browser_login(tmp_path):
    """A saved CLI credential is not a browser prerequisite or a provider support claim."""
    settings, _, _, _, _ = deployment(tmp_path)
    settings = configured(settings).model_copy(update={"bearer_token": SecretStr("expired-unused")})
    report = local_check(settings, project=tmp_path)
    assert report.observations[0].state == "configured"
    assert all(o.state != "supported" for o in report.observations)


async def test_untrusted_advertised_keys_are_not_contacted(tmp_path, monkeypatch):
    """An advertised foreign host cannot receive even a public discovery follow-up."""
    import httpx

    settings, _, _, _, _ = deployment(tmp_path)
    calls = []

    def handle(request):
        calls.append(request.url.host)
        if request.url.host == "vault.example":
            return httpx.Response(200, json={"sealed": False})
        return httpx.Response(
            200,
            json={
                "issuer": settings.oauth_issuer,
                "token_endpoint": settings.oauth_issuer + "/token",
                "jwks_uri": "https://untrusted.example/keys",
            },
        )

    async def reachable(*args):
        return "observed"

    monkeypatch.setattr("agent.workspace.diagnostics.Diagnostics._tcp", reachable)
    report = await check(
        configured(settings), project=tmp_path, network=True, transport=httpx.MockTransport(handle)
    )
    assert "untrusted.example" not in calls
    assert report.exit_code == 2 and report.observations[0].state == "blocked"


def test_bad_vault_trust_does_not_disable_independent_signin(tmp_path):
    """The report names the bad trust setting without collapsing the usable OIDC route."""
    settings, _, _, _, _ = deployment(tmp_path)
    file = tmp_path / "invalid-ca.pem"
    file.write_text("invalid certificate")
    report = local_check(
        configured(settings).model_copy(update={"vault_ca_file": str(file)}), project=tmp_path
    )
    assert report.observations[0].state == "configured"
    assert report.observations[1].state == "blocked"
    assert "VAULT_CA_FILE" in report.missing_settings
    assert str(file) not in report.model_dump_json()


def test_bad_profile_names_exact_repair_before_effects(tmp_path):
    """Malformed/custom profiles cannot pass baseline execution readiness."""
    settings, _, _, _, _ = deployment(tmp_path)
    file = tmp_path / "bad-profiles.json"
    file.write_text("{}")
    report = local_check(
        configured(settings).model_copy(update={"profiles_file": str(file)}), project=tmp_path
    )
    assert report.exit_code == 2 and "PROFILES_FILE" in report.missing_settings
    assert report.observations[0].state == "configured"
    assert report.observations[1].state == "blocked"
