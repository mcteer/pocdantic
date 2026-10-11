"""Generic ingress verifies signed users without agent or Verify administrative credentials."""

import httpx
import pytest
from pydantic import SecretStr

from agent.oauth import JWTVerifier, OAuthClient
from agent.probe import oauth_config
from agent.security import SecurityError
from tests.portability_support import deployment
from tests.test_workspace_auth import login


@pytest.mark.parametrize(
    "change", [{"iss": "https://other.example"}, {"aud": "other"}, {"exp": 1}, {"sub": "forged"}]
)
async def test_invalid_identity_cannot_issue(tmp_path, monkeypatch, change):
    """Signature claims and human guard binding fail before a Vault request."""
    settings, store, state, factory, http = deployment(tmp_path)
    async with http:
        with pytest.raises(SecurityError):
            await factory(change)(1)
    assert not any(path.startswith("/v1/") for _, path in state["calls"])
    assert not store.read().attempts


async def test_opaque_token_is_not_a_user(tmp_path):
    """Opaque tokens never become inferred subjects or Vault authority."""
    settings, store, state, factory, http = deployment(tmp_path)
    async with http:
        with pytest.raises(SecurityError):
            await JWTVerifier(
                OAuthClient(oauth_config(settings, verification=True), http), "records"
            ).verify(SecretStr("opaque"))
    assert not store.read().attempts


def test_generic_does_not_use_leftover_verify(workspace_settings):
    """Unrelated admin configuration must not choose discovery for a generic issuer."""
    settings = workspace_settings.model_copy(
        update={
            "oauth_discovery_url": None,
            "verify_tenant_url": "https://old.example",
            "oauth_client_id": None,
            "oauth_client_secret": None,
        }
    )
    assert oauth_config(settings, verification=True).discovery_url is None


async def test_browser_login_needs_no_presaved_user_or_agent(workspace_settings, identity_provider):
    """Confidential browser login itself supplies the signed user access token."""
    settings = workspace_settings.model_copy(
        update={
            "database_auth_mode": "user-jwt",
            "oauth_client_id": None,
            "oauth_client_secret": None,
            "bearer_token": None,
        }
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        _, _, session = await login(settings, identity_provider, http)
        assert session.credentials.principal.subject == "user"
        assert not settings.bearer_token


@pytest.mark.parametrize("trusted", [False, True])
async def test_cross_host_keys_require_explicit_trust(workspace_settings, trusted):
    """Advertised URLs cannot extend the configured DNS trust boundary."""
    settings = workspace_settings.model_copy(
        update={"oauth_trusted_hosts": ("keys.example",) if trusted else ()}
    )
    calls = []

    def handler(request):
        calls.append(request.url.host)
        return httpx.Response(
            200,
            json={
                "issuer": settings.oauth_issuer,
                "token_endpoint": "https://id.example/token",
                "jwks_uri": "https://keys.example/keys",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        oauth = OAuthClient(oauth_config(settings, verification=True), http)
        if trusted:
            assert (await oauth.metadata())["jwks_uri"] == "https://keys.example/keys"
        else:
            with pytest.raises(SecurityError):
                await oauth.metadata()
    assert calls == ["id.example"]
