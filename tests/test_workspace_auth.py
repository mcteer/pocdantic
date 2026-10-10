import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from pydantic import SecretStr

from agent.security import SecurityError
from agent.workspace.auth import WorkspaceAuth
from agent.workspace.sessions import SessionStore


async def login(settings, provider, http):
    auth = WorkspaceAuth(settings, http, "http://127.0.0.1:8000")
    store = SessionStore()
    browser = store.bootstrap(None)
    url = await auth.start(browser)
    params = parse_qs(urlparse(url).query)
    provider.nonce = params["nonce"][0]
    credentials = await auth.complete(browser, "code", params["state"][0])
    session = store.authenticate(browser, credentials)
    return auth, store, session


async def test_pkce_single_use_and_separate_authority(workspace_settings, identity_provider):
    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as h:
        auth, store, session = await login(workspace_settings, identity_provider, h)
        assert session.credentials.principal.subject == "user"
        assert workspace_settings.oauth_client_id == "actor"
        with pytest.raises(SecurityError):
            await auth.complete(session, "code", "wrong")
        assert "initial-refresh" not in repr(session)
        assert "login-secret" not in repr(auth)


@pytest.mark.parametrize(
    "change",
    [
        {"nonce": "wrong"},
        {"aud": "other"},
        {"azp": "actor"},
        {"sub": "other"},
        {"at_hash": "wrong"},
    ],
)
async def test_id_validation_cannot_be_replaced(workspace_settings, identity_provider, change):
    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as h:
        auth = WorkspaceAuth(workspace_settings, h, "http://127.0.0.1:8000")
        with pytest.raises(SecurityError):
            await auth.validate_identity(
                SecretStr(identity_provider.identity(**change)),
                SecretStr(identity_provider.access()),
                "test-nonce",
                initial=True,
            )


async def test_refresh_rotation_identity_continuity_and_lifetime(
    workspace_settings, identity_provider
):
    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as h:
        auth, store, session = await login(workspace_settings, identity_provider, h)
        session.credentials = session.credentials.with_expiry(time.time() + 2)
        updated = await auth.admit(session)
        assert updated.refresh_token.get_secret_value() == "rotated-refresh"
        assert identity_provider.calls.count("refresh_token") == 1
        session.credentials = updated.with_expiry(time.time() + 2)
        identity_provider.refresh_subject = "other"
        with pytest.raises(SecurityError, match="sign_in_required"):
            await auth.admit(session)
        assert session.state == "reauth_required"


async def test_too_short_refresh_never_admits(workspace_settings, identity_provider):
    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as h:
        auth, store, session = await login(workspace_settings, identity_provider, h)
        session.credentials = session.credentials.with_expiry(time.time() + 2)
        identity_provider.ttl = 10
        with pytest.raises(SecurityError, match="token_lifetime_short"):
            await auth.admit(session)


async def test_pkce_expiry_refresh_ambiguity_and_scope_narrowing(
    workspace_settings, identity_provider
):
    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as h:
        auth = WorkspaceAuth(workspace_settings, h, "http://127.0.0.1:8000")
        store = SessionStore()
        browser = store.bootstrap(None)
        params = parse_qs(urlparse(await auth.start(browser)).query)
        import base64
        import hashlib

        assert params["code_challenge_method"] == ["S256"]
        assert params["code_challenge"] == [
            base64.urlsafe_b64encode(hashlib.sha256(browser.attempt.verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        ]
        browser.attempt.deadline = 0
        with pytest.raises(SecurityError):
            auth.consume(browser, params["state"][0])
        auth, store, session = await login(workspace_settings, identity_provider, h)
        session.credentials = session.credentials.with_expiry(time.time() + 1)
        identity_provider.scopes = "tickets:read"
        updated = await auth.admit(session)
        assert updated.principal.scopes == frozenset({"tickets:read"})
        session.credentials = updated.with_expiry(time.time() + 1)
        identity_provider.refresh_error = True
        before = identity_provider.calls.count("refresh_token")
        with pytest.raises(SecurityError):
            await auth.admit(session)
        with pytest.raises(SecurityError):
            await auth.admit(session)
        assert identity_provider.calls.count("refresh_token") == before + 1
        assert session.credentials.refresh_token is None


async def test_refresh_omission_retains_token_and_serializes_admission(
    workspace_settings, identity_provider
):
    import asyncio

    original = identity_provider.handle

    def handle(request):
        response = original(request)
        if request.url.path == "/token" and b"grant_type=refresh_token" in request.content:
            value = response.json()
            value.pop("refresh_token", None)
            return httpx.Response(200, json=value)
        return response

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        auth, store, session = await login(workspace_settings, identity_provider, http)
        session.credentials = session.credentials.with_expiry(time.time() + 1)
        first, second = await asyncio.gather(auth.admit(session), auth.admit(session))
        assert first.refresh_token.get_secret_value() == "initial-refresh"
        assert second.refresh_token == first.refresh_token
        assert identity_provider.calls.count("refresh_token") == 1


@pytest.mark.parametrize(
    "endpoint", ["http://id.example/authorize", "https://evil.example/authorize"]
)
async def test_authorization_endpoint_must_be_trusted(
    workspace_settings, identity_provider, endpoint
):
    original = identity_provider.handle

    def handle(request):
        response = original(request)
        if request.url.path == "/discovery":
            return httpx.Response(200, json=response.json() | {"authorization_endpoint": endpoint})
        return response

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        auth = WorkspaceAuth(workspace_settings, http, "http://127.0.0.1:8000")
        with pytest.raises(SecurityError):
            await auth.start(SessionStore().bootstrap(None))
    assert not identity_provider.calls


async def test_access_and_id_tokens_require_distinct_audiences(
    workspace_settings, identity_provider
):
    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth = WorkspaceAuth(workspace_settings, http, "http://127.0.0.1:8000")
        with pytest.raises(SecurityError):
            await auth.validate_identity(
                SecretStr(identity_provider.identity()),
                SecretStr(identity_provider.access(aud="login")),
                "test-nonce",
                initial=True,
            )
        with pytest.raises(SecurityError):
            await auth.validate_identity(
                SecretStr(identity_provider.identity(exp=1)),
                SecretStr(identity_provider.access()),
                "test-nonce",
                initial=True,
            )


def test_token_response_secrets_are_bounded_and_excluded_from_repr():
    from pydantic import ValidationError

    from agent.oauth import TokenResponse

    token = TokenResponse(
        access_token="private-access",
        refresh_token="private-refresh",
        id_token="private-id",
        token_type="Bearer",
    )
    assert not any(
        secret in repr(token) for secret in ("private-access", "private-refresh", "private-id")
    )
    for field in ("access_token", "refresh_token", "id_token"):
        for value in ("", "x" * 65537):
            with pytest.raises(ValidationError):
                TokenResponse.model_validate(
                    {"access_token": "access", "token_type": "Bearer", field: value}
                )


async def test_oversized_token_response_never_parses(workspace_settings, identity_provider):
    original = identity_provider.handle

    def handle(request):
        if request.url.path == "/token":
            return httpx.Response(200, content=b" " * 262145)
        return original(request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        auth = WorkspaceAuth(workspace_settings, http, "http://127.0.0.1:8000")
        browser = SessionStore().bootstrap(None)
        await auth.start(browser)
        with pytest.raises(SecurityError):
            await auth.complete(browser, "code", browser.attempt.state)
        assert browser.attempt is None
