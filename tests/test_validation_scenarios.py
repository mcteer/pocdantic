import pytest

from agent.validation.catalog import load_catalog
from agent.validation.scenarios import offline_scenario


@pytest.mark.parametrize("scenario", load_catalog().suites[0].scenarios)
async def test_offline_effect_boundaries(scenario):
    result = await offline_scenario(scenario.label, cleanup_timeout=1)
    assert result.outcome == "pass"
    assert result.effect_attempts >= 1
    assert result.forbidden_effects == 0
    if scenario.label == "cleanup-failure":
        assert result.cleanup == "failed" and result.operation_outcome == "fail"
    if scenario.label == "cleanup-cancelled":
        assert result.cleanup == "revoked" and result.operation_outcome == "interrupted"


@pytest.mark.parametrize("status", [403, 200])
async def test_actor_only_boundary_denial_or_unexpected_success_cleanup(monkeypatch, status):
    import httpx
    from pydantic import SecretStr

    from agent.oauth import JWTVerifier, OAuthClient
    from agent.schemas import Principal
    from agent.validation.scenarios import actor_only_probe, offline_settings

    class Token:
        access_token = SecretStr("synthetic-token")

    async def actor(self):
        return Token()

    details_seen = []

    async def exchange(self, subject, actor, details, audience):
        details_seen.append(details)
        return Token()

    async def verify(self, token):
        if details_seen:
            return {
                "sub": "synthetic-user",
                "act": {"sub": "synthetic-actor", "iss": "https://synthetic.invalid"},
                "authorization_details": details_seen[-1],
            }
        return {"sub": "synthetic-actor", "iss": "https://synthetic.invalid"}

    monkeypatch.setattr(OAuthClient, "client_credentials", actor)
    monkeypatch.setattr(OAuthClient, "exchange_details", exchange)
    monkeypatch.setattr(JWTVerifier, "verify_claims", verify)
    calls = []

    def handle(request):
        calls.append(request.method)
        if request.method == "GET":
            return httpx.Response(
                status,
                json={
                    "lease_id": "database/creds/read/synthetic",
                    "lease_duration": 60,
                    "data": {"username": "synthetic", "password": "synthetic"},
                },
            )
        return httpx.Response(204)

    s = offline_settings().model_copy(
        update={
            "oauth_token_endpoint": "https://synthetic.invalid/token",
            "oauth_client_id": "synthetic",
            "oauth_client_secret": SecretStr("synthetic"),
            "bearer_token": SecretStr("synthetic-human"),
            "vault_addr": "https://synthetic.invalid",
            "vault_read_path": "database/creds/read",
            "vault_audience": "vault",
        }
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        result = await actor_only_probe(
            s, Principal(issuer="synthetic", subject="synthetic-user"), http=http
        )
    assert result.outcome == ("pass" if status == 403 else "fail")
    assert result.effect_attempts == 1
    assert calls == (["GET"] if status == 403 else ["GET", "PUT"])
    assert result.forbidden_effects == (0 if status == 403 else 1)
    if status == 200:
        assert details_seen[0][0]["allowed_parameters"] == {
            "lease_id": ["database/creds/read/synthetic"]
        }
        assert result.cleanup == "revoked"


async def test_repeated_cancel_cannot_skip_cleanup():
    import asyncio

    import httpx
    from pydantic import SecretStr

    from agent.vault import VaultClient

    acquired, cleanup_started, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    revoked = []

    def handler(request):
        return httpx.Response(
            200,
            json={
                "lease_id": "synthetic",
                "lease_duration": 60,
                "data": {"username": "synthetic", "password": "synthetic"},
            },
        )

    async def revoke(lease_id):
        cleanup_started.set()
        await release.wait()
        revoked.append(lease_id)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:

        async def operation():
            async with VaultClient("https://synthetic.invalid", "", http).credentials(
                SecretStr("synthetic"), "database/creds/read", revoke=revoke, cleanup_timeout=1
            ):
                acquired.set()
                await asyncio.Future()

        task = asyncio.create_task(operation())
        await acquired.wait()
        task.cancel()
        await cleanup_started.wait()
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert revoked == ["synthetic"]
