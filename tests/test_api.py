import httpx
import pytest
from pydantic import SecretStr
from pydantic_ai.models.test import TestModel

pytest.importorskip("fastapi")
from agent.api import create_app
from agent.security import SecurityError
from agent.settings import Settings


async def test_invalid_or_missing_auth_rejected_before_runtime(monkeypatch):
    monkeypatch.setattr("agent.api.selected_model", lambda _: TestModel())
    settings = Settings(
        _env_file=None,
        oauth_audience="poc-api",
        oauth_discovery_url="https://id.example/discovery",
        oauth_client_id="client",
        oauth_client_secret=SecretStr("private"),
    )
    app = create_app(settings)
    called = []

    async def reject(self, token):
        raise SecurityError("identity_invalid")

    async def model_must_not_run(*args, **kwargs):
        called.append(True)
        raise AssertionError("model invoked without valid identity")

    monkeypatch.setattr("agent.api.JWTVerifier.verify", reject)
    monkeypatch.setattr("agent.api.Runtime.run", model_must_not_run)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://api.example"
        ) as http,
    ):
        body = {"task": "Retrieve POC-1"}
        assert (await http.post("/runs", json=body)).status_code in {401, 403}
        assert (
            await http.post(
                "/runs", json=body, headers={"Cookie": "agent_workspace_8000=" + "x" * 43}
            )
        ).status_code in {401, 403}
        assert (
            await http.post("/runs", json=body, headers={"Authorization": "Bearer forged"})
        ).status_code == 401
        assert (await http.get("/health")).json() == {"status": "ok"}
    assert not called


async def test_authenticated_api_database_boundary_shares_recovery_gate(
    monkeypatch, recovery_store
):
    from fastapi.responses import JSONResponse

    from agent.schemas import Principal

    monkeypatch.setattr("agent.api.selected_model", lambda _: TestModel())
    config = recovery_store.settings.model_copy(
        update={"oauth_client_secret": SecretStr("synthetic")}
    )
    app = create_app(config, recovery_store=recovery_store)
    with recovery_store.effect() as owner:
        item = recovery_store.begin(owner)
        recovery_store.update(item.incident_id, item.revision, state="unresolved")
    calls = []

    async def verified(self, token):
        return Principal(issuer="https://id.example", subject="user")

    async def boundary(self, request, principal, **kwargs):
        broker = kwargs["database_reader"]
        assert broker.recovery_store is recovery_store
        with pytest.raises(SecurityError, match="acquisition_uncertain"):
            await broker(1)
        calls.append(True)
        return JSONResponse({"contained": True})

    monkeypatch.setattr("agent.api.JWTVerifier.verify", verified)
    monkeypatch.setattr("agent.api.Runtime.run", boundary)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://api.example"
        ) as http,
    ):
        response = await http.post(
            "/runs",
            json={"task": "read", "profile": "database-reader"},
            headers={"Authorization": "Bearer synthetic"},
        )
        assert response.status_code == 200 and response.json() == {"contained": True}
    assert calls == [True] and recovery_store.read().attempts[0].state == "unresolved"
