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
