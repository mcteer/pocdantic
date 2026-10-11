"""Workspace governance reads use verified session ownership, with no privileged routes."""

from urllib.parse import parse_qs, urlparse

import httpx
from governance_support import binding, installed, source
from pydantic_ai.models.test import TestModel


async def test_owner_scoped_governance_and_logout(workspace_settings, identity_provider, tmp_path):
    from agent.workspace.app import create_workspace_app

    s = installed(tmp_path)
    s.configure((source(),), 1)
    own = s.case("fixture")
    other = s.case("fixture")
    own = own.model_copy(update={"binding": binding(owner_subject="user", owner="private-team")})
    other = other.model_copy(update={"binding": binding(owner_subject="other-user")})
    s.change(lambda j: j.model_copy(update={"candidates": (own, other)}))
    app = create_workspace_app(
        workspace_settings,
        model=TestModel(call_tools=[]),
        http_transport=httpx.MockTransport(identity_provider.handle),
        governance_store=s,
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as h,
    ):
        assert (await h.get("/api/governance")).status_code == 401
        view = (await h.get("/workspace/session")).json()
        url = (
            await h.post(
                "/auth/login",
                json={"schema_version": 1},
                headers={"Origin": "http://127.0.0.1:8000", "X-CSRF-Token": view["csrf_token"]},
            )
        ).json()["authorization_url"]
        params = parse_qs(urlparse(url).query)
        identity_provider.nonce = params["nonce"][0]
        await h.get("/auth/callback", params={"code": "code", "state": params["state"][0]})
        result = await h.get("/api/governance")
        assert result.status_code == 200
        assert [c["candidate_id"] for c in result.json()["candidates"]] == [str(own.candidate_id)]
        assert "private-team" not in result.text and "entity" not in result.text
        assert (await h.get("/api/governance?owner=other-user")).status_code == 400
        signed = (await h.get("/workspace/session")).json()
        assert (
            await h.post(
                "/api/governance",
                json={"schema_version": 1},
                headers={"Origin": "http://127.0.0.1:8000", "X-CSRF-Token": signed["csrf_token"]},
            )
        ).status_code == 405
        import time

        active = next(iter(app.state.store.sessions.values()))
        active.credentials = active.credentials.with_expiry(time.time() - 1)
        expired = (await h.get("/api/governance")).json()
        assert expired["candidates"] == [] and expired["reason_code"] == "sign_in_required"
        await h.post(
            "/auth/logout",
            json={"schema_version": 1},
            headers={"Origin": "http://127.0.0.1:8000", "X-CSRF-Token": signed["csrf_token"]},
        )
        assert (await h.get("/api/governance")).status_code == 401
