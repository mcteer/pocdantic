"""Owner-only source inspection and sign-out purge use existing authenticated boundaries."""

from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import httpx
import pytest
from pydantic_ai.models.test import TestModel

from agent.schemas import RequestEnvelope
from agent.workspace.app import create_workspace_app


@pytest.mark.asyncio
async def test_inspection_owner_no_cache_and_signout(workspace_settings, identity_provider):
    app = create_workspace_app(
        workspace_settings,
        model=TestModel(call_tools=[]),
        http_transport=httpx.MockTransport(identity_provider.handle),
    )
    origin = "http://127.0.0.1:8000"
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=origin) as http,
    ):
        bootstrap = (await http.get("/workspace/session")).json()
        auth = await http.post(
            "/auth/login",
            json={"schema_version": 1},
            headers={"Origin": origin, "X-CSRF-Token": bootstrap["csrf_token"]},
        )
        params = parse_qs(urlparse(auth.json()["authorization_url"]).query)
        identity_provider.nonce = params["nonce"][0]
        await http.get("/auth/callback", params={"code": "code", "state": params["state"][0]})
        signed = (await http.get("/workspace/session")).json()
        session = next(s for s in app.state.store.sessions.values() if s.state == "active")
        job_id = uuid4()
        session.jobs[job_id] = SimpleNamespace(
            request=RequestEnvelope(task="fixture", profile="database-analyst"),
            sandbox_view={"code": "<script>inert</script>", "queries": []},
        )
        reply = await http.get(f"/workspace/runs/{job_id}/sandbox")
        assert reply.status_code == 200 and reply.headers["cache-control"] == "no-store"
        assert reply.json()["code"] == "<script>inert</script>"
        assert (await http.get(f"/workspace/runs/{uuid4()}/sandbox")).status_code == 404
        session.jobs[job_id].sandbox_view = None
        assert (await http.get(f"/workspace/runs/{job_id}/sandbox")).status_code == 410
        session.jobs.clear()
        await http.post(
            "/auth/logout",
            json={"schema_version": 1},
            headers={"Origin": origin, "X-CSRF-Token": signed["csrf_token"]},
        )
        assert (await http.get(f"/workspace/runs/{job_id}/sandbox")).status_code in (400, 401, 403)
