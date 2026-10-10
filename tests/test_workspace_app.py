import httpx
import pytest
from pydantic_ai.models.test import TestModel

from agent.security import SecurityError
from agent.settings import Settings
from agent.workspace.app import create_workspace_app


def test_missing_configuration_is_local_and_actionable():
    with pytest.raises(SecurityError, match="configuration_missing"):
        create_workspace_app(Settings(_env_file=None), model=TestModel())


async def test_bootstrap_login_callback_and_cookie_csrf(workspace_settings, identity_provider):
    app = create_workspace_app(
        workspace_settings,
        model=TestModel(),
        http_transport=httpx.MockTransport(identity_provider.handle),
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as h,
    ):
        view = (await h.get("/workspace/session")).json()
        assert not view["signed_in"]
        assert (
            await h.post(
                "/auth/login",
                json={"schema_version": 1},
                headers={"Origin": "http://127.0.0.1:8000"},
            )
        ).status_code == 400
        r = await h.post(
            "/auth/login",
            json={"schema_version": 1},
            headers={"Origin": "http://127.0.0.1:8000", "X-CSRF-Token": view["csrf_token"]},
        )
        from urllib.parse import parse_qs, urlparse

        p = parse_qs(urlparse(r.json()["authorization_url"]).query)
        identity_provider.nonce = p["nonce"][0]
        assert (
            await h.get("/auth/callback", params={"code": "code", "state": p["state"][0]})
        ).status_code == 303
        signed = (await h.get("/workspace/session")).json()
        assert signed["signed_in"] and signed["csrf_token"] != view["csrf_token"]
        assert not any(x in str(signed) for x in ("login-secret", "access_token", "refresh_token"))
        assert (await h.get("/auth/callback?code=a&code=b&state=x")).status_code == 400
        assert (
            await h.post(
                "/auth/logout",
                json={"schema_version": 1},
                headers={"Origin": "http://127.0.0.1:8000", "X-CSRF-Token": signed["csrf_token"]},
            )
        ).status_code == 204


@pytest.mark.parametrize("port", [0, 1023, 65536, True])
def test_workspace_rejects_invalid_port_before_network(workspace_settings, port):
    with pytest.raises(SecurityError, match="invalid_request"):
        create_workspace_app(workspace_settings, port=port, model=TestModel())


def test_workspace_cli_has_only_local_port_option():
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-c", "from agent.cli import main; main()", "workspace", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--port" in result.stdout
    assert "--host" not in result.stdout


async def test_job_http_ownership_and_server_profile(workspace_settings, identity_provider):
    from urllib.parse import parse_qs, urlparse
    from uuid import uuid4

    app = create_workspace_app(
        workspace_settings,
        model=TestModel(call_tools=[]),
        http_transport=httpx.MockTransport(identity_provider.handle),
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as h,
    ):
        view = (await h.get("/workspace/session")).json()
        headers = {"Origin": "http://127.0.0.1:8000", "X-CSRF-Token": view["csrf_token"]}
        url = (await h.post("/auth/login", json={"schema_version": 1}, headers=headers)).json()[
            "authorization_url"
        ]
        p = parse_qs(urlparse(url).query)
        identity_provider.nonce = p["nonce"][0]
        await h.get("/auth/callback", params={"code": "code", "state": p["state"][0]})
        headers["X-CSRF-Token"] = (await h.get("/workspace/session")).json()["csrf_token"]
        body = {
            "schema_version": 1,
            "submission_id": str(uuid4()),
            "task": "hi",
            "profile": "ticket-reader",
        }
        result = await h.post("/workspace/runs", json=body, headers=headers)
        assert result.status_code == 202
        job = result.json()
        assert (await h.post("/workspace/runs", json=body, headers=headers)).json()[
            "job_id"
        ] == job["job_id"]
        await app.state.manager.worker
        assert (await h.get("/workspace/runs/" + job["job_id"])).json()["state"] == "completed"
        assert len((await h.get("/workspace/runs")).json()["jobs"]) == 1
        body["submission_id"] = str(uuid4())
        body["profile"] = "unknown"
        assert (await h.post("/workspace/runs", json=body, headers=headers)).json()["error"][
            "code"
        ] == "profile_unavailable"
        assert (await h.get("/workspace/runs/" + str(uuid4()))).status_code == 404


async def test_invalid_callback_inputs_never_exchange(workspace_settings, identity_provider):
    app = create_workspace_app(
        workspace_settings,
        model=TestModel(call_tools=[]),
        http_transport=httpx.MockTransport(identity_provider.handle),
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as http,
    ):
        view = (await http.get("/workspace/session")).json()
        for query in (
            "code=a&code=b&state=x",
            "code=a&error=e&state=x",
            "code=a&state=x&state=y",
            "code=a&state=" + "x" * 8193,
        ):
            assert (await http.get("/auth/callback?" + query)).status_code == 400
        assert not identity_provider.calls
        headers = {"Origin": "http://127.0.0.1:8000", "X-CSRF-Token": view["csrf_token"]}
        from urllib.parse import parse_qs, urlparse

        started = (
            await http.post("/auth/login", json={"schema_version": 1}, headers=headers)
        ).json()
        state = parse_qs(urlparse(started["authorization_url"]).query)["state"][0]
        assert (
            await http.get("/auth/callback", params={"code": "a", "state": "wrong"})
        ).status_code == 400
        assert not identity_provider.calls
        assert (
            await http.get("/auth/callback", params={"error": "cancel", "state": state})
        ).status_code == 303
        assert not identity_provider.calls
        assert (await http.get("/workspace/session")).json()["login_error"][
            "code"
        ] == "login_cancelled"


async def test_bootstrap_capacity_has_429(workspace_settings, identity_provider):
    app = create_workspace_app(
        workspace_settings,
        model=TestModel(call_tools=[]),
        http_transport=httpx.MockTransport(identity_provider.handle),
    )
    async with app.router.lifespan_context(app):
        for _ in range(16):
            app.state.store.bootstrap(None)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as http:
            assert (await http.get("/workspace/session")).status_code == 429


def test_cli_occupied_port_is_actionable_before_network(tmp_path):
    import os
    import socket
    import subprocess
    import sys

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("LOGIN_", "OAUTH_", "VERIFY_", "POCDANTIC_"))
        }
        env.update(
            {
                "MODEL": "test",
                "LOGIN_CLIENT_ID": "login",
                "LOGIN_CLIENT_SECRET": "fixture",
                "OAUTH_AUDIENCE": "resource",
                "OAUTH_DISCOVERY_URL": "https://id.example/discovery",
            }
        )
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from agent.cli import main; main()",
                "workspace",
                "--port",
                str(listener.getsockname()[1]),
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "Port unavailable" in result.stderr and "--port" in result.stderr
        assert "fixture" not in result.stderr


def test_workspace_budget_is_checked_locally(workspace_settings):
    for timeout in (0, 181):
        with pytest.raises(SecurityError, match="configuration_missing"):
            create_workspace_app(
                workspace_settings.model_copy(update={"timeout_seconds": timeout}),
                model=TestModel(call_tools=[]),
            )


async def test_operational_routes_require_bootstrap_and_csrf(workspace_settings, identity_provider):
    app = create_workspace_app(
        workspace_settings,
        model=TestModel(call_tools=[]),
        http_transport=httpx.MockTransport(identity_provider.handle),
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as http,
    ):
        assert (await http.get("/workspace/operations")).status_code == 403
        view = (await http.get("/workspace/session")).json()
        assert (await http.get("/workspace/operations")).json()["authentication"] is False
        assert (
            await http.post(
                "/workspace/recovery/check",
                json={"schema_version": 1},
                headers={"Origin": "http://127.0.0.1:8000"},
            )
        ).status_code in {400, 403}
        headers = {"Origin": "http://127.0.0.1:8000", "X-CSRF-Token": view["csrf_token"]}
        response = await http.post(
            "/workspace/recovery/check", json={"schema_version": 1}, headers=headers
        )
        assert response.status_code == 200 and response.json()["incidents"] == []
        assert (
            await http.post(
                "/workspace/diagnostics",
                json={"schema_version": 1, "url": "https://evil.example"},
                headers=headers,
            )
        ).status_code == 400
