"""Ephemeral WebKit workspace with synthetic signed identity; external network denied."""

import asyncio
import html
import socket
import threading
import time
from urllib.parse import parse_qs, urlencode, urlparse
from uuid import uuid4

import httpx
import pytest
import uvicorn
from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.models.test import TestModel

from agent.approval import ApprovalOutcome
from agent.broker import DatabaseBroker
from agent.workspace.app import create_workspace_app


@pytest.fixture
def workspace_browser(workspace_settings, identity_provider, request, monkeypatch):
    from playwright.sync_api import sync_playwright

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    options = getattr(request, "param", {})
    counts = {"model": 0, "read": 0, "prompt": 0}
    mode = options.get("mode")
    if options.get("scopes"):
        identity_provider.scopes = options["scopes"]

    def respond(messages, info):
        counts["model"] += 1
        returns = sum(
            isinstance(part, ToolReturnPart) for message in messages for part in message.parts
        )
        if returns < options.get("reads", 1):
            return ModelResponse(
                parts=[
                    ToolCallPart("read_database", {"record_id": 1})
                    if mode == "database"
                    else ToolCallPart("request_infrastructure_restart", {})
                ]
            )
        return ModelResponse(
            parts=[
                ToolCallPart(
                    info.output_tools[0].name,
                    {"summary": options.get("summary", "Record 1: healthy")},
                )
            ]
        )

    async def read(lease, **kwargs):
        counts["read"] += 1
        if options.get("read_delay"):
            await asyncio.sleep(options["read_delay"])
        assert lease.username.get_secret_value() == "fixture-user"
        assert kwargs["record_id"] == 1
        return [{"id": 1, "status": "healthy"}]

    monkeypatch.setattr("agent.broker.read_postgres", read)
    config = workspace_settings.model_copy(
        update={
            "timeout_seconds": options.get("timeout", 1),
            "vault_addr": "https://vault.example",
            "vault_audience": "vault",
            "database_host": "db.example",
            "database_name": "postgres",
        }
    )

    def factory(snapshot, sink):
        return DatabaseBroker(
            config, snapshot.access_token, snapshot.principal.subject, http=app.state.auth.http
        )

    async def backend(deps, approval, action):
        counts["prompt"] += 1
        if options.get("prompt_delay"):
            await asyncio.sleep(options["prompt_delay"])
        decision = options.get("decision", "unconfirmed") if counts["prompt"] == 1 else "approved"
        if decision in {"approved", "denied"}:
            deps.approvals.record_decision(
                approval.id,
                approved=decision == "approved",
                approver=deps.principal.subject,
                source_event="controlled-native-decision",
            )
        return ApprovalOutcome(decision)

    async def transport(request):
        if request.url.host == "vault.example" and request.method == "PUT":
            if options.get("cleanup_delay"):
                await asyncio.sleep(options["cleanup_delay"])
        return identity_provider.handle(request)

    app = create_workspace_app(
        config,
        port=port,
        model=FunctionModel(respond) if mode else TestModel(call_tools=[]),
        http_transport=httpx.MockTransport(transport),
        database_reader_factory=factory,
        approval_backend=backend,
    )
    app.state.test_counts = counts
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            access_log=False,
            proxy_headers=False,
            log_level="error",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("local test server did not start")
        time.sleep(0.01)
    with sync_playwright() as playwright:
        browser = playwright.webkit.launch()
        context = browser.new_context()

        def route(request_route):
            url = request_route.request.url
            if url.startswith(origin + "/"):
                request_route.continue_()
            elif url.startswith("https://id.example/authorize?"):
                values = parse_qs(urlparse(url).query)
                code = str(uuid4())
                identity_provider.codes[code] = (
                    "wrong-nonce" if options.get("bad_nonce") else values["nonce"][0]
                )
                destination = (
                    values["redirect_uri"][0]
                    + "?"
                    + urlencode({"code": code, "state": values["state"][0]})
                )
                request_route.fulfill(
                    status=200,
                    content_type="text/html",
                    body='<meta http-equiv="refresh" content="0;url='
                    + html.escape(destination, quote=True)
                    + '">',
                )
            else:
                request_route.abort()
                raise AssertionError("unmocked browser network")

        app.state.test_browser_route = route
        context.route("**/*", route)
        page = context.new_page()
        yield page, origin, app, identity_provider
        context.close()
        browser.close()
    server.should_exit = True
    thread.join(timeout=10)
    assert not thread.is_alive()
