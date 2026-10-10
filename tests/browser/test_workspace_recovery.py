"""Browser recovery observes operator closure without replay or restored authority."""

import argparse
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from playwright.sync_api import expect

from agent.recovery.commands import execute_recovery


@pytest.mark.parametrize("authority", ["active", "signed_out", "expired"])
def test_operator_closure_and_manual_new_submission(workspace_browser, authority):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("old task")
    page.get_by_role("button", name="Run", exact=True).click()
    expect(page.locator("#status")).to_have_text("Completed")
    prior_counts = dict(app.state.test_counts)
    store = app.state.recovery
    with store.effect() as owner:
        item = store.begin(owner)
        item = store.update(
            item.incident_id,
            item.revision,
            state="unresolved",
            lease_handle=item.credential_path + "/native",
        )
    session = next(iter(app.state.store.sessions.values()))
    job = next(iter(session.jobs.values()))
    job.incidents.add(item.incident_id)
    app.state.manager.recovery_incidents.add(item.incident_id)
    app.state.manager.quarantined = True
    page.get_by_role("button", name="Check recovery", exact=True).click()
    expect(page.locator("#operations-status")).to_contain_text("blocked")
    expect(page.locator("#incidents")).to_contain_text(str(item.incident_id))
    if authority == "signed_out":
        page.get_by_role("button", name="Sign out", exact=True).click()
    elif authority == "expired":
        session.state = "reauth_required"
        page.reload()
    from pydantic import SecretStr

    settings = store.settings.model_copy(update={"vault_token": SecretStr("private")})
    calls = []

    def cleanup(request):
        calls.append(request)
        assert request.method == "PUT" and json.loads(request.content)["sync"] is True
        return httpx.Response(204)

    with ThreadPoolExecutor(max_workers=1) as executor:
        code = executor.submit(
            lambda: asyncio.run(
                execute_recovery(
                    argparse.Namespace(recovery_command="revoke", incident_id=item.incident_id),
                    settings=settings,
                    project=store.project,
                    transport=httpx.MockTransport(cleanup),
                )
            )
        ).result(timeout=5)
    assert code == 0
    page.get_by_role("button", name="Check recovery", exact=True).click()
    expect(page.locator("#operations-status")).to_contain_text("clear")
    assert len(calls) == 1 and app.state.test_counts == prior_counts
    if authority == "active":
        expect(page.locator("#session-status")).to_have_text("Signed in")
        expect(page.locator("#status")).to_have_text("Completed")
        page.locator("#task").fill("new manually submitted task")
        page.get_by_role("button", name="Run", exact=True).click()
        expect(page.locator("#history li")).to_have_count(2)
    else:
        expect(page.locator("#workspace")).to_be_hidden()
        expect(page.locator("#incidents li")).to_have_count(0)
    assert provider.calls == ["authorization_code"]


def test_anonymous_missing_state_has_no_incident_details(workspace_browser):
    page, origin, app, provider = workspace_browser
    (app.state.recovery.root / "anchor.json").unlink()
    page.goto(origin)
    expect(page.locator("#operations-status")).to_contain_text("storage error")
    expect(page.locator("#incidents li")).to_have_count(0)
    expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_enabled()
    assert app.state.test_counts == {"model": 0, "read": 0, "prompt": 0}


def test_restart_loses_sessions_jobs_but_keeps_durable_block(workspace_browser):
    import threading
    import time

    import uvicorn
    from pydantic_ai.models.test import TestModel
    from starlette.testclient import TestClient

    from agent.recovery.store import RecoveryError, RecoveryStore
    from agent.workspace.app import create_workspace_app

    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    store = app.state.recovery
    with store.effect() as owner:
        item = store.begin(owner)
    second = create_workspace_app(
        app.state.config,
        port=int(origin.rsplit(":", 1)[1]),
        model=TestModel(call_tools=[]),
        recovery_store=RecoveryStore(store.settings, project=store.project),
    )
    with pytest.raises(RecoveryError, match="recovery_busy"):
        with TestClient(second):
            pass
    app.state.test_server.should_exit = True
    app.state.test_thread.join(timeout=5)
    assert not app.state.test_thread.is_alive()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=int(origin.rsplit(":", 1)[1]),
            access_log=False,
            log_level="error",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        page.reload()
        expect(page.locator("#session-status")).to_have_text("Sign in to run a task")
        expect(page.locator("#operations-status")).to_contain_text("blocked")
        expect(page.locator("#incidents li")).to_have_count(0)
        expect(page.locator("#history li")).to_have_count(0)
        assert store.read().attempts[0].incident_id == item.incident_id
        assert store.read().attempts[0].state == "unresolved"
        assert not app.state.store.sessions
        assert provider.calls == ["authorization_code"]
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        assert not thread.is_alive()
