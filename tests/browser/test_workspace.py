import pytest
from playwright.sync_api import expect


def test_keyboard_sign_in_and_sign_out(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
    page.get_by_role("button", name="Sign in", exact=True).focus()
    page.keyboard.press("Enter")
    expect(page.locator("#session-status")).to_have_text("Signed in")
    assert provider.calls == ["authorization_code"]
    assert (
        page.evaluate("Object.keys(localStorage).length + Object.keys(sessionStorage).length") == 0
    )
    assert "agent_workspace" not in page.evaluate("document.cookie")
    page.get_by_role("button", name="Sign out", exact=True).focus()
    page.keyboard.press("Enter")
    expect(page.locator("#session-status")).to_have_text("Sign in to run a task")


def test_submit_reload_inert_result_and_double_click(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("<script>window.compromised=true</script>")
    page.locator("#profile").select_option("ticket-reader")
    page.get_by_role("button", name="Run", exact=True).focus()
    page.keyboard.press("Enter")
    expect(page.locator("#status")).to_have_text("Completed", timeout=2000)
    expect(page.locator("#history li")).to_have_count(1)
    page.reload()
    expect(page.locator("#status")).to_have_text("Completed", timeout=2000)
    expect(page.locator("#history li")).to_have_count(1)
    assert not page.evaluate("Boolean(window.compromised)")


@pytest.mark.parametrize(
    "workspace_browser",
    [{"mode": "database", "summary": '<img src=x onerror="window.compromised=true">'}],
    indirect=True,
)
def test_ten_signed_database_reads_and_exact_cleanup(workspace_browser):
    import json

    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#profile").select_option("database-reader")
    for index in range(10):
        page.locator("#task").fill("Read database record 1")
        page.get_by_role("button", name="Run", exact=True).click()
        expect(page.locator("#history li")).to_have_count(index + 1, timeout=2000)
        expect(page.locator("#status")).to_have_text("Completed", timeout=2000)
        expect(page.locator("#cleanup")).to_have_text("Credential cleanup: revoked")
    assert app.state.test_counts["read"] == 10
    assert len(provider.vault_calls) == 20
    for get, revoke in zip(provider.vault_calls[::2], provider.vault_calls[1::2], strict=True):
        assert get.method == "GET" and revoke.method == "PUT"
        assert get.headers["X-Vault-Token"] != revoke.headers["X-Vault-Token"]
        assert json.loads(revoke.content)["lease_id"].startswith(
            "database/creds/poc-readonly/lease"
        )
    expect(page.locator("#result")).to_contain_text("<img")
    assert page.locator("#result img").count() == 0
    assert not page.evaluate("Boolean(window.compromised)")


@pytest.mark.parametrize(
    "workspace_browser", [{"mode": "approval", "decision": "unconfirmed"}], indirect=True
)
def test_retry_is_explicit_and_does_not_replay_model(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("Request simulated restart")
    page.get_by_role("button", name="Run", exact=True).click()
    expect(page.locator("#status")).to_have_text("Failed — approval unconfirmed", timeout=2000)
    expect(page.get_by_role("button", name="Retry approval")).to_be_visible()
    models = app.state.test_counts["model"]
    page.get_by_role("button", name="Retry approval").focus()
    page.keyboard.press("Enter")
    expect(page.locator("#status")).to_have_text("Completed", timeout=2000)
    assert app.state.test_counts["model"] == models
    assert app.state.test_counts["prompt"] == 2
    expect(page.locator("#retry")).to_be_hidden()


@pytest.mark.parametrize("workspace_browser", [{"bad_nonce": True}], indirect=True)
def test_bad_nonce_has_no_session_or_model(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#error")).to_contain_text("could not be verified")
    expect(page.locator("#workspace")).to_be_hidden()
    assert app.state.test_counts["model"] == 0
    assert page.url == origin + "/"


def test_lost_submission_reuses_uuid(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    lost = []

    def lose(route):
        if route.request.method == "POST" and not lost:
            lost.append(True)
            route.fetch()
            route.abort()
        else:
            route.continue_()

    page.route(origin + "/workspace/runs", lose)
    page.locator("#task").fill("hello")
    page.locator("#profile").select_option("ticket-reader")
    page.locator("#run").click()
    expect(page.locator("#run")).to_have_text("Check submission")
    page.locator("#run").click()
    expect(page.locator("#run")).to_have_text("Run")
    expect(page.locator("#history li")).to_have_count(1)


@pytest.mark.parametrize("workspace_browser", [{"mode": "database"}], indirect=True)
def test_admission_refresh_in_webkit(workspace_browser):
    import time

    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    session = next(iter(app.state.store.sessions.values()))
    session.credentials = session.credentials.with_expiry(time.time() + 1)
    page.locator("#task").fill("Read database record 1")
    page.locator("#profile").select_option("database-reader")
    page.locator("#run").click()
    expect(page.locator("#status")).to_have_text("Completed", timeout=2000)
    assert provider.calls.count("refresh_token") == 1


@pytest.mark.parametrize(
    "workspace_browser",
    [{"mode": "approval", "decision": "approved"}, {"mode": "approval", "decision": "denied"}],
    indirect=True,
)
def test_terminal_approval_has_no_retry(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("restart")
    page.locator("#run").click()
    expect(page.locator("#status")).to_have_text(
        __import__("re").compile("Completed|Denied"), timeout=2000
    )
    expect(page.locator("#retry")).to_be_hidden()
    assert app.state.test_counts["prompt"] == 1


@pytest.mark.parametrize(
    "workspace_browser", [{"mode": "approval", "prompt_delay": 2, "timeout": 5}], indirect=True
)
def test_waiting_status_is_visible_and_signout_interrupts(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("restart")
    page.locator("#run").click()
    expect(page.locator("#status")).to_have_text("Waiting for your phone decision", timeout=2000)
    job = app.state.manager.owner
    page.locator("#logout").click()
    expect(page.locator("#session-status")).to_have_text("Sign in to run a task")
    assert job.stopped
    assert not job.view.retry_available


def test_cross_site_requests_and_forged_authority_are_rejected(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    headers = {"Origin": "https://evil.example"}
    assert (
        page.request.post(
            origin + "/auth/login", data={"schema_version": 1}, headers=headers
        ).status
        == 400
    )
    assert (
        page.request.get(origin + "/workspace/session", headers={"Host": "evil.example"}).status
        == 400
    )
    expect(page.locator("#workspace")).to_be_hidden()
    assert provider.calls == []


def test_foreign_signed_session_cannot_view_job(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.locator("#login").click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("hello")
    page.locator("#profile").select_option("ticket-reader")
    page.locator("#run").click()
    expect(page.locator("#status")).to_have_text("Completed", timeout=2000)
    job_id = page.request.get(origin + "/workspace/runs").json()["jobs"][0]["job_id"]
    context = page.context.browser.new_context()
    context.route("**/*", app.state.test_browser_route)
    second = context.new_page()
    second.goto(origin)
    second.locator("#login").click()
    expect(second.locator("#session-status")).to_have_text("Signed in")
    expect(second.locator("#history li")).to_have_count(0)
    from uuid import uuid4

    foreign = context.request.get(origin + "/workspace/runs/" + job_id)
    unknown = context.request.get(origin + "/workspace/runs/" + str(uuid4()))
    assert foreign.status == unknown.status == 404
    assert foreign.json() == unknown.json()
    context.close()


@pytest.mark.parametrize(
    "workspace_browser", [{"mode": "database", "scopes": "tickets:read"}], indirect=True
)
def test_database_permission_denial_has_zero_effects(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.locator("#login").click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("Read database record 1")
    page.locator("#profile").select_option("database-reader")
    page.locator("#run").click()
    expect(page.locator("#status")).to_have_text("Denied", timeout=2000)
    expect(page.locator("#cleanup")).to_have_text("Credential cleanup: not_acquired")
    assert not provider.vault_calls and app.state.test_counts["read"] == 0


@pytest.mark.parametrize(
    "workspace_browser", [{"mode": "database", "read_delay": 0.5, "timeout": 5}], indirect=True
)
def test_database_signout_drains_exact_lease(workspace_browser):
    import time

    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.locator("#login").click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("Read database record 1")
    page.locator("#profile").select_option("database-reader")
    page.locator("#run").click()
    # Wait only for the controlled lease to be acquired before the operator signs out.
    deadline = time.monotonic() + 2
    while app.state.test_counts["read"] == 0 and time.monotonic() < deadline:
        page.wait_for_timeout(10)
    assert app.state.test_counts["read"] == 1
    job = app.state.manager.owner
    page.locator("#logout").click()
    expect(page.locator("#session-status")).to_have_text("Sign in to run a task")
    deadline = time.monotonic() + 2
    while app.state.manager.busy and time.monotonic() < deadline:
        page.wait_for_timeout(10)
    assert not app.state.manager.busy
    assert len(provider.vault_calls) == 2 and provider.vault_calls[-1].method == "PUT"
    assert job.view.state == "interrupted" and job.view.cleanup_status == "revoked"
    assert not job.view.retry_available


@pytest.mark.parametrize(
    "workspace_browser", [{"mode": "database", "cleanup_delay": 1.5, "timeout": 5}], indirect=True
)
def test_signout_during_cleanup_keeps_gate_and_snapshot(workspace_browser):
    import time

    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.locator("#login").click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("Read database record 1")
    page.locator("#profile").select_option("database-reader")
    page.locator("#run").click()
    expect(page.locator("#status")).to_have_text("Cleaning up credentials", timeout=2000)
    job = app.state.manager.owner
    assert job.snapshot is not None
    page.locator("#logout").click()
    expect(page.locator("#session-status")).to_have_text("Sign in to run a task")
    deadline = time.monotonic() + 3
    while app.state.manager.busy and time.monotonic() < deadline:
        page.wait_for_timeout(10)
    assert not app.state.manager.busy and job.snapshot is None
    assert job.view.state == "interrupted" and job.view.cleanup_status == "revoked"
    assert not job.view.retry_available


@pytest.mark.parametrize("workspace_browser", [{"mode": "database", "reads": 2}], indirect=True)
def test_multiple_sequential_leases_in_one_job(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.locator("#login").click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("Read database record 1 twice")
    page.locator("#profile").select_option("database-reader")
    page.locator("#run").click()
    expect(page.locator("#status")).to_have_text("Completed", timeout=2000)
    expect(page.locator("#cleanup")).to_have_text("Credential cleanup: revoked")
    assert app.state.test_counts["read"] == 2
    assert len(provider.vault_calls) == 4
    session = next(iter(app.state.store.sessions.values()))
    job = next(iter(session.jobs.values()))
    assert job.acquired == job.revoked == 2


def test_history_keeps_keyboard_focus_while_polling(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.goto(origin)
    page.locator("#login").click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("hello")
    page.locator("#profile").select_option("ticket-reader")
    page.locator("#run").click()
    expect(page.locator("#status")).to_have_text("Completed", timeout=2000)
    button = page.locator("#history button").first
    button.focus()
    page.wait_for_timeout(1100)
    expect(button).to_be_focused()
