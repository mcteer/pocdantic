"""Real WebKit keeps incident detail within its owning browser session."""

import time

from playwright.sync_api import expect
from response_support import signal

from agent.response.coordinator import Coordinator
from agent.response.models import ResponseError


def local_control(operation):
    """Retry only short-lock contention from concurrent browser status requests.

    Navigating away stops new polling but cannot drain a request already executing
    on the server thread. Keep production locks nonblocking and preserve every
    non-busy error, including stale revisions and unsafe release.
    """
    deadline = time.monotonic() + 2
    while True:
        try:
            return operation()
        except ResponseError as error:
            if str(error) != "response_busy" or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def completed(page, origin):
    """Sign in and establish one trusted terminal root through the browser workflow."""
    page.goto(origin)
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.locator("#task").fill("Read a ticket")
    page.locator("#profile").select_option("ticket-reader")
    page.get_by_role("button", name="Run", exact=True).click()
    expect(page.locator("#status")).to_have_text("Completed")


def test_root_hold_details_and_unrelated_admission(workspace_browser):
    """A retained root hold is visible to its owner but permits a fresh unrelated root."""
    page, origin, app, provider = workspace_browser
    completed(page, origin)
    store = app.state.response
    run = local_control(store.read).runs[0]
    coordinator = Coordinator(store)
    event = signal(store.settings, root=run.root_run_id)
    item, _ = local_control(lambda: coordinator.submit(event))
    assert local_control(lambda: coordinator.reconcile(item.incident_id)).phase == "settled"
    page.reload()
    expect(page.locator("#containment-status")).to_contain_text("Work stopped")
    expect(page.locator("#containment-status")).to_contain_text("confirmed")
    expect(page.get_by_role("button", name="Run", exact=True)).to_be_enabled()
    # A second session uses the same synthetic human identity, but owns no prior jobs.
    foreign = page.context.browser.new_context()
    try:
        foreign.route("**/*", app.state.test_browser_route)
        other = foreign.new_page()
        other.goto(origin)
        other.get_by_role("button", name="Sign in", exact=True).click()
        expect(other.locator("#session-status")).to_have_text("Signed in")
        view = other.evaluate("fetch('/workspace/operations').then(r=>r.json())")
        assert str(item.incident_id) not in str(view)
        assert view["containment"]["incidents"] == []
    finally:
        foreign.close()
    page.get_by_role("button", name="Sign out", exact=True).click()
    page.reload()
    expect(page.locator("#session-status")).to_have_text("Sign in to run a task")
    view = page.evaluate("fetch('/workspace/operations').then(r=>r.json())")
    assert str(item.incident_id) not in str(view)
    assert "incidents" not in view["containment"]
    assert not page.get_by_role("button", name="Release", exact=True).count()


def test_definition_hold_release_and_fresh_generation(workspace_browser):
    """A local release opens new admission without attaching old incidents to new roots."""
    page, origin, app, provider = workspace_browser
    completed(page, origin)
    store = app.state.response
    coordinator = Coordinator(store)
    event = signal(store.settings)
    item, _ = local_control(lambda: coordinator.submit(event))
    assert local_control(lambda: coordinator.reconcile(item.incident_id)).phase == "settled"
    page.reload()
    expect(page.get_by_role("button", name="Run", exact=True)).to_be_disabled()
    page.goto("about:blank")
    local_control(
        lambda: coordinator.release(
            store.settings.workload_definition,
            [item.incident_id],
            store.read().revision,
            "test-operator",
        )
    )
    page.goto(origin)
    expect(page.get_by_role("button", name="Run", exact=True)).to_be_enabled()
    page.locator("#task").fill("Read a fresh ticket")
    page.locator("#profile").select_option("ticket-reader")
    page.get_by_role("button", name="Run", exact=True).click()
    expect(page.locator("#history li")).to_have_count(2)
    expect(page.locator("#status")).to_have_text("Completed")
    expect(page.locator("#containment-status")).to_have_text("")
    state = local_control(store.read)
    assert state.runs[-1].generation > state.runs[0].generation
