"""WebKit renders owned independent provider outcomes and closes suspended user sessions."""

import pytest
from playwright.sync_api import expect
from response_support import signal

from agent.response.coordinator import Coordinator

from .test_workspace_containment import completed, local_control


@pytest.mark.parametrize("workspace_browser", [{"provider_response": "teams"}], indirect=True)
def test_partial_provider_details_owned_and_signout_private(workspace_browser):
    """An unknown notice stays visible to its owner, without capability URL or native IDs."""
    page, origin, app, provider = workspace_browser
    completed(page, origin)
    store = app.state.response
    page.goto("about:blank")
    run = local_control(store.read).runs[0]
    incident, _ = local_control(
        lambda: Coordinator(store).submit(signal(store.settings, root=run.root_run_id))
    )

    def uncertain():
        """Simulate a lost provider reply through the real short atomic snapshot transaction."""
        with store.transaction() as (fd, state):
            store.commit(
                fd,
                state,
                provider_actions=tuple(
                    type(a).model_validate(
                        a.model_dump() | {"state": "uncertain", "reason": "provider_uncertain"}
                    )
                    for a in state.provider_actions
                ),
            )

    local_control(uncertain)
    page.goto(origin)
    expect(page.locator("#provider-controls")).to_contain_text("uncertain")
    expect(page.locator("#provider-controls")).to_contain_text("not run")
    view = page.evaluate("fetch('/workspace/operations').then(r=>r.json())")
    assert "provider.example" not in str(view) and "resource-one" not in str(view)
    foreign = page.context.browser.new_context()
    try:
        foreign.route("**/*", app.state.test_browser_route)
        other = foreign.new_page()
        other.goto(origin)
        other.get_by_role("button", name="Sign in", exact=True).click()
        expect(other.locator("#session-status")).to_have_text("Signed in")
        peer = other.evaluate("fetch('/workspace/operations').then(r=>r.json())")
        assert str(incident.incident_id) not in str(peer)
        expect(other.locator("#provider-controls li")).to_have_count(0)
    finally:
        foreign.close()
    page.get_by_role("button", name="Sign out", exact=True).click()
    expect(page.locator("#provider-controls li")).to_have_count(0)
    page.reload()
    expect(page.locator("#provider-controls li")).to_have_count(0)


@pytest.mark.parametrize("workspace_browser", [{"provider_response": "user"}], indirect=True)
def test_subject_hold_closes_only_matching_session(workspace_browser):
    """A subject hold closes only its matching workspace session."""
    page, origin, app, provider = workspace_browser
    completed(page, origin)
    foreign = page.context.browser.new_context()
    try:
        foreign.route("**/*", app.state.test_browser_route)
        provider.subject = "other-user"
        other = foreign.new_page()
        other.goto(origin)
        other.get_by_role("button", name="Sign in", exact=True).click()
        expect(other.locator("#session-status")).to_have_text("Signed in")
        store = app.state.response
        local_control(lambda: Coordinator(store).submit(signal(store.settings)))
        page.reload()
        expect(page.locator("#session-status")).to_have_text("Sign in to run a task")
        other.reload()
        expect(other.locator("#session-status")).to_have_text("Signed in")
        assert (
            other.evaluate("fetch('/workspace/operations').then(r=>r.json())")["containment"][
                "incidents"
            ]
            == []
        )
    finally:
        foreign.close()
