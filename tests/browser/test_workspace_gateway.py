"""WebKit projects closed model control outcomes without credential or body echoes."""

import pytest
from playwright.sync_api import expect


@pytest.mark.parametrize("workspace_browser", [{"mode": "gateway-denied"}], indirect=True)
def test_gateway_refusal_is_safe_and_never_retried(workspace_browser):
    """The owning browser gets an actionable closed refusal and no automatic retry."""
    page, origin, app, _ = workspace_browser
    page.goto(origin)
    page.click("#login")
    expect(page.locator("#session-status")).to_have_text("Signed in")
    page.select_option("#profile", "ticket-reader")
    page.fill("#task", "Synthetic request")
    page.click("#run")
    expect(page.locator("#error")).to_contain_text("Credential protection blocked", timeout=5000)
    expect(page.locator("#retry")).to_be_hidden()
    assert app.state.test_counts["model"] == 1
    assert app.state.test_counts["read"] == 0
    assert "fixture-password" not in page.content()


@pytest.mark.parametrize("workspace_browser", [{"legacy_direct": True}], indirect=True)
def test_legacy_direct_is_visible(workspace_browser):
    """Explicit direct mode cannot be mistaken for reviewed Gateway protection."""
    page, origin, _, _ = workspace_browser
    page.goto(origin)
    expect(page.locator("#issues")).to_contain_text("Gateway controls are absent")


def test_operator_managed_administration_is_visible(workspace_browser):
    """A reviewed protection label must not imply budget or service-retention attestation."""
    page, origin, _, _ = workspace_browser

    def status(route):
        """Keep the synthetic session fixture while selecting the closed ownership state."""
        response = route.fetch()
        body = response.json()
        body["model_control"] = "protected-operator-managed"
        route.fulfill(response=response, json=body)

    page.route("**/workspace/session", status)
    page.goto(origin)
    expect(page.locator("#issues")).to_contain_text(
        "spending and service retention are operator-managed"
    )
