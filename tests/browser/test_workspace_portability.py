"""WebKit presents generic setup without implying advanced provider support."""

import pytest


@pytest.mark.parametrize("workspace_browser", [{"portable": True}], indirect=True)
def test_generic_browser_can_sign_in_without_agent_credentials(workspace_browser):
    """No saved bearer or Verify configuration is needed for confidential login."""
    page, origin, _, _ = workspace_browser
    page.goto(origin)
    page.wait_for_selector("#capabilities li")
    assert "phone approval: unverified" in page.locator("#capabilities").inner_text()
    page.click("#login")
    page.wait_for_selector("#logout:not([hidden])")
    assert page.locator("#session-status").inner_text() == "Signed in"


@pytest.mark.parametrize(
    "workspace_browser", [{"portable": True, "bad_nonce": True}], indirect=True
)
def test_generic_bad_identity_does_not_open_workspace(workspace_browser):
    """The generic baseline preserves signed identity and single-use callback protection."""
    from playwright.sync_api import expect

    page, origin, app, _ = workspace_browser
    page.goto(origin)
    page.click("#login")
    expect(page.locator("#error")).to_contain_text("Sign-in could not be verified")
    assert page.locator("#workspace").is_hidden()
    assert app.state.test_counts["read"] == app.state.test_counts["prompt"] == 0
