"""WebKit displays generated code only for the owning session and as inert text."""

import pytest


@pytest.mark.parametrize("workspace_browser", [{"mode": "sandbox"}], indirect=True)
def test_real_engine_workspace_explanation(workspace_browser):
    page, origin, app, _ = workspace_browser
    page.goto(origin)
    page.click("#login")
    page.wait_for_selector("#logout:not([hidden])")
    page.select_option("#profile", "database-analyst")
    page.fill("#task", "Count and double the records")
    page.click("#run")
    page.wait_for_selector("#show-execution:not([hidden])", timeout=20000)
    page.click("#show-execution")
    page.wait_for_selector("#execution:not([hidden])")
    text = page.locator("#execution").inner_text()
    assert "query_database" in text and "sandbox: passed" in text
    assert "fixture-user" not in text and "fixture-password" not in text
    page.click("#logout")
    page.wait_for_selector("#login:not([hidden])")
    assert page.locator("#workspace").is_hidden()
