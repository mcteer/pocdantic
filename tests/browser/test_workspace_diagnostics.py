"""Keyboard-accessible factual diagnostics, signed-out recovery, and delayed bootstrap."""

import httpx
import pytest
from playwright.sync_api import expect


@pytest.mark.parametrize(
    "category", ["configuration", "reachability", "timeout", "authorization", "sign_in", "recovery"]
)
def test_six_categories_do_not_issue_or_execute(workspace_browser, category):
    page, origin, app, provider = workspace_browser
    d = app.state.diagnostics

    async def tcp(*args):
        return None

    d.tcp = tcp

    def handler(request):
        if category == "timeout":
            raise httpx.ReadTimeout("PRIVATE")
        if category == "reachability":
            raise httpx.ConnectError("PRIVATE")
        return httpx.Response(
            403 if category == "authorization" else 200,
            json={"sealed": False, "issuer": "https://id.example"},
        )

    d.transport = httpx.MockTransport(handler)
    if category == "configuration":
        d.settings = d.settings.model_copy(update={"database_name": None})
    if category == "recovery":
        store = app.state.recovery
        with store.effect() as owner:
            item = store.begin(owner)
            store.update(item.incident_id, 1, state="unresolved")
    page.goto(origin)
    button = page.get_by_role("button", name="Check connection", exact=True)
    expect(button).to_be_enabled()
    button.focus()
    page.keyboard.press("Enter")
    expect(page.locator("#diagnostic-checks")).to_contain_text(category)
    assert app.state.test_counts == {"model": 0, "read": 0, "prompt": 0}
    assert provider.vault_calls == [] and provider.calls == []
    assert "PRIVATE" not in page.content()
    expect(page.locator("#operations-status")).to_contain_text("sign-in required")
    if category == "recovery":
        expect(page.locator("#operations-status")).to_contain_text("blocked")
        expect(page.locator("#incidents li")).to_have_count(0)
        expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_enabled()
        page.get_by_role("button", name="Check recovery", exact=True).click()
        expect(page.locator("#operations-status")).to_contain_text("blocked")


def test_checks_wait_for_bootstrap(workspace_browser):
    page, origin, app, provider = workspace_browser
    page.add_init_script("""
      const fetchOriginal=window.fetch.bind(window);
      window.fetch=(...args)=>args[0]==='/workspace/session' ? new Promise(resolve=>{
        window.releaseBootstrap=()=>resolve(fetchOriginal(...args));
      }):fetchOriginal(...args);
    """)
    page.goto(origin)
    expect(page.get_by_role("button", name="Check connection", exact=True)).to_be_disabled()
    expect(page.get_by_role("button", name="Check recovery", exact=True)).to_be_disabled()
    page.evaluate("window.releaseBootstrap()")
    expect(page.get_by_role("button", name="Check recovery", exact=True)).to_be_enabled()
    assert provider.calls == []


def test_observations_become_stale_without_new_effects(workspace_browser):
    page, origin, app, provider = workspace_browser

    async def tcp(*args):
        return None

    app.state.diagnostics.tcp = tcp
    app.state.diagnostics.transport = httpx.MockTransport(
        lambda _: httpx.Response(200, json={"sealed": False, "issuer": "https://id.example"})
    )
    page.goto(origin)
    page.get_by_role("button", name="Check connection", exact=True).click()
    expect(page.locator("#diagnostic-checks")).to_contain_text("transport only")
    page.evaluate("Date.now=()=>new Date().getTime()+61000; diagnosticFreshness()")
    expect(page.locator("#diagnostic-freshness")).to_contain_text("stale")
    assert app.state.test_counts["read"] == 0 and provider.calls == []
