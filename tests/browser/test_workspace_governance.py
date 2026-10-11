"""WebKit displays only owned generated cases and clears them when signing out."""

import pytest
from playwright.sync_api import expect

from .test_workspace_containment import completed, local_control


@pytest.mark.parametrize("closure", ["logout", "expiry", "suspension"])
def test_governance_owned_rows_clear_on_signout(workspace_browser, closure):
    """Native owner/entity data and foreign cases never enter the browser view."""
    from governance_support import binding, source

    page, origin, app, provider = workspace_browser
    completed(page, origin)
    gov = app.state.governance

    def prepare():
        """Install a synthetic case under the fixture's isolated private project root."""
        gov.prepare()
        gov.configure((source(),), 1)
        own = gov.case("fixture")
        other = gov.case("fixture")
        own = own.model_copy(
            update={"binding": binding(owner_subject=provider.subject, owner="private-canary")}
        )
        other = other.model_copy(update={"binding": binding(owner_subject="foreign-subject")})
        gov.change(lambda j: j.model_copy(update={"candidates": (own, other)}))
        return own, other

    own, other = local_control(prepare)
    page.goto(origin)
    expect(page.locator("#governance-cases")).to_contain_text(own.alias)
    expect(page.locator("#governance-cases")).not_to_contain_text(other.alias)
    assert "private-canary" not in page.content()
    if closure == "logout":
        page.get_by_role("button", name="Sign out", exact=True).click()
    elif closure == "expiry":

        def expire():
            """Expire only the fixture credentials; status performs no automatic refresh."""
            import time

            active = next(iter(app.state.store.sessions.values()))
            active.credentials = active.credentials.with_expiry(time.time() - 1)

        local_control(expire)
    else:
        local_control(lambda: setattr(app.state.store, "subject_held", lambda *_: True))
    expect(page.locator("#governance-cases li")).to_have_count(0)
