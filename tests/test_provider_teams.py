"""Workflow capability URL stays private and acceptance is not delivery."""

from uuid import uuid4

import httpx
import pytest
from provider_support import resource
from pydantic import SecretStr

from agent.response.models import ResponseError
from agent.response.providers.models import ProviderAction


async def test_safe_card_and_distinct_acceptance(workspace_settings):
    """The card has opaque correlations and no authority header or source content."""
    from agent.response.providers.teams import TeamsAdapter

    calls = []

    def handle(request):
        """Capture a synthetic card without contacting a workflow."""
        calls.append(request)
        return httpx.Response(202)

    action = ProviderAction(
        kind="notify_teams",
        binding=resource(workspace_settings, "teams"),
        enrollment_digest="1" * 64,
        incidents=(uuid4(),),
        notice_id=uuid4(),
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        result = await TeamsAdapter(
            http, {"teams-hook": SecretStr("https://provider.example/workflow?sig=fixture")}
        ).execute(action)
    assert "authorization" not in calls[0].headers
    assert len(calls[0].content) <= 8192
    assert b"fixture" not in calls[0].content and b"https" not in calls[0].content
    assert result.reason == "notification_accepted" and result.proof == "not_run"


async def test_reconcile_never_sends(workspace_settings):
    """Status cannot silently resend a notice or probe a capability URL."""
    from agent.response.providers.teams import TeamsAdapter

    action = ProviderAction(
        kind="notify_teams",
        binding=resource(workspace_settings, "teams"),
        enrollment_digest="1" * 64,
        incidents=(uuid4(),),
        notice_id=uuid4(),
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: pytest.fail("network"))
    ) as http:
        with pytest.raises(ResponseError, match="unsupported"):
            await TeamsAdapter(http, {}).execute(action, read_only=True)


async def test_root_advisory_card_has_exact_scope_and_timeout_is_uncertain(workspace_settings):
    """A root notice labels only root containment and never claims delivery on a lost reply."""
    import json

    from agent.response.providers.teams import TeamsAdapter

    action = ProviderAction(
        kind="notify_teams",
        scope="root_run",
        binding=resource(workspace_settings, "teams"),
        enrollment_digest="1" * 64,
        incidents=(uuid4(),),
        notice_id=uuid4(),
    )

    def lost(request):
        """Inspect the fixed generated scope before simulating a post-send timeout."""
        facts = json.loads(request.content)["attachments"][0]["content"]["body"][1]["facts"]
        assert next(f["value"] for f in facts if f["title"] == "Scope") == "root_run"
        raise httpx.ReadTimeout("PRIVATE_PROVIDER_CANARY", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(lost)) as http:
        with pytest.raises(ResponseError, match="provider_uncertain"):
            await TeamsAdapter(
                http, {"teams-hook": SecretStr("https://provider.example/workflow?sig=fixture")}
            ).execute(action)
