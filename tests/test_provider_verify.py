"""Verify controls are tenant scoped and preserve independent unknown outcomes."""

import json
from uuid import uuid4

import httpx
import pytest
from provider_support import resource
from pydantic import SecretStr

from agent.response.providers.models import ProviderAction


@pytest.mark.parametrize(
    "kind,method,path",
    [
        ("suspend_user", "PATCH", "/v2.0/Users/resource-one"),
        ("revoke_user_sessions", "DELETE", "/v1.0/auth/sessions/resource-one"),
    ],
)
async def test_exact_user_control(workspace_settings, kind, method, path):
    """Only the pinned user receives a tenant operation; upstream IBMid is unclaimed."""
    from agent.response.providers.verify import VerifyAdapter

    settings = workspace_settings.model_copy(
        update={
            "verify_tenant_url": "https://provider.example",
            "verify_api_client_id": "fixture",
            "verify_api_client_secret": SecretStr("fixture"),
            "oauth_token_endpoint": "https://provider.example/token",
            "oauth_provider": "generic",
        }
    )
    calls = []

    def handle(request):
        """Issue only a synthetic API token and acknowledge the exact target."""
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "fixture", "token_type": "Bearer"})
        calls.append(request)
        return httpx.Response(204)

    action = ProviderAction(
        kind=kind,
        binding=resource(settings, "user"),
        enrollment_digest="1" * 64,
        incidents=(uuid4(),),
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        result = await VerifyAdapter(settings, http).execute(action)
    assert calls[0].method == method and calls[0].url.path == path
    assert result.proof == "not_run"
    if method == "PATCH":
        assert json.loads(calls[0].content)["Operations"][:1] == [
            {"op": "replace", "path": "active", "value": False}
        ]
