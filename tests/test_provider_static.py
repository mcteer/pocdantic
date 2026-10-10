"""Static role response rotates one isolated role without reading credentials."""

from uuid import uuid4

import httpx
from provider_support import resource
from pydantic import SecretStr

from agent.response.providers.models import ProviderAction
from agent.response.providers.vault import VaultAdapter


async def test_static_role_rotation_never_root_or_credential_read(workspace_settings):
    """A metadata-only contract and exact POST cannot select rotate-root/static-creds."""
    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    calls = []

    def handle(request):
        """Capture a synthetic single-role rotation acknowledgment."""
        calls.append(request)
        return httpx.Response(204)

    action = ProviderAction(
        kind="rotate_static",
        binding=resource(settings, "static_role"),
        enrollment_digest="1" * 64,
        incidents=(uuid4(),),
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        result = await VaultAdapter(settings, http).execute(action)
    assert (
        calls[0].method == "POST" and calls[0].url.path == "/v1/database/rotate-role/resource-one"
    )
    assert result.proof == "not_run"
