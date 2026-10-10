"""Vault controls use exact enrolled endpoints and independent readback."""

from uuid import uuid4

import httpx
import pytest
from provider_support import resource
from pydantic import SecretStr

from agent.response.providers.models import ProviderAction
from agent.response.providers.vault import VaultAdapter


@pytest.mark.parametrize(
    "status,state", [(204, "acknowledged"), (403, "denied"), (500, "uncertain")]
)
async def test_exact_registration_control(workspace_settings, status, state):
    """Provider acceptance has no enforcement proof; HTTP rejection stays distinct."""
    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    calls = []

    def handle(request):
        """Record only synthetic request metadata, without live network."""
        calls.append(request)
        return httpx.Response(status, json={} if status != 204 else None)

    action = ProviderAction(
        kind="block_registration",
        binding=resource(settings),
        enrollment_digest="1" * 64,
        incidents=(uuid4(),),
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        result = await VaultAdapter(settings, http).execute(action)
    assert calls[0].method == "DELETE"
    assert calls[0].url.path == "/v1/agent-registry/registration/id/resource-one"
    assert result.state == state and result.proof == "not_run"


async def test_missing_registration_readback_is_only_registration_proof(workspace_settings):
    """Metadata absence never claims same-token denial or fresh issuance prevention."""
    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    action = ProviderAction(
        kind="block_registration",
        binding=resource(settings),
        enrollment_digest="1" * 64,
        incidents=(uuid4(),),
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(404, json={"errors": []}))
    ) as http:
        result = await VaultAdapter(settings, http).execute(action, read_only=True)
    assert result.path == "registration" and result.proof == "proven"


async def test_readiness_checks_exact_metadata_and_authority_without_mutation(workspace_settings):
    """Metadata/capability checks cannot rotate, delete or read static credentials."""
    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    binding = resource(settings, "static_role")
    calls = []

    def handle(request):
        """Return only a synthetic exact role and narrowly scoped capability result."""
        calls.append(request)
        if request.url.path == "/v1/sys/capabilities-self":
            return httpx.Response(
                200,
                json={
                    "database/static-roles/resource-one": ["read"],
                    "database/rotate-role/resource-one": ["update"],
                },
            )
        return httpx.Response(
            200,
            json={"data": {"username": "isolated", "db_name": "fixture", "rotation_period": 3600}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        checked = await VaultAdapter(settings, http).readiness(binding)
    assert checked.capability == "supported" and checked.checked_at and checked.capability_digest
    assert len(calls) == 2 and all(r.method in {"GET", "POST"} for r in calls)
    assert not any("static-creds" in r.url.path or "rotate-root" in r.url.path for r in calls)


async def test_capability_rejection_cannot_enable_static_rotation(workspace_settings):
    """An installed role without rotation authority remains blocked after metadata succeeds."""
    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )

    def handle(request):
        """Return exact metadata but only read capability, with no update grant."""
        if request.url.path == "/v1/sys/capabilities-self":
            return httpx.Response(
                200,
                json={
                    "database/static-roles/resource-one": ["read"],
                    "database/rotate-role/resource-one": ["deny"],
                },
            )
        return httpx.Response(200, json={"data": {"username": "isolated", "db_name": "fixture"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        result = await VaultAdapter(settings, http).readiness(resource(settings, "static_role"))
    assert result.capability != "supported"


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"Location": "https://evil.example"}),
        httpx.Response(200, content=b" " * 262145),
    ],
)
async def test_provider_response_limits_and_redirects_fail_closed(response):
    """Provider replies cannot change the destination or exceed the bounded parsing budget."""
    from agent.response.models import ResponseError
    from agent.response.providers.common import request

    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: response)) as http:
        with pytest.raises(ResponseError):
            await request(http, "GET", "https://provider.example/v1/fixed")


async def test_installed_dynamic_sql_matches_explicit_review_without_execution(workspace_settings):
    """Readiness compares reviewed role metadata and never silently installs revocation SQL."""
    import hashlib
    from types import SimpleNamespace

    from agent.validation.models import canonical

    statements = [
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='{{name}}';",
        'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "{{name}}"; DROP ROLE "{{name}}";',
    ]
    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    calls = []

    def handle(request):
        """Return installed role statements as private metadata only."""
        calls.append(request)
        return httpx.Response(200, json={"data": {"revocation_statements": statements}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        adapter = VaultAdapter(settings, http)
        policy = SimpleNamespace(
            dynamic_revocation_review_digest=hashlib.sha256(canonical(statements)).hexdigest()
        )
        assert await adapter.dynamic_readiness(policy) == "provider_state_observed"
        policy.dynamic_revocation_review_digest = "0" * 64
        assert await adapter.dynamic_readiness(policy) != "provider_state_observed"
    assert all(r.method == "GET" and "/roles/" in r.url.path for r in calls)
