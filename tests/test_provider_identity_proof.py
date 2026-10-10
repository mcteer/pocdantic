"""Negative issuance probes never weaken production acquisition uncertainty."""

import os
from uuid import uuid4

import httpx
from provider_support import activate, enrollment
from response_support import enrolled, principal

from agent.recovery.store import RecoveryStore


async def test_definitive_denial_can_close_only_probe(tmp_path, recovery_settings):
    """Authenticated empty 403 closes a probe without inventing an audit receipt."""
    from agent.response.providers.proof import acquisition_probe

    recovery = RecoveryStore(recovery_settings, project=tmp_path)
    recovery.initialize()
    store = enrolled(recovery_settings, tmp_path, recovery=recovery)
    activate(store, enrollment(store))
    run, fd = store.register(uuid4(), uuid4(), principal(recovery_settings))
    try:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(403, json={"errors": ["permission denied"]})
            )
        ) as http:
            item, _ = await acquisition_probe(
                store, run.ownership(), http, "fixture", scenario="same_jwt"
            )
        assert item.state == "denied_no_issuance"
        assert recovery.read().attempts == ()
    finally:
        store.finish(run)
        os.close(fd)


async def test_malformed_denial_remains_uncertain(tmp_path, recovery_settings):
    """Malformed rejection cannot prove that no credential was issued."""
    from agent.response.providers.proof import acquisition_probe

    recovery = RecoveryStore(recovery_settings, project=tmp_path)
    recovery.initialize()
    store = enrolled(recovery_settings, tmp_path, recovery=recovery)
    activate(store, enrollment(store))
    run, fd = store.register(uuid4(), uuid4(), principal(recovery_settings))
    try:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(403, content=b"invalid"))
        ) as http:
            item, _ = await acquisition_probe(
                store, run.ownership(), http, "fixture", scenario="same_jwt"
            )
        assert item.state == "uncertain"
    finally:
        store.finish(run)
        os.close(fd)


async def test_successful_probe_is_adopted_idempotently(tmp_path, recovery_settings):
    """A durable handle joins exact recovery once, preserving original identity/times."""
    from agent.response.providers.proof import acquisition_probe

    recovery = RecoveryStore(recovery_settings, project=tmp_path)
    recovery.initialize()
    store = enrolled(recovery_settings, tmp_path, recovery=recovery)
    activate(store, enrollment(store))
    run, fd = store.register(uuid4(), uuid4(), principal(recovery_settings))
    path = recovery_settings.vault_read_path
    try:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    200,
                    json={
                        "lease_id": path + "/fixture",
                        "lease_duration": 60,
                        "data": {"username": "fixture", "password": "fixture"},
                    },
                )
            )
        ) as http:
            probe, _ = await acquisition_probe(
                store, run.ownership(), http, "fixture", scenario="same_jwt"
            )
        assert probe.state == "cleanup_pending"
        original = recovery.read().attempts[0]
        with recovery.effect() as owner:
            adopted = recovery.adopt_probe(owner, store, probe.acquisition_id)
        assert original == adopted
        assert adopted.operation_id == probe.acquisition_id and adopted.ownership == probe.ownership
        assert (
            adopted.created_at == probe.created_at
            and adopted.acquisition_submitted_at == probe.submitted_at
        )
        assert len(recovery.read().attempts) == 1
    finally:
        store.finish(run)
        os.close(fd)


async def test_oauth_denial_with_credential_material_is_not_definitive(workspace_settings):
    """An HTTP denial carrying any credential-shaped response stays uncertain."""
    import httpx
    import pytest

    from agent.oauth import OAuthClient
    from agent.probe import oauth_config
    from agent.security import SecurityError

    settings = workspace_settings.model_copy(
        update={"oauth_token_endpoint": "https://id.example/token"}
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                403, json={"error": "access_denied", "access_token": "synthetic-material"}
            )
        )
    ) as http:
        client = OAuthClient(oauth_config(settings), http)
        with pytest.raises(SecurityError):
            await client.client_credentials()
        assert client.definitive_token_denial is False
