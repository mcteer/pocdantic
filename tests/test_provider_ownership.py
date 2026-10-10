"""Actor binding and subject holds keep human and workload identities distinct."""

import os
from uuid import uuid4

import pytest
from provider_support import activate, enrollment, provider_store, resource
from response_support import principal, signal

from agent.response.coordinator import Coordinator
from agent.response.models import ResponseError
from agent.response.providers.models import Rule


def test_verified_actor_capture_is_exact(tmp_path, workspace_settings):
    """Only the enrolled workload actor may be captured; human ownership is unchanged."""
    store = provider_store(workspace_settings, tmp_path)
    binding = resource(workspace_settings)
    activate(store, enrollment(store, bindings=(binding,)))
    run, fd = store.register(uuid4(), uuid4(), principal(workspace_settings))
    try:
        ownership = run.ownership()
        with pytest.raises(ResponseError, match="mapping_missing"):
            store.bind_actor(run, binding.actor_issuer, "wrong")
        store.bind_actor(run, binding.actor_issuer, binding.actor_subject)
        current = store.read().runs[0]
        assert current.ownership() == ownership
        assert current.subject != current.actor_subject
        store.check(run)
    finally:
        store.finish(run)
        os.close(fd)


def test_user_hold_is_atomic_with_incident(tmp_path, workspace_settings):
    """The enrolled user hold is durable when intake returns, before network work."""
    store = provider_store(workspace_settings, tmp_path)
    user = resource(workspace_settings, "user")
    rule = Rule(
        alias="suspend-rule",
        actions=("suspend_user",),
        bindings=(user.binding_id,),
        required=frozenset({"suspend_user"}),
    )
    activate(store, enrollment(store, bindings=(user,), rules=(rule,)))
    incident, _ = Coordinator(store).submit(signal(workspace_settings))
    assert store.subject_held(user.user_issuer, user.user_subject)
    assert store.read().subject_holds[0].incident_id == incident.incident_id


async def test_native_login_lost_reply_preserves_unknown_accessor(tmp_path, workspace_settings):
    """A provider may create a service token before transport loss; inventory stays open."""
    import httpx
    from pydantic import SecretStr

    from agent.response.guard import RootGuard
    from agent.vault import VaultClient

    settings = workspace_settings.model_copy(update={"vault_addr": "https://provider.example"})
    store = provider_store(settings, tmp_path)
    registration = resource(settings)
    activate(
        store,
        enrollment(
            store,
            bindings=(registration,),
            native_login_mount="jwt",
            native_login_role="exclusive",
            native_exclusive_tree=True,
        ),
    )
    run, fd = store.register(uuid4(), uuid4(), principal(settings))
    store.bind_actor(run, registration.actor_issuer, registration.actor_subject)

    def lost(request):
        """Observe durable submission before simulating successful issuance/lost reply."""
        assert store.read().native_acquisitions[0].state == "submitted"
        raise httpx.ReadError("fixture", request=request)

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(lost)) as http:
            client = VaultClient(
                settings.vault_addr, "", http, credential_guard=RootGuard(store, run, fd)
            )
            from agent.security import SecurityError

            with pytest.raises(SecurityError):
                await client.workload_login("jwt", "exclusive", SecretStr("fixture"))
        item = store.read().native_acquisitions[0]
        assert item.state == "uncertain" and item.binding is None
    finally:
        store.finish(run)
        os.close(fd)


async def test_native_accessor_bound_before_result_exposure(tmp_path, workspace_settings):
    """A successful login returns only after exact trusted accessor ownership is durable."""
    import httpx
    from pydantic import SecretStr

    from agent.response.guard import RootGuard
    from agent.vault import VaultClient

    settings = workspace_settings.model_copy(update={"vault_addr": "https://provider.example"})
    store = provider_store(settings, tmp_path)
    registration = resource(settings)
    activate(
        store,
        enrollment(
            store,
            bindings=(registration,),
            native_login_mount="jwt",
            native_login_role="exclusive",
            native_exclusive_tree=True,
        ),
    )
    run, fd = store.register(uuid4(), uuid4(), principal(settings))
    store.bind_actor(run, registration.actor_issuer, registration.actor_subject)

    def handle(request):
        """Inspect durable submitted intent before returning synthetic service authority."""
        assert store.read().native_acquisitions[0].state == "submitted"
        return httpx.Response(
            200,
            json={
                "auth": {
                    "client_token": "fixture-token",
                    "accessor": "fixture-accessor",
                    "token_type": "service",
                }
            },
        )

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
            result = await VaultClient(
                settings.vault_addr, "", http, credential_guard=RootGuard(store, run, fd)
            ).workload_login("jwt", "exclusive", SecretStr("fixture-jwt"))
        acquisition = store.read().native_acquisitions[0]
        assert acquisition.state == "bound" and acquisition.binding.ownership == run.ownership()
        assert result["auth"]["accessor"] == acquisition.binding.native_id
        assert "fixture-token" not in (store.root / "state.json").read_text()
    finally:
        store.finish(run)
        os.close(fd)
