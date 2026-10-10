"""Explicit recovery preserves history and rejects stale or uncertain authority."""

import pytest
from test_provider_worker import planned

from agent.response.models import ResponseError


def test_retry_never_resets_predecessor(tmp_path, workspace_settings):
    """A definitive failure can create a linked attempt while original history remains."""
    from agent.response.providers.worker import change, retry

    store, incident = planned(workspace_settings, tmp_path)
    old = store.read().provider_actions[0]
    change(store, old.action_id, state="denied", reason="provider_denied")
    revision = store.read().revision
    new = retry(store, old.action_id, revision, "fixture-operator")
    assert new.predecessor == old.action_id and new.state == "planned"
    assert store.read().provider_actions[0].state == "denied"
    assert store.read().provider_plans[0].action_ids == (new.action_id,)
    with pytest.raises(ResponseError, match="revision_conflict"):
        retry(store, new.action_id, revision, "fixture-operator")


def test_uncertain_without_review_cannot_retry(tmp_path, workspace_settings):
    """Ambiguous mutation requires independent disposition, not a fresh UUID alone."""
    from agent.response.providers.worker import change, retry

    store, incident = planned(workspace_settings, tmp_path)
    old = store.read().provider_actions[0]
    change(store, old.action_id, state="uncertain", reason="provider_uncertain")
    with pytest.raises(ResponseError, match="provider_retry_review"):
        retry(store, old.action_id, store.read().revision, "fixture-operator")


async def test_retry_reads_current_state_and_avoids_repeat(tmp_path, workspace_settings):
    """A confirmed absent registration is reconciled, never deleted again."""
    import httpx
    from pydantic import SecretStr

    from agent.response.providers.worker import change, reviewed_retry

    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    store, _ = planned(settings, tmp_path)
    action = store.read().provider_actions[0]
    change(store, action.action_id, state="uncertain", reason="provider_uncertain")
    calls = []

    def handle(request):
        """Expose metadata only; a mutation is a regression."""
        calls.append(request.method)
        return httpx.Response(404, json={"errors": ["absent"]})

    result = await reviewed_retry(
        store,
        action.action_id,
        store.read().revision,
        "operator",
        transport=httpx.MockTransport(handle),
    )
    assert calls == ["GET"] and result.state == "reconciled"
    assert len(store.read().provider_actions) == 1


def test_same_actor_lifetime_restoration_waits_complete_bound(tmp_path, workspace_settings):
    """A short observed JWT does not justify restoring minting before maximum lifetime expires."""
    from datetime import timedelta

    from agent.recovery.models import now
    from agent.response.providers.models import Observation
    from agent.response.providers.proof import lifetime_safe
    from agent.validation.models import implementation_revision

    store, incident = planned(workspace_settings, tmp_path)
    state = store.read()
    action = state.provider_actions[0]
    policy = state.enrollment.model_copy(update={"max_token_lifetime_seconds": 600})
    lifetime = policy.max_token_lifetime_seconds

    def observed(seconds):
        """Create an independently reviewed cessation attestation for this exact actor."""
        return Observation(
            installation_id=state.installation_id,
            environment_digest=state.environment_digest,
            implementation_digest=implementation_revision(),
            enrollment_digest=action.enrollment_digest,
            incident_id=incident.incident_id,
            action_id=action.action_id,
            binding_id=action.binding.binding_id,
            resource_generation=action.binding.generation,
            path="old_credential_safety",
            result="proven",
            source="native_evidence",
            source_digest="2" * 64,
            reviewer="reviewer",
            reviewed_at=now(),
            minting_stopped_at=now() - timedelta(seconds=seconds),
            maximum_lifetime_seconds=lifetime,
        )

    for seconds, safe in ((lifetime, False), (lifetime + 31, True)):
        updated = type(action).model_validate(
            action.model_dump() | {"observations": (observed(seconds),)}
        )
        assert lifetime_safe(updated, policy) is safe


def test_release_needs_complete_hold_set_and_admits_only_fresh_roots(tmp_path, workspace_settings):
    """Reviewed lifetime-bound proof releases all concurrent holds while old roots stay terminal."""
    import os
    from datetime import timedelta
    from uuid import uuid4

    from provider_support import activate, enrollment, provider_store, resource
    from response_support import principal, signal

    from agent.recovery.models import now
    from agent.response.coordinator import Coordinator
    from agent.response.providers.models import Observation, Rule
    from agent.validation.models import implementation_revision

    store = provider_store(workspace_settings, tmp_path)
    binding = resource(workspace_settings)
    rule = Rule(
        alias="release-rule",
        actions=("block_registration",),
        bindings=(binding.binding_id,),
        required=frozenset({"block_registration"}),
    )
    activate(
        store, enrollment(store, bindings=(binding,), rules=(rule,), max_token_lifetime_seconds=600)
    )
    old, owner = store.register(uuid4(), uuid4(), principal(workspace_settings))
    coordinator = Coordinator(store)
    incidents = [
        coordinator.submit(signal(workspace_settings, event=event))[0]
        for event in ("hold-one", "hold-two")
    ]
    store.finish(old)
    os.close(owner)
    state = store.read()
    action = state.provider_actions[0]
    stamp = now()
    observations = []
    for path in ("registration", "same_jwt", "fresh_issuance", "old_credential_safety"):
        observations.append(
            Observation(
                installation_id=state.installation_id,
                environment_digest=state.environment_digest,
                implementation_digest=implementation_revision(),
                enrollment_digest=action.enrollment_digest,
                incident_id=incidents[0].incident_id,
                action_id=action.action_id,
                binding_id=binding.binding_id,
                resource_generation=1,
                path=path,
                result="proven",
                source="native_evidence",
                source_digest="3" * 64,
                reviewer="reviewer",
                reviewed_at=stamp,
                observed_at=stamp - timedelta(seconds=620)
                if path in {"same_jwt", "fresh_issuance"}
                else stamp,
                credential_digest="4" * 64 if path == "same_jwt" else None,
                credential_expires_at=stamp - timedelta(seconds=31) if path == "same_jwt" else None,
                before_succeeded=True,
                healthy_control=True,
                minting_stopped_at=stamp - timedelta(seconds=631)
                if path == "old_credential_safety"
                else None,
                maximum_lifetime_seconds=600 if path == "old_credential_safety" else None,
            )
        )
    with store.transaction() as (fd, current):
        store.commit(
            fd,
            current,
            provider_actions=(
                type(action).model_validate(
                    action.model_dump()
                    | {"state": "acknowledged", "observations": tuple(observations)}
                ),
            ),
        )
    for incident in incidents:
        coordinator.reconcile(incident.incident_id)
    with pytest.raises(ResponseError, match="release_unsafe"):
        coordinator.release(
            workspace_settings.workload_definition,
            (incidents[0].incident_id,),
            store.read().revision,
            "reviewer",
        )
    coordinator.release(
        workspace_settings.workload_definition,
        tuple(i.incident_id for i in incidents),
        store.read().revision,
        "reviewer",
    )
    with pytest.raises(ResponseError, match="contained"):
        store.check(old)
    fresh, owner = store.register(uuid4(), uuid4(), principal(workspace_settings))
    try:
        assert fresh.generation == store.read().generation and fresh.generation > old.generation
        store.check(fresh)
    finally:
        store.finish(fresh)
        os.close(owner)
