"""Retention closure and concurrent authority fences preserve unresolved provider work."""

from datetime import timedelta
from uuid import uuid4

from provider_support import provider_store, resource
from response_support import signal

from agent.recovery.models import now
from agent.response.coordinator import Coordinator
from agent.response.providers.models import IncidentPlan, ProviderAction


def aged_incident(store, state):
    """Construct a settled old incident with one advisory action and no remaining hold."""
    incident, _ = Coordinator(store).submit(signal(store.settings))
    old = now() - timedelta(days=31)
    incident = type(incident).model_validate(
        incident.model_dump()
        | {"phase": "settled", "received_at": old, "contained_at": old, "source_at": old}
    )
    action = ProviderAction(
        kind="notify_teams",
        binding=resource(store.settings, "teams"),
        enrollment_digest="1" * 64,
        incidents=(incident.incident_id,),
        required=False,
        notice_id=uuid4(),
        state=state,
        created_at=old,
    )
    plan = IncidentPlan(
        incident_id=incident.incident_id, enrollment_digest="1" * 64, action_ids=(action.action_id,)
    )
    with store.transaction() as (fd, journal):
        store.commit(
            fd,
            journal,
            incidents=(incident,),
            holds=(),
            provider_actions=(action,),
            provider_plans=(plan,),
        )
    return incident


def test_settled_provider_records_age_out(tmp_path, workspace_settings):
    """Resolved advisory records age out together after the full retention period."""
    store = provider_store(workspace_settings, tmp_path)
    aged_incident(store, "acknowledged")
    store.prune()
    state = store.read()
    assert not state.incidents and not state.provider_actions and not state.provider_plans


def test_uncertain_provider_records_remain_pinned(tmp_path, workspace_settings):
    """Age never clears a possibly submitted notice or its incident correlation."""
    store = provider_store(workspace_settings, tmp_path)
    incident = aged_incident(store, "uncertain")
    store.prune()
    state = store.read()
    assert state.incidents[0].incident_id == incident.incident_id
    assert state.provider_actions[0].state == "uncertain"


def test_recent_completion_retains_old_incident(tmp_path, workspace_settings):
    """A long-running incident gets thirty days of retention after its late completion."""
    store = provider_store(workspace_settings, tmp_path)
    incident = aged_incident(store, "acknowledged")
    with store.transaction() as (fd, state):
        action = state.provider_actions[0]
        completed = type(action).model_validate(action.model_dump() | {"completed_at": now()})
        store.commit(fd, state, provider_actions=(completed,))
    store.prune()
    assert store.read().incidents[0].incident_id == incident.incident_id


async def test_retry_readback_intake_race_rejects_decision(tmp_path, workspace_settings):
    """A newer hold committed during network readback fences out the old retry decision."""
    import httpx
    import pytest
    from pydantic import SecretStr
    from test_provider_worker import planned

    from agent.response.models import ResponseError
    from agent.response.providers.worker import change, reviewed_retry

    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    store, _ = planned(settings, tmp_path)
    action = store.read().provider_actions[0]
    change(store, action.action_id, state="denied")

    def handle(request):
        """Independent intake remains fast while the effect owner reads metadata."""
        Coordinator(store).submit(signal(settings, event="concurrent-hold"))
        return httpx.Response(200, json={"data": {"id": action.binding.native_id}})

    with pytest.raises(ResponseError, match="revision_conflict"):
        await reviewed_retry(
            store,
            action.action_id,
            store.read().revision,
            "reviewer",
            transport=httpx.MockTransport(handle),
        )
    assert len(store.read().provider_actions) == 1
    assert len(store.read().holds[0].incident_ids) == 2


def test_effect_lock_does_not_block_intake(tmp_path, workspace_settings):
    """Short containment commits do not wait for provider ownership or network completion."""
    import time

    store = provider_store(workspace_settings, tmp_path)
    with store.effect():
        started = time.monotonic()
        incident, _ = Coordinator(store).submit(signal(workspace_settings))
        assert time.monotonic() - started < 2
        assert store.read().holds[0].incident_ids == (incident.incident_id,)


def test_worker_owner_fences_enrollment_and_migration(tmp_path, workspace_settings):
    """Offline authority changes refuse a live service owner rather than bypassing its lock."""
    import pytest
    from provider_support import activate, enrollment

    from agent.response.models import ResponseError

    store = provider_store(workspace_settings, tmp_path)
    with store._lock("worker.lock"):
        with pytest.raises(ResponseError):
            activate(store, enrollment(store))
        # Idempotent v2 migration needs no rewrite, so it may safely report current.
        assert store.migrate() is False
    assert store.read().enrollment is None


def test_plan_capacity_rejects_intake_before_hold(tmp_path, workspace_settings):
    """Seventeen exact controls cannot partially commit containment or provider dispatch."""
    import pytest
    from provider_support import activate, enrollment

    from agent.response.models import ResponseError
    from agent.response.providers.models import Rule

    store = provider_store(workspace_settings, tmp_path)
    bindings = tuple(
        resource(workspace_settings, alias=f"registration-{i}", native_id=f"native-{i}")
        for i in range(17)
    )
    rule = Rule(
        alias="capacity-rule",
        actions=("block_registration",),
        bindings=tuple(b.binding_id for b in bindings[:16]),
    )
    second = Rule(
        alias="overflow-rule", actions=("block_registration",), bindings=(bindings[-1].binding_id,)
    )
    activate(store, enrollment(store, bindings=bindings, rules=(rule, second)))
    with pytest.raises(ResponseError, match="provider_capacity"):
        Coordinator(store).submit(signal(workspace_settings))
    assert not store.read().incidents and not store.read().holds


def test_accepted_observation_consumes_reserved_capacity(tmp_path, workspace_settings, monkeypatch):
    """Result persistence spends its reserved capacity near the snapshot bound."""
    from test_provider_proof import setup

    import agent.response.store as storage
    from agent.response.providers.journal import result_reservation
    from agent.response.providers.proof import import_observation
    from agent.validation.models import canonical

    store = provider_store(workspace_settings, tmp_path)
    observation = setup(store)
    state = store.read()
    reserved = sum(
        max(0, storage.RESERVE - len(canonical(i.actions)))
        for i in state.incidents
        if i.phase != "settled"
    ) + result_reservation(state)
    monkeypatch.setattr(storage, "MAX_BYTES", len(canonical(state)) + reserved + 128)
    assert import_observation(store, canonical(observation), state.revision)
    assert store.read().provider_actions[0].observations == (observation,)
