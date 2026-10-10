"""Durable provider dispatch cannot replay mutations after uncertainty or restart."""

import httpx
import pytest
from provider_support import activate, enrollment, provider_store, resource
from pydantic import SecretStr
from response_support import signal

from agent.response.coordinator import Coordinator
from agent.response.providers.models import Rule


def planned(settings, tmp_path):
    """Create one exact reviewed registration-block action through real intake."""
    store = provider_store(settings, tmp_path)
    binding = resource(settings)
    rule = Rule(
        alias="block-rule",
        actions=("block_registration",),
        bindings=(binding.binding_id,),
        required=frozenset({"block_registration"}),
    )
    activate(store, enrollment(store, bindings=(binding,), rules=(rule,)))
    incident, _ = Coordinator(store).submit(signal(settings))
    return store, incident


async def test_lost_reply_no_automatic_replay(tmp_path, workspace_settings):
    """A server-side commit with a lost reply remains uncertain across restart."""
    from agent.response.providers.worker import Worker

    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    store, incident = planned(settings, tmp_path)
    calls = []

    def lost(request):
        """Acknowledge nothing even though the provider may have applied the request."""
        calls.append(request)
        raise httpx.ReadError("private provider error", request=request)

    worker = Worker(store, transport=httpx.MockTransport(lost))
    await worker.process(incident.incident_id)
    worker.normalize()
    await worker.process(incident.incident_id)
    assert len(calls) == 1
    assert store.read().provider_actions[0].state == "uncertain"
    assert store.read().holds


async def test_budget_sends_no_unfinishable_effect(tmp_path, workspace_settings):
    """Budget exhaustion does not mark an unsubmitted action as applied."""
    from agent.response.providers.worker import Worker

    store, incident = planned(workspace_settings, tmp_path)
    worker = Worker(
        store, transport=httpx.MockTransport(lambda _: pytest.fail("network")), budget=0
    )
    await worker.process(incident.incident_id)
    assert store.read().provider_actions[0].state == "planned"
    assert store.read().holds


async def test_acknowledgment_retains_success_and_monotonic_duration(tmp_path, workspace_settings):
    """A successful dispatch stays acknowledged without claiming credential denial."""
    from agent.response.providers.worker import Worker

    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    store, incident = planned(settings, tmp_path)
    await Worker(store, transport=httpx.MockTransport(lambda _: httpx.Response(204))).process(
        incident.incident_id
    )
    action = store.read().provider_actions[0]
    assert action.state == "acknowledged" and action.attempt_ms is not None
    assert not action.observations


async def test_timeout_after_durable_submission_is_uncertain(
    tmp_path, workspace_settings, monkeypatch
):
    """A network deadline cannot authorize another mutation attempt or clear the hold."""
    from agent.response.providers.worker import Worker

    store, incident = planned(workspace_settings, tmp_path)
    worker = Worker(store)

    async def timed_out(action, **kwargs):
        """Model a request that may have committed before its deadline elapsed."""
        assert store.read().provider_actions[0].state == "submitted"
        raise TimeoutError()

    monkeypatch.setattr(worker, "dispatch", timed_out)
    await worker.process(incident.incident_id)
    await worker.process(incident.incident_id)
    assert store.read().provider_actions[0].state == "uncertain" and store.read().holds
