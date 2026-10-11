"""Multi-action durable incident retains partial outcomes and never replays lost replies."""

import httpx
from provider_support import activate, enrollment, provider_store, resource
from pydantic import SecretStr
from response_support import signal

from agent.response.coordinator import Coordinator
from agent.response.providers.models import Rule
from agent.response.providers.report import controls
from agent.response.providers.worker import Worker


async def test_partial_incident_preserves_holds_and_no_replay(tmp_path, workspace_settings):
    "Compose real intake, worker and report with success, uncertainty and notification acceptance."
    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    store = provider_store(settings, tmp_path)
    one = resource(settings)
    two = resource(settings, alias="second", native_id="resource-two")
    teams = resource(settings, "teams", alias="notice")
    rule = Rule(
        alias="joined",
        actions=("block_registration", "notify_teams"),
        bindings=(one.binding_id, two.binding_id, teams.binding_id),
        required=frozenset({"block_registration"}),
    )
    activate(store, enrollment(store, bindings=(one, two, teams), rules=(rule,)))
    coordinator = Coordinator(store)
    event = signal(settings)
    incident, _ = coordinator.submit(event)
    calls = []

    def provider(request):
        """Lose one reply after possible application, acknowledge the other and accept a notice."""
        calls.append((request.method, request.url.path))
        if "resource-two" in request.url.path:
            raise httpx.ReadError("PRIVATE_CANARY", request=request)
        return httpx.Response(202 if request.url.path == "/workflow" else 204)

    worker = Worker(store, transport=httpx.MockTransport(provider))
    await worker.process(incident.incident_id)
    count = len(calls)
    coordinator.submit(event)
    worker.normalize()
    await worker.process(incident.incident_id)
    assert len(calls) == count == 3
    state = store.read()
    assert state.holds
    rows = controls(state, incident.incident_id)
    assert {r["state"] for r in rows if r["kind"] == "block_registration"} == {
        "acknowledged",
        "uncertain",
    }
    notification = next(r for r in rows if r["kind"] == "notify_teams")
    assert notification["reason_code"] == "notification_accepted"
    assert all(value != "proven" for value in notification["paths"].values())
    assert "PRIVATE_CANARY" not in str(rows)
