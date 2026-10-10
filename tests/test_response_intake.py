"""Durable containment precedes acceptance; duplicates never create more actions."""

from datetime import timedelta

import pytest
from response_support import enrolled, signal

from agent.response.coordinator import Coordinator, parse_signal
from agent.response.models import ResponseError


def test_accept_duplicate_conflict(tmp_path, workspace_settings):
    store = enrolled(workspace_settings, tmp_path)
    worker = Coordinator(store)
    event = signal(workspace_settings)
    item, new = worker.submit(event)
    assert new and store.read().holds
    same, new = worker.submit(event)
    assert not new and same.incident_id == item.incident_id
    with pytest.raises(ResponseError, match="event_conflict"):
        worker.submit(event.model_copy(update={"reason": "policy_violation"}))
    assert len(store.read().incidents) == 1


@pytest.mark.parametrize(
    "raw", [b'{"schema_version":1,"schema_version":1}', b" " * 16385, b"[[[[[[[[[1]]]]]]]]]"]
)
def test_strict_json(raw):
    with pytest.raises(ResponseError, match="signal_invalid"):
        parse_signal(raw)


def test_stale_unknown_zero_holds(tmp_path, workspace_settings):
    store = enrolled(workspace_settings, tmp_path)
    worker = Coordinator(store)
    event = signal(workspace_settings)
    with pytest.raises(ResponseError, match="signal_stale"):
        worker.submit(
            event.model_copy(update={"occurred_at": event.occurred_at - timedelta(seconds=301)})
        )
    assert store.read().incidents == ()


async def test_relay_api_persists_before_ack_and_isolates_sources(tmp_path, workspace_settings):
    """API acceptance is durable, bounded and distinct from browser or source-ID knowledge."""
    from types import SimpleNamespace

    import httpx

    from agent.response.api import create_response_app
    from agent.response.models import SourcePolicy
    from agent.response.store import ResponseStore
    from agent.validation.models import canonical

    store = ResponseStore(workspace_settings, project=tmp_path)
    store.prepare()
    policy = SourcePolicy.model_validate(
        store.policy().model_dump()
        | {
            "intake_mode": "relay",
            "audience": "response",
            "sources": [
                {
                    "alias": "relay-one",
                    "issuer": workspace_settings.oauth_issuer,
                    "subject": "one",
                    "allowed_scopes": ["definition"],
                },
                {
                    "alias": "relay-two",
                    "issuer": workspace_settings.oauth_issuer,
                    "subject": "two",
                    "allowed_scopes": ["definition"],
                },
            ],
        }
    )
    (store.root / "policy.json").write_bytes(canonical(policy))
    store.initialize()
    app = create_response_app(workspace_settings, store=store)

    async def verify(token):
        """Select a test source; cryptographic negative cases are exercised separately."""
        return policy.sources[0 if token.get_secret_value() == "one" else 1]

    app.state.auth = SimpleNamespace(verify=verify)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as http:
        headers = {"Authorization": "Bearer one", "Content-Type": "application/json"}
        event = signal(workspace_settings)
        response = await http.post("/response/incidents", content=canonical(event), headers=headers)
        assert response.status_code == 202
        incident = response.json()["incident_id"]
        assert store.read().holds and len(store.read().incidents) == 1
        duplicate = await http.post(
            "/response/incidents", content=canonical(event), headers=headers
        )
        assert duplicate.status_code == 200 and duplicate.json()["incident_id"] == incident
        foreign = await http.get(
            "/response/incidents/" + incident, headers={"Authorization": "Bearer two"}
        )
        assert foreign.status_code == 404 and incident not in foreign.text
        oversized = await http.post("/response/incidents", content=b"x" * 16385, headers=headers)
        assert oversized.status_code == 413 and len(store.read().incidents) == 1
        cookie_only = await http.post(
            "/response/incidents",
            content=canonical(event),
            headers={"Cookie": "agent_workspace=canary"},
        )
        assert cookie_only.status_code == 403


def test_retained_duplicate_precedes_freshness(tmp_path, workspace_settings, monkeypatch):
    """An old accepted payload stays idempotent rather than becoming another action."""
    import agent.response.coordinator as implementation

    store = enrolled(workspace_settings, tmp_path)
    worker = Coordinator(store)
    event = signal(workspace_settings)
    item, _ = worker.submit(event)
    monkeypatch.setattr(implementation, "now", lambda: event.occurred_at + timedelta(seconds=601))
    duplicate, new = worker.submit(event)
    assert not new and duplicate.incident_id == item.incident_id
    assert len(store.read().incidents) == 1


async def test_response_worker_lifetime_is_exclusive(tmp_path, workspace_settings):
    """Only one service owns scheduling, independent of its short control transactions."""
    from agent.response.api import create_response_app

    store = enrolled(workspace_settings, tmp_path)
    first = create_response_app(workspace_settings, store=store)
    second = create_response_app(workspace_settings, store=store)
    async with first.router.lifespan_context(first):
        with pytest.raises(ResponseError, match="response_busy"):
            async with second.router.lifespan_context(second):
                pytest.fail("two response schedulers admitted")
