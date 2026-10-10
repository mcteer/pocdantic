"""Strict signal and authority models reject coercion and secret-bearing extensions."""

from uuid import uuid4

import pytest
from pydantic import ValidationError

from agent.recovery.models import now
from agent.response.models import ResponseAction, RiskSignal, SourcePolicy


def valid():
    return dict(
        event_id="event-001",
        occurred_at=now(),
        reason="suspected_compromise",
        target={"kind": "definition", "workload_definition": "demo-agent"},
    )


@pytest.mark.parametrize(
    "changes",
    [
        dict(schema_version=True),
        dict(schema_version="1"),
        dict(event_id=""),
        dict(event_id="a" * 129),
        dict(reason="rotate"),
        dict(token="private"),
        dict(occurred_at="2026-01-01T01:00:00+01:00"),
        dict(target={"kind": "child", "run": str(uuid4())}),
    ],
)
def test_signal_rejects(changes):
    with pytest.raises(ValidationError):
        RiskSignal(**(valid() | changes))


def test_modes_and_private_representations():
    policy = dict(
        workload_definition="demo-agent", environment_digest="a" * 64, issuer="https://id.example"
    )
    local = SourcePolicy(**policy)
    assert local.audience is None and local.sources == ()
    for change in [
        dict(automatic_cleanup=1),
        dict(intake_mode="relay"),
        dict(audience="ordinary"),
        dict(secret="x"),
    ]:
        with pytest.raises(ValidationError):
            SourcePolicy(**(policy | change))
    assert "https://" not in repr(local)
    with pytest.raises(ValidationError):
        ResponseAction(kind="revoke_prefix", target_id=uuid4())


@pytest.mark.parametrize(
    "change",
    [
        {"alias": "local-operator"},
        {"alias": "x" * 33},
        {"subject": ""},
        {"subject": "x" * 257},
        {"allowed_scopes": []},
        {"allowed_scopes": ["native_user"]},
        {"issuer": ""},
    ],
)
def test_source_bounds(change):
    """Private mapping cannot broaden allowed targets or collide with OS operator input."""
    from agent.response.models import Source

    value = {
        "alias": "relay-one",
        "issuer": "https://id.example",
        "subject": "relay",
        "allowed_scopes": ["root_run"],
    }
    with pytest.raises(ValidationError):
        Source.model_validate(value | change)


@pytest.mark.parametrize(
    "change",
    [
        {"generation": True},
        {"generation": 0},
        {"subject": ""},
        {"root_run_id": "child"},
        {"workload_definition": "https://provider.example"},
        {"secret": "canary"},
    ],
)
def test_bound_ownership_and_private_repr(change):
    """Acquisition ownership accepts only immutable, host-derived bounded context."""
    from agent.recovery.models import BoundOwnership

    value = {
        "root_run_id": uuid4(),
        "request_id": uuid4(),
        "generation": 1,
        "workload_definition": "demo-agent",
        "issuer": "https://id.example",
        "subject": "private-canary",
    }
    assert "private-canary" not in repr(BoundOwnership.model_validate(value))
    with pytest.raises(ValidationError):
        BoundOwnership.model_validate(value | change)


def test_anchor_mode_and_public_projection_bounds():
    """Missing configured state cannot become a no-database success projection."""
    from agent.response.models import PublicSummary, ResponseAnchor

    for value in (
        {"recovery_mode": "configured"},
        {"recovery_mode": "not_configured", "recovery_installation_id": uuid4()},
    ):
        with pytest.raises(ValidationError):
            ResponseAnchor(installation_id=uuid4(), **value)
    public = {
        "incident_id": uuid4(),
        "scope": "root_run",
        "phase": "partial",
        "contained": True,
        "cleanup": "pending",
        "reason_code": "cleanup_uncertain",
        "next_action": "recover_exact_lease",
    }
    for change in (
        {"contained": 1},
        {"next_action": "arbitrary-canary"},
        {"source": "canary"},
        {"scope": "native_user"},
        {"reason_code": "provider-text"},
    ):
        with pytest.raises(ValidationError):
            PublicSummary.model_validate(public | change)
    for change in (
        {"status": "queued"},
        {"kind": "revoke_prefix"},
        {"reason_code": "provider-text"},
    ):
        with pytest.raises(ValidationError):
            ResponseAction.model_validate({"target_id": uuid4(), "kind": "revoke_exact"} | change)


def test_journal_queue_and_record_bounds(workspace_settings):
    """Bound queues, retained records and action reservations cannot grow without limit."""
    from response_support import binding

    from agent.response.models import DefinitionHold, Incident, ResponseJournal

    root = binding(workspace_settings)
    state = {"installation_id": uuid4(), "environment_digest": "a" * 64, "policy_digest": "b" * 64}
    for changes in (
        {"runs": (root,) * 1001},
        {"root_holds": (root.root_run_id,) * 1001},
        {"revision": True},
        {"generation": 0},
    ):
        with pytest.raises(ValidationError):
            ResponseJournal.model_validate(state | changes)
    incidents = []
    for n in range(17):
        key = uuid4()
        item = Incident(
            incident_id=key,
            source="local-operator",
            event_id=f"event-{n}",
            source_at=now(),
            payload_digest="a" * 64,
            policy_digest="b" * 64,
            target={"kind": "definition", "workload_definition": "demo-agent"},
            actions=[ResponseAction(kind="cancel_local", target_id=key)],
        )
        incidents.append(item)
    with pytest.raises(ValidationError):
        ResponseJournal.model_validate(state | {"incidents": incidents})
    item = incidents[0]
    for changes in (
        {"actions": []},
        {"actions": item.actions * 102},
        {"cancel_ms": -1},
        {"worker_ms": True},
        {"cleanup_ms": 1.5},
        {"phase": "released"},
        {"revision": "1"},
    ):
        with pytest.raises(ValidationError):
            Incident.model_validate(item.model_dump() | changes)
    with pytest.raises(ValidationError):
        DefinitionHold(
            workload_definition="demo-agent", generation=1, incident_ids=(uuid4(),) * 1001
        )


def test_relay_policy_bound_and_ambiguous_mappings():
    """Source counts and identity uniqueness are enforced independently of JWT validity."""
    sources = [
        {
            "alias": f"relay-{n}",
            "issuer": "https://id.example",
            "subject": str(n),
            "allowed_scopes": ["definition"],
        }
        for n in range(17)
    ]
    base = {
        "intake_mode": "relay",
        "sources": sources[:1],
        "audience": "response",
        "workload_definition": "demo-agent",
        "environment_digest": "a" * 64,
        "issuer": "https://id.example",
    }
    for changes in (
        {"sources": sources},
        {"sources": sources[:1] * 2},
        {"audience": "x" * 257},
        {"environment_digest": "A" * 64},
        {"sources": [sources[0] | {"issuer": "https://foreign.example"}]},
    ):
        with pytest.raises(ValidationError):
            SourcePolicy.model_validate(base | changes)
