"""Observation intake refuses spoofing, changed replays and secret-bearing payloads."""

import json

import pytest
from governance_support import installed, source

from agent.governance.models import GovernanceError, now


def setup(tmp_path):
    s = installed(tmp_path)
    s.configure((source(),), 1)
    return s


def body(**changes):
    return json.dumps(
        {"id": "event-1", "object": "unknown-object", "kind": "unknown", "time": now().isoformat()}
        | changes
    ).encode()


def claims(**changes):
    t = int(now().timestamp())
    return {
        "iss": "https://id.example",
        "sub": "relay",
        "aud": "discovery",
        "iat": t,
        "exp": t + 60,
        "scope": "governance:observe",
    } | changes


def test_duplicate_is_durable_without_authority(tmp_path):
    from agent.governance.source import ingest

    s = setup(tmp_path)
    raw = body()
    first = ingest(s, "fixture", raw, claims())
    second = ingest(s, "fixture", raw, claims())
    assert second == first | {"disposition": "duplicate"}
    state = s.read()
    assert len(state.observations) == len(state.candidates) == 1
    assert state.candidates[0].binding is None
    assert not state.registrations and not state.credentials
    with pytest.raises(GovernanceError, match="replay_conflict"):
        ingest(s, "fixture", body(object="changed"), claims())


def test_relay_scope_is_separate(tmp_path):
    from agent.governance.source import ingest

    s = setup(tmp_path)
    for change in (
        {"iss": "https://other.example"},
        {"sub": "owner"},
        {"aud": "response"},
        {"scope": "response:submit"},
        {"iat": True},
        {"exp": int(now().timestamp()) + 301},
    ):
        with pytest.raises(GovernanceError):
            ingest(s, "fixture", body(), claims(**change))
    assert not s.read().observations


def test_secret_fields_rejected_even_if_not_projected(tmp_path):
    from agent.governance.source import ingest

    s = setup(tmp_path)
    for raw in (
        body(access_token="canary"),
        body(unused={"password": "canary"}),
        b'{"id":"one","id":"two"}',
        b'"' + b"x" * 65536 + b'"',
    ):
        with pytest.raises(GovernanceError):
            ingest(s, "fixture", raw, claims())
    assert not s.read().observations


def test_managed_first_is_not_unknown_discovery(tmp_path):
    from agent.governance.source import ingest

    s = setup(tmp_path)
    with pytest.raises(GovernanceError, match="source_invalid"):
        ingest(s, "fixture", body(kind="managed"), claims())
    assert not s.read().candidates


def test_depth_scalar_and_old_event_bounds(tmp_path):
    from datetime import timedelta

    from agent.governance.source import ingest

    s = setup(tmp_path)
    nested = "value"
    for _ in range(9):
        nested = {"child": nested}
    for raw in (
        body(unused=nested),
        body(unused=list(range(129))),
        body(time=(now() - timedelta(seconds=301)).isoformat()),
    ):
        with pytest.raises(GovernanceError):
            ingest(s, "fixture", raw, claims())
    assert not s.read().observations


def test_stale_authenticated_source_cannot_commit(tmp_path):
    from agent.governance.source import ingest

    s = setup(tmp_path)
    old = source()
    changed = old.model_copy(update={"generation": 2})
    s.configure((changed,), s.read().revision)
    with pytest.raises(GovernanceError, match="configuration_changed"):
        ingest(s, "fixture", body(), claims(), expected_source=old)
