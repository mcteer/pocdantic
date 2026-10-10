"""Migration preserves existing holds and authority without dispatching providers."""

import os

import pytest
from provider_support import provider_store
from response_support import principal, signal

from agent.response.coordinator import Coordinator
from agent.response.models import ResponseError, ResponseJournal
from agent.validation.models import canonical


def legacy(store):
    """Make a genuine schema-1 fixture by removing only new empty state fields."""
    state = store.read()
    old = {k: v for k, v in state.model_dump().items() if k in ResponseJournal.model_fields}
    old["schema_version"] = 1
    (store.root / "state.json").write_bytes(canonical(ResponseJournal.model_validate(old)))


def test_preserve_and_idempotent_migration(tmp_path, workspace_settings):
    """Old incidents remain held and local-only; old binaries reject new schema."""
    store = provider_store(workspace_settings, tmp_path)
    incident, _ = Coordinator(store).submit(signal(workspace_settings))
    legacy(store)
    unchanged = {p: (store.root / p).read_bytes() for p in ("policy.json", "anchor.json")}
    before = store.read()
    assert store.migrate() is True
    after = store.read()
    assert after.schema_version == 2 and after.holds == before.holds
    assert after.incidents == before.incidents and not after.provider_actions
    assert store.migrate() is False
    assert all((store.root / p).read_bytes() == raw for p, raw in unchanged.items())
    with pytest.raises(ValueError):
        ResponseJournal.model_validate(after.model_dump())
    assert incident.incident_id in after.holds[0].incident_ids


def test_v1_blocks_admission_and_migration_with_owner(tmp_path, workspace_settings):
    """Read-only status remains available; migration cannot bypass a live root owner."""
    from uuid import uuid4

    store = provider_store(workspace_settings, tmp_path)
    run, fd = store.register(uuid4(), uuid4(), principal(workspace_settings))
    legacy(store)
    with pytest.raises(ResponseError):
        store.register(uuid4(), uuid4(), principal(workspace_settings))
    with pytest.raises(ResponseError):
        store.migrate()
    with pytest.raises(ResponseError, match="response_schema_migration_required"):
        store.finish(run)
    os.close(fd)
    assert store.migrate()
    store.finish(run)


def test_failed_migration_retains_original(tmp_path, workspace_settings, monkeypatch):
    """Failure before rename leaves a complete, readable legacy snapshot."""
    store = provider_store(workspace_settings, tmp_path)
    legacy(store)
    before = (store.root / "state.json").read_bytes()

    def fail(*args, **kwargs):
        """Simulate atomic replacement failure, without replacing the fixture."""
        raise OSError("private failure")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(ResponseError):
        store.migrate()
    assert (store.root / "state.json").read_bytes() == before
