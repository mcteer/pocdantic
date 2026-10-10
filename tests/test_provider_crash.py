"""Interrupted effects retain durable uncertainty and never replay provider mutations."""

import asyncio
import os
from uuid import uuid4

import httpx
import pytest
from provider_support import activate, enrollment
from response_support import enrolled, principal
from test_provider_worker import planned

from agent.recovery.store import RecoveryStore
from agent.response.providers.worker import Worker, change


def test_restart_normalizes_submitted_without_network(tmp_path, workspace_settings):
    """An abandoned durable intent is uncertain, even if its provider effect succeeded."""
    store, _ = planned(workspace_settings, tmp_path)
    action = store.read().provider_actions[0]
    change(store, action.action_id, state="submitted")
    Worker(store).normalize()
    assert store.read().provider_actions[0].state == "uncertain"
    assert store.read().holds


async def test_persistence_failure_prevents_dispatch(tmp_path, workspace_settings, monkeypatch):
    """If submission cannot become durable, the external effect must not begin."""
    from agent.response.models import ResponseError

    store, incident = planned(workspace_settings, tmp_path)

    def fail(*args, **kwargs):
        """Simulate an atomic snapshot failure before dispatch."""
        raise ResponseError("response_storage_error")

    monkeypatch.setattr(store, "commit", fail)
    with pytest.raises(ResponseError):
        await Worker(
            store, transport=httpx.MockTransport(lambda _: pytest.fail("network"))
        ).process(incident.incident_id)
    assert store.read().provider_actions[0].state == "planned"


async def test_cancel_after_submission_preserves_uncertain(
    tmp_path, workspace_settings, monkeypatch
):
    """Cancellation cannot roll a possibly applied provider effect back to planned."""
    store, incident = planned(workspace_settings, tmp_path)
    worker = Worker(store)

    async def interrupted(*args, **kwargs):
        """Cancel only after the worker persists its dispatch intent."""
        assert store.read().provider_actions[0].state == "submitted"
        raise asyncio.CancelledError()

    monkeypatch.setattr(worker, "dispatch", interrupted)
    with pytest.raises(asyncio.CancelledError):
        await worker.process(incident.incident_id)
    assert store.read().provider_actions[0].state == "uncertain"


async def test_probe_adoption_link_failure_is_rediscovered(
    tmp_path, recovery_settings, monkeypatch
):
    """Recovery-first adoption survives failure of the subsequent response linkage write."""
    from agent.response.models import ResponseError
    from agent.response.providers.proof import acquisition_probe

    recovery = RecoveryStore(recovery_settings, project=tmp_path)
    recovery.initialize()
    store = enrolled(recovery_settings, tmp_path, recovery=recovery)
    activate(store, enrollment(store))
    run, fd = store.register(uuid4(), uuid4(), principal(recovery_settings))
    original = store.commit

    def fail_link(*args, **kwargs):
        """Fail only the cleanup_pending link after the recovery receipt is durable."""
        if any(p.state == "cleanup_pending" for p in kwargs.get("probe_acquisitions", ())):
            raise ResponseError("response_storage_error")
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "commit", fail_link)
    try:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    200,
                    json={
                        "lease_id": recovery_settings.vault_read_path + "/fixture-crash",
                        "lease_duration": 60,
                        "data": {"username": "fixture", "password": "fixture"},
                    },
                )
            )
        ) as http:
            await acquisition_probe(store, run.ownership(), http, "fixture", scenario="same_jwt")
        assert len(recovery.read().attempts) == 1
        probe = store.read().probe_acquisitions[0]
        assert probe.state == "issued"
        monkeypatch.setattr(store, "commit", original)
        with recovery.effect() as owner:
            recovered = recovery.adopt_probe(owner, store, probe.acquisition_id)
        assert recovered.operation_id == probe.acquisition_id
        assert len(recovery.read().attempts) == 1
    finally:
        store.finish(run)
        os.close(fd)


def test_inherited_effect_descriptor_blocks_replacement_owner(tmp_path, workspace_settings):
    """A live trusted child retains effect ownership after its parent's descriptor closes."""
    import subprocess
    import sys

    from agent.recovery.store import RecoveryError

    store, _ = planned(workspace_settings, tmp_path)
    context = store.effect()
    owner = context.__enter__()
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys; print('ready', flush=True); sys.stdin.read()"],
        pass_fds=(owner.fd,),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        assert child.stdout.readline() == b"ready\n"
        context.__exit__(None, None, None)
        with pytest.raises(RecoveryError, match="recovery_busy"):
            with store.effect():
                pytest.fail("effect owner escaped its live child")
    finally:
        child.communicate(timeout=5)
    with store.effect():
        pass
