"""Governance ownership is exclusive and holds interrupt before the next dispatch."""

import asyncio
from types import SimpleNamespace

import pytest
from governance_support import installed

from agent.governance.models import GovernanceError


def test_nonblocking_effect_ownership(tmp_path):
    from agent.governance.store import GovernanceStore

    s = installed(tmp_path)
    other = GovernanceStore(project=tmp_path, environment="0" * 64)
    with s.lock("effect.lock"):
        with pytest.raises(GovernanceError, match="workspace_busy"):
            with other.lock("effect.lock"):
                pytest.fail("second effect acquired")
    with other.lock("effect.lock"):
        pass


def test_hold_and_unknown_acquisition_fail_closed():
    from agent.governance.coordinator import admit

    clean = SimpleNamespace(holds=(), root_holds=(), subject_holds=(), incidents=())
    recovery = SimpleNamespace(attempts=())
    admit(clean, recovery)
    with pytest.raises(GovernanceError, match="contained"):
        admit(SimpleNamespace(**(vars(clean) | {"holds": (object(),)})), recovery)
    with pytest.raises(GovernanceError, match="issuance_unresolved"):
        admit(clean, SimpleNamespace(attempts=(SimpleNamespace(state="unresolved"),)))


def test_hold_cancels_waiting_operation():
    from agent.governance.coordinator import guarded

    checks = 0

    async def slow():
        await asyncio.sleep(10)
        pytest.fail("effect escaped hold")

    def check():
        nonlocal checks
        checks += 1
        if checks >= 2:
            raise GovernanceError("contained")

    with pytest.raises(GovernanceError, match="contained"):
        asyncio.run(guarded(slow, check, timeout=1))


def test_child_keeps_owner_after_parent_descriptor_closes(tmp_path):
    """An inherited flock stays held until the worker actually terminates."""
    import subprocess
    import sys

    from agent.governance.store import GovernanceStore

    s = installed(tmp_path)
    other = GovernanceStore(project=tmp_path, environment="0" * 64)
    with s.lock("effect.lock") as fd:
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
            pass_fds=(fd,),
            stdin=subprocess.PIPE,
        )
    try:
        with pytest.raises(GovernanceError, match="workspace_busy"):
            with other.lock("effect.lock"):
                pytest.fail("abandoned worker lost ownership")
    finally:
        child.communicate(timeout=2)
    with other.lock("effect.lock"):
        pass


def test_compiled_worker_deadline_kills_and_drains(monkeypatch):
    """The worker wrapper terminates its process before returning uncertainty."""
    from contextlib import asynccontextmanager

    from agent.governance import workers

    drained = False

    @asynccontextmanager
    async def fake(*_args, **_kwargs):
        nonlocal drained

        class Process:
            async def communicate(self, _raw):
                await asyncio.sleep(10)

        try:
            yield Process()
        finally:
            drained = True

    monkeypatch.setattr(workers, "network_process", fake)
    with pytest.raises(GovernanceError, match="effect_uncertain"):
        asyncio.run(workers.run("observe", {}, budget=0.01))
    assert drained


def test_real_response_intake_is_not_blocked_by_effect_ownership(tmp_path):
    """A new durable hold can arrive during I/O and blocks the next governance phase."""
    from governance_support import anchors
    from response_support import signal

    from agent.governance.coordinator import Coordinator
    from agent.response.coordinator import Coordinator as ResponseCoordinator

    settings, governance, response, recovery = anchors(tmp_path)
    coordinator = Coordinator(governance, response, recovery)
    with coordinator.ownership():
        coordinator.check()
        ResponseCoordinator(response).submit(signal(settings))
        with pytest.raises(GovernanceError, match="contained"):
            coordinator.check()
    assert response.read().holds


def test_existing_workspace_owner_blocks_governance_without_reset(tmp_path):
    from governance_support import anchors

    from agent.governance.coordinator import Coordinator

    _settings, governance, response, recovery = anchors(tmp_path)
    before = governance.read()
    with recovery.workspace():
        with pytest.raises(GovernanceError, match="workspace_busy"):
            with Coordinator(governance, response, recovery).ownership():
                pytest.fail("workspace ownership escaped")
    assert governance.read() == before


def test_parent_death_retains_all_effect_locks_until_child_deadline(tmp_path):
    """Kill an actual owner process; its inherited child keeps the complete lock chain."""
    import json
    import os
    import subprocess
    import sys
    import time
    from pathlib import Path

    from governance_support import anchors

    from agent.governance.coordinator import Coordinator

    settings, governance, response, recovery = anchors(tmp_path)
    config = tmp_path / "selectors.json"
    config.write_text(json.dumps(settings.model_dump(mode="json")))
    parent_source = """
import json, subprocess, sys
from agent.settings import Settings
from agent.recovery.store import RecoveryStore, environment_digest
from agent.recovery.workers import OWNERSHIP_FDS
from agent.response.store import ResponseStore
from agent.governance.store import GovernanceStore
from agent.governance.coordinator import Coordinator
root = sys.argv[1]
settings = Settings.model_construct(**json.loads(open(root + "/selectors.json").read()))
r = RecoveryStore(settings, project=root)
s = ResponseStore(settings, project=root, recovery=r)
g = GovernanceStore(project=root, environment=environment_digest(settings))
with Coordinator(g, s, r).ownership():
    script = "import signal,time; signal.alarm(2); time.sleep(30)"
    child = subprocess.Popen([sys.executable, "-c", script], pass_fds=OWNERSHIP_FDS.get())
    print(child.pid, flush=True)
    sys.stdin.buffer.read()
"""
    parent = subprocess.Popen(
        [sys.executable, "-c", parent_source, str(tmp_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
    )
    child_pid = None
    try:
        child_pid = int(parent.stdout.readline())
        parent.kill()
        parent.wait(timeout=2)
        with pytest.raises(GovernanceError, match="workspace_busy"):
            with Coordinator(governance, response, recovery).ownership():
                pytest.fail("child lost lifetime ownership after parent death")
        deadline = time.monotonic() + 5
        while True:
            try:
                with Coordinator(governance, response, recovery).ownership():
                    break
            except GovernanceError as error:
                assert str(error) == "workspace_busy"
                assert time.monotonic() < deadline
                time.sleep(0.02)
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=2)
        if child_pid:
            try:
                os.kill(child_pid, 15)
            except ProcessLookupError:
                pass


def test_real_compiled_child_requires_complete_inherited_owners(tmp_path):
    """The executable worker cannot dispatch standalone provider mutations."""
    from governance_support import anchors, source

    from agent.governance.commands import public_selectors
    from agent.governance.config import create_private
    from agent.governance.coordinator import Coordinator
    from agent.governance.workers import run
    from agent.recovery.workers import OWNERSHIP_FDS

    settings, store, response, recovery = anchors(tmp_path)
    store.configure((source(),), 1)
    item = store.case("fixture")
    create_private(
        store, f"candidate-{item.candidate_id}.draft.json", {"schema_version": 1, "binding": None}
    )
    payload = {
        "project": str(tmp_path),
        "environment": store.environment,
        "settings": public_selectors(settings),
        "revision": store.read().revision,
        "candidate": str(item.candidate_id),
        "ownership": [],
    }
    with pytest.raises(GovernanceError, match="workspace_busy"):
        asyncio.run(run("readiness", payload))
    with Coordinator(store, response, recovery).ownership():
        payload["ownership"] = list(OWNERSHIP_FDS.get())
        with pytest.raises(GovernanceError, match="missing_authority"):
            asyncio.run(run("readiness", payload))
    assert not store.read().credentials and not store.read().registrations
