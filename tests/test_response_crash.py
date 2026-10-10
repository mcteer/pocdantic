"""Submitted effects remain uncertain after restart and inherited locks survive parent death."""

from response_support import signal
from test_response_coordinator import setup_attempt

from agent.response.coordinator import Coordinator


async def test_submitted_restart_does_not_call_provider(tmp_path, recovery_settings):
    response, recovery, run, attempt = setup_attempt(tmp_path, recovery_settings)
    coordinator = Coordinator(response)
    item, _ = coordinator.submit(signal(recovery_settings, root=run.root_run_id))
    coordinator.reconcile(item.incident_id)
    action = next(a for a in coordinator.get(item.incident_id).actions if a.kind == "revoke_exact")
    coordinator.action(item.incident_id, action.action_id, "submitted")
    restarted = Coordinator(response)
    restarted.normalize()
    result = await restarted.process(item.incident_id)
    assert next(a for a in result.actions if a.kind == "revoke_exact").status == "uncertain"
    assert recovery.read().attempts[0].state == "unresolved"


def test_parent_death_does_not_release_inherited_owners(tmp_path, recovery_settings):
    """A real surviving subprocess keeps both locks until its descriptor copies close."""
    import os
    import signal as os_signal
    import subprocess
    import sys
    import time

    import pytest
    from response_support import enrolled

    from agent.recovery.store import RecoveryError, RecoveryStore

    recovery = RecoveryStore(recovery_settings, project=tmp_path)
    recovery.initialize()
    response = enrolled(recovery_settings, tmp_path, recovery=recovery)
    marker = tmp_path / "owners-ready"
    script = """
import asyncio, json, os, subprocess, sys
from pathlib import Path
sys.path.insert(0, 'tests')
from recovery_support import settings
from response_support import principal
from agent.recovery.store import RecoveryStore
from agent.response.store import ResponseStore
from agent.recovery.workers import descriptor_scope, network_process
from uuid import uuid4
root, marker = Path(sys.argv[1]), Path(sys.argv[2])
s = settings(root)
r = RecoveryStore(s, project=root)
c = ResponseStore(s, project=root, recovery=r)
async def main():
    run, fd = c.register(uuid4(), uuid4(), principal(s))
    with r.effect() as owner, descriptor_scope(fd), descriptor_scope(owner.fd):
        # network_process is the production descriptor propagation boundary.
        async with network_process('agent.recovery.commands', 'cleanup-worker') as child:
            marker.write_text(json.dumps({'pid':child.pid, 'root':str(run.root_run_id)}))
            await asyncio.Future()
asyncio.run(main())
"""
    # Use matching settings in both processes; no environment or customer credentials.
    from recovery_support import settings

    configured = settings(tmp_path)
    # Re-enroll under the exact synthetic environment before spawning its owner.
    import shutil

    shutil.rmtree(response.root)
    shutil.rmtree(recovery.root)
    recovery = RecoveryStore(configured, project=tmp_path)
    recovery.initialize()
    response = enrolled(configured, tmp_path, recovery=recovery)
    parent = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path), str(marker)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child_pid = None
    try:
        deadline = time.monotonic() + 8
        while not marker.exists() and parent.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists(), "owner did not reach inherited-descriptor boundary"
        import json
        from uuid import UUID

        data = json.loads(marker.read_text())
        child_pid = data["pid"]
        root = UUID(data["root"])
        os.kill(parent.pid, os_signal.SIGKILL)
        parent.wait(timeout=3)
        assert response.busy(root)
        with pytest.raises(RecoveryError, match="recovery_busy"):
            with recovery.effect():
                pass
        os.kill(child_pid, os_signal.SIGKILL)
        deadline = time.monotonic() + 3
        while response.busy(root) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not response.busy(root)
        with recovery.effect():
            pass
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=3)
        if child_pid:
            try:
                os.kill(child_pid, os_signal.SIGKILL)
            except ProcessLookupError:
                pass
