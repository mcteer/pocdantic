"""SIGKILL at real credential lifecycle boundaries cannot erase durable uncertainty."""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent.recovery.store import RecoveryError, RecoveryStore

CHILD = """
import sys, asyncio, httpx
sys.path.insert(0, 'tests')
from recovery_support import settings, crash_checkpoint
from agent.recovery.store import RecoveryStore
from agent.recovery.lifecycle import CredentialLifecycle
from agent.vault import VaultClient
from pydantic import SecretStr
from pathlib import Path
root, checkpoint, marker = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
store = RecoveryStore(settings(root), project=root)
def stop(name):
    if checkpoint == name: crash_checkpoint(name, marker)
async def run():
    with store.effect() as owner:
        lifecycle = CredentialLifecycle(store, owner)
        original_acquired, original_completed = lifecycle.acquired, lifecycle.completed
        original_start, original_pending = lifecycle.start, lifecycle.pending
        def start():
            original_start()
            stop('before_send')
        def pending():
            original_pending()
            stop('cleanup_intent')
        lifecycle.start, lifecycle.pending = start, pending
        def acquired(*args, **kwargs):
            stop('handle_before_persist')
            original_acquired(*args, **kwargs)
            stop('handle_persisted')
        def completed(*args, **kwargs):
            stop('response_before_receipt')
            original_completed(*args, **kwargs)
            stop('terminal_receipt')
        lifecycle.acquired, lifecycle.completed = acquired, completed
        async def handler(request):
            if request.method == 'GET':
                stop('lost_response')
                data = {'lease_id':'database/creds/read/native','lease_duration':30,
                        'data':{'username':'private','password':'private'}}
                return httpx.Response(200, json=data)
            stop('cleanup_submitted')
            return httpx.Response(204)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            vault = VaultClient('https://vault.example','fixture',http,credential_lifecycle=lifecycle)
            async with vault.credentials(SecretStr('private'),'database/creds/read'):
                pass
asyncio.run(run())
"""


@pytest.mark.parametrize(
    "checkpoint",
    [
        "before_send",
        "lost_response",
        "handle_before_persist",
        "handle_persisted",
        "cleanup_intent",
        "cleanup_submitted",
        "response_before_receipt",
        "terminal_receipt",
    ],
)
def test_kill_restart_never_replays_or_clears(recovery_store, checkpoint):
    marker = recovery_store.project / "checkpoint"
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(recovery_store.project), checkpoint, str(marker)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=Path(__file__).parents[1],
    )
    try:
        deadline = time.monotonic() + 8
        while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists(), "controlled child did not reach checkpoint"
        with pytest.raises(RecoveryError, match="recovery_busy"):
            with recovery_store.effect():
                pass
        os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=3)
        restarted = RecoveryStore(recovery_store.settings, project=recovery_store.project)
        restarted.normalize()
        item = restarted.read().attempts[0]
        assert item.state == ("resolved" if checkpoint == "terminal_receipt" else "unresolved")
        if checkpoint != "terminal_receipt":
            with pytest.raises(RecoveryError):
                with restarted.effect() as owner:
                    restarted.begin(owner)
        else:
            assert item.resolution == "revoked" and item.receipt
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
