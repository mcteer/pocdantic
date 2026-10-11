"""Compiled subprocess dispatch with private pipes and inherited lifetime ownership.

Children enforce their own deadline so a dead parent cannot leave a provider worker
holding authority forever. Errors and stderr never carry provider bodies to the caller.
"""

import asyncio
import json
import signal
import sys

from agent.recovery.workers import network_process
from agent.validation.store import decode_json

from .models import GovernanceError, require

WORKFLOWS = {
    "readiness",
    "observe",
    "enroll",
    "reconcile-case",
    "identity",
    "permissions",
    "negatives",
}


async def run(operation, payload, *, ownership_fds=(), budget=120):
    """Execute one compiled provider operation with a bounded safe result channel."""
    require(operation in WORKFLOWS and 0 < budget <= 120)
    raw = json.dumps({"operation": operation, "payload": payload}, allow_nan=False).encode()
    require(len(raw) <= 65536, "capacity_exhausted")
    try:
        async with asyncio.timeout(budget):
            async with network_process(__name__, ownership_fds=ownership_fds) as process:
                output, _ = await process.communicate(raw)
                require(process.returncode == 0 and len(output) <= 262144, "effect_uncertain")
                result = decode_json(output)
                require(
                    isinstance(result, dict) and result.get("schema_version") == 1,
                    "effect_uncertain",
                )
                if "reason" in result:
                    raise GovernanceError(result["reason"], effect=result.get("effect") is True)
                return result
    except GovernanceError:
        raise
    except BaseException:
        raise GovernanceError("effect_uncertain") from None


async def child():
    """Read only private stdin and invoke a fixed adapter; emit no bearer credentials."""
    # A hard process deadline also applies if the parent dies during I/O or drain.
    signal.alarm(120)
    try:
        raw = sys.stdin.buffer.read(65537)
        require(len(raw) <= 65536)
        envelope = decode_json(raw)
        require(set(envelope) == {"operation", "payload"})
        operation, payload = envelope["operation"], envelope["payload"]
        require(operation in WORKFLOWS)
        async with asyncio.timeout(110):
            result = await workflow(operation, payload)
    except GovernanceError as error:
        result = {"schema_version": 1, "reason": str(error), "effect": error.effect}
    except BaseException:
        result = {"schema_version": 1, "reason": "effect_uncertain", "effect": True}
    sys.stdout.write(json.dumps(result, allow_nan=False))


async def workflow(operation, payload):
    """Reopen anchored state in the child while retaining all inherited lifetime locks."""
    import os

    from agent.recovery.store import RecoveryStore, environment_digest
    from agent.response.store import ResponseStore
    from agent.settings import Settings

    from .coordinator import Coordinator
    from .runtime import execute
    from .store import GovernanceStore

    # Omitted fields must not fall back to a contributor's ambient credentials.
    os.environ.clear()
    settings = Settings(_env_file=None, **payload["settings"])
    require(environment_digest(settings) == payload["environment"], "configuration_changed")
    store = GovernanceStore(project=payload["project"], environment=payload["environment"])
    recovery = RecoveryStore(settings, project=store.project)
    response = ResponseStore(settings, project=store.project, recovery=recovery)
    coordinator = Coordinator(store, response, recovery)
    # Parent acquired these exact lifetime locks before spawn; inherited open file
    # descriptions keep them owned even if that parent dies during a provider call.
    validate_owners(payload.get("ownership"), store, response, recovery)
    coordinator.active = True
    coordinator.check()
    before = store.read()
    try:
        return await execute(
            "reconcile" if operation == "reconcile-case" else operation,
            payload,
            store,
            settings,
            coordinator.check,
        )
    except GovernanceError as error:
        try:
            after = store.read()
            dispatched = len(after.credentials) > len(before.credentials) or len(
                after.registrations
            ) > len(before.registrations)
        except Exception:
            dispatched = True
        raise GovernanceError(str(error), effect=dispatched) from None


def validate_owners(fds, governance, response, recovery):
    """Require inherited descriptors for the exact complete compiled ownership chain."""
    import fcntl
    import os

    from agent.recovery.store import check_stat

    paths = (
        recovery.root / "workspace.lock",
        response.root / "worker.lock",
        response.root / "probe.lock",
        governance.root / "effect.lock",
        recovery.root / "effect.lock",
    )
    require(
        isinstance(fds, list)
        and len(fds) == 5
        and all(type(fd) is int and fd >= 3 for fd in fds)
        and len(set(fds)) == 5,
        "workspace_busy",
    )
    for fd, path in zip(fds, paths, strict=True):
        before, expected = os.fstat(fd), path.lstat()
        check_stat(before)
        check_stat(expected)
        require(
            (before.st_dev, before.st_ino) == (expected.st_dev, expected.st_ino), "workspace_busy"
        )
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


if __name__ == "__main__":
    asyncio.run(child())
