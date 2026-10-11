"""Own isolated profile children, bounded metadata, process cleanup and the closed CLI."""

import argparse
import importlib.metadata
import os
import platform
import selectors as io_selectors
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from .catalog import CASES, policies, select, selection_digest, validate
from .isolation import Guards, content_digest, environment, snapshot
from .models import (
    VERSION_KEYS,
    Frame,
    Integrity,
    Manifest,
    RegressionError,
    Seal,
    canonical,
    decode,
    digest,
    now,
)
from .store import Store

BUDGET = 600
DRAIN = 10


def phase_outcome(phases):
    """Fail assertions/xpass before incomplete states; only three passed phases pass."""
    for phase, reason in (
        ("fail", "test_failed"),
        ("xpass", "unexpected_pass"),
        ("skip", "test_skipped"),
        ("xfail", "expected_failure"),
    ):
        if phase in phases:
            return ("fail" if phase in {"fail", "xpass"} else "incomplete"), reason
    return ("pass", None) if phases == ["pass", "pass", "pass"] else ("incomplete", "phase_missing")


def child():
    """Fixed bootstrap: install guards before importing pytest or any test module."""
    request = decode(sys.stdin.buffer.read(16 * 1024 * 1024))
    root = Path.cwd()
    sys.path[:0] = [str(root / "src"), str(root / "tests"), str(root)]
    fd = int(os.environ["SECURITY_REGRESSION_FD"])
    parent = os.getppid()
    # A separate process remains alive if the owner dies; it never owns report writes.
    watchdog = os.fork()
    if watchdog == 0:
        os.close(fd)
        deadline = request["deadline"]
        while time.time() < deadline and os.getppid() != 1:
            try:
                os.kill(parent, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        os.killpg(os.getpgrp(), signal.SIGKILL)
        os._exit(2)
    try:
        guard = Guards(root).install()
        import agent

        if not Path(agent.__file__).resolve().is_relative_to(root / "src"):
            raise RegressionError("isolation_failed")
        import pytest

        from .plugin import Reporter

        reporter = Reporter(
            fd, request["identity"], request["selectors"], guard, request["item_limit"]
        )
        code = pytest.main(
            [
                "-q",
                "-p",
                "no:cacheprovider",
                "-p",
                "pytest_asyncio.plugin",
                "--override-ini=addopts=",
                "--basetemp=scratch/pytest",
                *request["selectors"],
            ],
            plugins=[reporter],
        )
        reporter.finish(int(code))
        return int(code)
    finally:
        try:
            os.kill(watchdog, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(watchdog, 0)
        os.close(fd)


def terminate(process, timeout=DRAIN):
    """TERM then KILL the whole owned group and reap the child within the drain budget."""
    start = time.monotonic()
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=min(0.5, max(0.01, timeout - (time.monotonic() - start))))
        except subprocess.TimeoutExpired:
            pass
    try:
        process.wait(timeout=max(0.01, timeout - (time.monotonic() - start)))
        while time.monotonic() - start < timeout:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return "drained"
            time.sleep(0.01)
    except subprocess.TimeoutExpired:
        pass
    return "unknown"


def execute(root, manifest, profile, selected, deadline, item_limit=10000):
    """Incrementally validate one child protocol while discarding raw output concurrently."""
    read_fd, write_fd = os.pipe()
    os.set_inheritable(write_fd, True)
    identity = {
        "run_id": manifest.run_id,
        "schema_version": 1,
        "content_digest": manifest.content_digest,
        "selection_digest": manifest.selection_digest,
        "profile": profile,
    }
    env = environment(profile) | {"SECURITY_REGRESSION_FD": str(write_fd)}
    bootstrap = (
        "import sys;sys.path[:0]=['scripts','src','.'];from security_regre"
        "ssion.runner import child;sys.exit(child())"
    )
    process = None
    reason = None
    cleanup = "unknown"
    frames, inventory, results = [], [], {}
    seal = None
    buffer = b""
    sequence = 0
    retained_bytes = 0
    inventory_nodes = set()
    collection_sealed = False
    request = {
        "identity": identity,
        "selectors": selected,
        "item_limit": item_limit,
        "deadline": time.time() + max(0, deadline - time.monotonic()),
    }
    try:
        process = subprocess.Popen(
            [sys.executable, "-c", bootstrap],
            cwd=root,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(write_fd,),
            start_new_session=True,
        )
        os.close(write_fd)
        write_fd = None
        process.stdin.write(canonical(request))
        process.stdin.close()
        with io_selectors.DefaultSelector() as poll:
            for stream, kind in (
                (process.stdout, "raw"),
                (process.stderr, "raw"),
                (read_fd, "meta"),
            ):
                os.set_blocking(stream if isinstance(stream, int) else stream.fileno(), False)
                poll.register(stream, io_selectors.EVENT_READ, kind)
            while poll.get_map():
                if time.monotonic() >= deadline:
                    reason = "timeout"
                    break
                for key, _ in poll.select(min(0.1, max(0, deadline - time.monotonic()))):
                    block = os.read(key.fd, 65536)
                    if not block:
                        poll.unregister(key.fileobj)
                        continue
                    if key.data == "raw":
                        continue
                    buffer += block
                    while b"\n" in buffer:
                        raw, buffer = buffer.split(b"\n", 1)
                        event = Frame.model_validate(decode(raw, 16 * 1024))
                        sequence += 1
                        retained_bytes += len(raw)
                        if (
                            event.seq != sequence
                            or any(getattr(event, k) != v for k, v in identity.items())
                            or seal is not None
                        ):
                            raise RegressionError("protocol_invalid")
                        if event.selector is not None and event.selector not in selected:
                            raise RegressionError("protocol_invalid")
                        if event.kind == "collection":
                            if event.node_digest:
                                if (
                                    collection_sealed
                                    or event.node_digest in inventory_nodes
                                    or event.ordinal != len(inventory) + 1
                                ):
                                    raise RegressionError("protocol_invalid")
                                inventory.append([event.selector, event.node_digest, event.ordinal])
                                inventory_nodes.add(event.node_digest)
                            elif (
                                event.count != len(inventory)
                                or event.inventory_digest != digest(inventory)
                                or not inventory
                                or set(row[0] for row in inventory) != set(selected)
                            ):
                                raise RegressionError("selection_incomplete")
                            else:
                                if collection_sealed:
                                    raise RegressionError("protocol_invalid")
                                collection_sealed = True
                        elif event.kind == "item":
                            if (
                                not collection_sealed
                                or event.ordinal is None
                                or event.ordinal > len(inventory)
                                or inventory[event.ordinal - 1]
                                != [event.selector, event.node_digest, event.ordinal]
                                or event.node_digest in results
                            ):
                                raise RegressionError("protocol_invalid")
                            results[event.node_digest] = event.model_dump(
                                mode="json", exclude_none=True, exclude_defaults=True
                            )
                        elif event.kind == "terminal":
                            seal = event
                        elif event.kind == "error":
                            reason = event.reason or "protocol_invalid"
                        frames.append(
                            event.model_dump(mode="json", exclude_none=True, exclude_defaults=True)
                        )
                        if len(inventory) > 10000 or retained_bytes > 10 * 1024 * 1024:
                            raise RegressionError("limits_exceeded")
                    if len(buffer) > 16 * 1024:
                        raise RegressionError("limits_exceeded")
        if buffer:
            raise RegressionError("protocol_invalid")
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if seal is None or set(results) != {row[1] for row in inventory}:
            reason = reason or "phase_missing"
        elif (
            seal.count != len(results)
            or seal.inventory_digest != digest(inventory)
            or seal.exit_code != process.returncode
        ):
            reason = "protocol_invalid"
        elif seal.reason:
            reason = (
                "isolation_failed" if seal.reason == "isolation_failed" else reason or seal.reason
            )
        elif process.returncode:
            reason = "test_failed" if process.returncode == 1 else "collection_failed"
    except KeyboardInterrupt:
        reason = "interrupted"
    except RegressionError as error:
        reason = error.code
    except ValidationError:
        reason = "protocol_invalid"
    except subprocess.TimeoutExpired:
        reason = "timeout"
    finally:
        if process is not None:
            cleanup = terminate(process)
            process.stdout.close()
            process.stderr.close()
        if write_fd is not None:
            os.close(write_fd)
        os.close(read_fd)
    if cleanup != "drained":
        reason = "cleanup_unknown"
    return {
        "profile": profile,
        "frames": frames,
        "reason": reason,
        "cleanup": cleanup,
        "exit_code": process.returncode
        if process and process.returncode is not None and process.returncode >= 0
        else None,
    }


def versions():
    """Record only compiled dependency names and safe version labels."""
    values = {"python": platform.python_version()}
    for name in VERSION_KEYS[1:]:
        try:
            values[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            values[name] = "absent"
    if any(values[n] == "absent" for n in ("pytest", "pytest-asyncio", "httpx", "cryptography")):
        raise RegressionError("dependency_missing")
    return values


def run(project, cases, profiles):
    """Create one immutable run and seal only after every owned profile has drained."""
    from .report import reconstruct

    selected = validate(project)
    selected = sorted({s for c in cases for s in c.selectors})
    started = time.monotonic()
    run_id = str(uuid4())
    with snapshot(project) as (root, content):
        manifest = Manifest(
            run_id=run_id,
            content_digest=content,
            selection_digest=selection_digest(cases, profiles),
            started_at=now(),
            deadline_at=(datetime.now(UTC) + timedelta(seconds=BUDGET)).isoformat(),
            cases=[c.case_id for c in cases],
            profiles=profiles,
            complete_catalog=len(cases) == len(CASES) and len(profiles) == 2,
            catalog_digest=digest([c.model_dump() for c in CASES]),
            profile_digests={p: digest(policies()[p]) for p in profiles},
            versions=versions(),
            base_digest=content,
            platform="macOS" if sys.platform == "darwin" else "Linux",
        )
        with Store(project).create(run_id) as writer:
            artifacts = {"manifest.json": writer.write("manifest.json", manifest)}
            executions = []
            count = 0
            reason = None
            for profile in profiles:
                execution = execute(
                    root, manifest, profile, selected, started + BUDGET, item_limit=10000 - count
                )
                executions.append(execution)
                if execution["cleanup"] != "drained":
                    marker = root / ".retain"
                    marker.touch(mode=0o600)
                count += sum(f["kind"] == "item" for f in execution["frames"])
                if count > 10000:
                    reason = "limits_exceeded"
                name = f"{profile}.json"
                artifacts[name] = writer.write(name, execution)
                reason = reason or execution["reason"]
                if reason in {"timeout", "interrupted", "cleanup_unknown", "limits_exceeded"}:
                    break
            if content_digest(root) != content or content_digest(project) != content:
                reason = "content_changed"
            outcomes = [
                phase_outcome(f["phases"])[0]
                for e in executions
                for f in e["frames"]
                if f["kind"] == "item"
            ]
            state = (
                "interrupted"
                if reason == "interrupted"
                else "failed"
                if reason
                in {"test_failed", "isolation_failed", "content_changed", "protocol_invalid"}
                or "fail" in outcomes
                else "incomplete"
                if reason or "incomplete" in outcomes or len(executions) != len(profiles)
                else "completed"
            )
            cleanup = "drained" if all(e["cleanup"] == "drained" for e in executions) else "unknown"
            seal = Seal(
                run_id=run_id,
                content_digest=content,
                selection_digest=manifest.selection_digest,
                profile_digests=manifest.profile_digests,
                artifacts=artifacts,
                count=min(count, 10000),
                state=state,
                finished_at=now(),
                exit_code=130
                if reason == "interrupted"
                else 0
                if state == "completed"
                else 1
                if state == "failed"
                else 2,
                cleanup=cleanup,
                reason=reason,
            )
            seal_digest = writer.write("seal.json", seal)
            report, code = reconstruct(project, writer)
            report_digest = writer.write("report.json", report)
            writer.write(
                "integrity.json",
                Integrity(
                    run_id=run_id,
                    content_digest=content,
                    selection_digest=manifest.selection_digest,
                    artifacts={"seal.json": seal_digest, "report.json": report_digest},
                ),
            )
            return report, code


def main(argv=None, *, project=None):
    """Accept only list/run/report and emit one safe bounded JSON object."""

    class SafeParser(argparse.ArgumentParser):
        """Prevent argparse from echoing arbitrary rejected arguments or paths."""

        def error(self, message):
            """Emit only a closed usage failure rather than the caller-supplied text."""
            raise SystemExit(2)

    parser = SafeParser(description="Synthetic contributor security regression")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    execute_parser = commands.add_parser("run")
    group = execute_parser.add_mutually_exclusive_group()
    group.add_argument("--group", action="append")
    group.add_argument("--case", action="append")
    execute_parser.add_argument("--profile")
    report_parser = commands.add_parser("report")
    report_parser.add_argument("--run", required=True)
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        if error.code:
            print(
                canonical(
                    {
                        "reason": "unknown_selection",
                        "next_action": "Use list, run or report with documented compiled IDs.",
                    }
                ).decode()
            )
        return int(error.code)
    project = Path(project) if project is not None else Path(__file__).resolve().parents[2]
    try:
        from .report import inspect, native

        if args.command == "list":
            validate(project)
            result, code = {"cases": [c.model_dump() for c in CASES], "native": native()}, 0
        elif args.command == "run":
            cases, profiles = select(args.group, args.case, args.profile)
            result, code = run(project, cases, profiles)
        else:
            result, code = inspect(project, args.run)
    except RegressionError as error:
        result, code = (
            {"reason": error.code},
            1 if error.code in {"artifact_mismatch", "content_changed", "isolation_failed"} else 2,
        )
    except ImportError:
        result, code = {"reason": "dependency_missing"}, 2
    except OSError:
        result, code = {"reason": "storage_error"}, 2
    except ValueError:
        result, code = {"reason": "unknown_selection"}, 2
    except Exception:
        result, code = {"reason": "internal_error"}, 2
    if "cases" not in result and result.get("reason"):
        # Operational failures have no selected case; still provide fixed ownership
        # and a concrete next step without echoing input or upstream diagnostics.
        from .report import NEXT_ACTIONS

        result = result | {
            "owner": "security",
            "severity": "high",
            "next_action": NEXT_ACTIONS[result["reason"]],
        }
    print(canonical(result).decode())
    return code
