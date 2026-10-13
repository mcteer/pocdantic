"""Actual installed entry points must ignore ambient live configuration and authority."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("entry", ["agent", "pocdantic"])
@pytest.mark.parametrize("poison", [False, True])
def test_demo_ignores_live_settings(tmp_path, entry, poison):
    """Poison every live selector and retain private-state canaries through ten runs."""
    canary = tmp_path / ".local" / "enrollment"
    canary.parent.mkdir()
    canary.write_bytes(b"private-state-canary")
    dotenv = tmp_path / ".env.local"
    dotenv.write_text("TIMEOUT_SECONDS=invalid\nPROFILES_FILE=missing\n")
    env = os.environ.copy()
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env["PATH"]
    if poison:
        env.update(
            TIMEOUT_SECONDS="invalid",
            POCDANTIC_TIMEOUT_SECONDS="invalid",
            MODEL="unknown:poison",
            PROFILES_FILE="missing",
            LOGFIRE_BASE_URL="invalid",
            LOGFIRE_TOKEN="synthetic-canary",
        )
    # sitecustomize denies sockets even if a future regression constructs live adapters.
    guard = tmp_path / "guard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(
        "import socket\n"
        'def denied(*args, **kwargs):\n    raise AssertionError("network_denied")\n'
        "socket.socket.connect = denied\nsocket.create_connection = denied\n"
    )
    env["PYTHONPATH"] = str(guard)
    for _ in range(10):
        result = subprocess.run(
            [entry, "demo"], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, result.stderr
        lines = result.stdout.splitlines()
        response = json.loads(lines[0])
        assert response["status"] == "completed"
        assert response["output"] == {
            "summary": "Synthetic POC-1 ticket retrieved by the restricted child."
        }
        audit = json.loads(lines[1])["audit"]
        assert [(event["event"], event["outcome"]) for event in audit] == [
            ("identity", "verified"),
            ("run", "started"),
            ("policy", "allowed"),
            ("delegation", "started"),
            ("policy", "allowed"),
            ("ticket.read", "synthetic"),
            ("delegation", "completed"),
            ("run", "completed"),
        ]
        assert json.loads(lines[1])["mode"] == "synthetic"
        assert "synthetic-canary" not in result.stdout + result.stderr
    assert canary.read_bytes() == b"private-state-canary"
    assert dotenv.read_text() == "TIMEOUT_SECONDS=invalid\nPROFILES_FILE=missing\n"


def test_optional_sandbox_poisoned_config(tmp_path):
    """Real Monty is optional; absent workers yield an install handoff, never fallback."""
    (tmp_path / ".env.local").write_text("TIMEOUT_SECONDS=invalid\n")
    env = os.environ | {
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
        "TIMEOUT_SECONDS": "invalid",
    }
    result = subprocess.run(
        ["agent", "sandbox", "demo"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode in {0, 2}
    report = json.loads(result.stdout)
    if result.returncode == 2:
        assert report["error_code"] == "sandbox_unavailable"
        assert "sandbox" in report["next_action"]
    else:
        assert report["passed"] is True
