"""Offline sandbox command with fixed probes and no arbitrary-code CLI entry point."""

import asyncio
import json

from . import INSTALL, available


def add_sandbox_parser(subparsers):
    """Expose only the deterministic demonstration, never credentials or supplied code."""
    parser = subparsers.add_parser("sandbox", help="Show sandbox computation and blocked actions")
    commands = parser.add_subparsers(dest="sandbox_command", required=True)
    commands.add_parser("demo", help="Real Monty, synthetic database; no provider traffic")


async def execute_sandbox(args):
    """Emit closed metadata and a meaningful exit status, without engine diagnostics."""
    if not available():
        print(json.dumps({"error_code": "sandbox_unavailable", "next_action": INSTALL}))
        return 2
    from .demo import demonstration

    try:
        report = await demonstration()
        print(json.dumps(report))
        return 0 if report["passed"] else 1
    except asyncio.CancelledError:
        return 130
    except Exception:
        print(json.dumps({"error_code": "sandbox_demo_failed"}))
        return 1
