"""Bounded root admission before CLI configuration or durable deployment-state access."""

import os
import subprocess
from pathlib import Path

from .security import SecurityError


def require_root() -> Path:
    """Return canonical cwd only when it is the Git top level or definitely outside Git.

    Discovery errors fail closed. No private files are read, paths changed, or journals
    relocated. Git runs with a one-second timeout and English diagnostics so a genuine
    outside-Git result can be distinguished from permission, corruption and other errors.
    """
    root = Path.cwd()
    logical = os.environ.get("PWD")
    if root.resolve() != root or (
        logical
        and Path(logical).is_absolute()
        and Path(logical).resolve() == root
        and Path(logical) != root
    ):
        raise SecurityError("deployment_root_required")
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=root,
            env={key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
            | {"LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0"},
            capture_output=True,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SecurityError("deployment_root_unavailable") from None
    if result.returncode:
        if result.returncode == 128 and result.stderr.startswith("fatal: not a git repository"):
            return root
        raise SecurityError("deployment_root_unavailable")
    value = result.stdout.rstrip("\n")
    candidate = Path(value)
    if "\n" in value or not candidate.is_absolute() or not candidate.is_dir():
        raise SecurityError("deployment_root_unavailable")
    if candidate.resolve() != candidate or candidate != root:
        raise SecurityError("deployment_root_required")
    return root


def configuration_free(args) -> bool:
    """Identify fixed offline commands that do not consume local deployment authority."""
    return (
        args.command in {"demo", "sandbox"}
        or (args.command == "validate" and getattr(args, "validation_command", None) == "list")
        or (args.command == "setup" and getattr(args, "recipe", None) == "offline")
    )
