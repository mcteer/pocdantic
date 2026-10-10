#!/usr/bin/env python3
"""Reject private paths and credential values from the Git index and optional history.

The publication allowlist is separate from credential scanning. Local configuration
is read only to detect accidental publication; its values are never printed.
"""

import argparse
import re
import subprocess
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

from publish_policy import generated_private, publishable


def git(*args, check=True):
    """Run a Git query with captured output so source bytes are scanned rather than
    printed.
    """
    return subprocess.run(["git", *args], check=check, capture_output=True).stdout


def forbidden(name):
    """Identify private working paths and generated evidence that must never be published."""
    p = PurePosixPath(name)
    return (
        generated_private(name)
        or "design" in p.parts
        or "chat" in p.parts
        or ("specs" in p.parts and bool({"private", "evidence"} & set(p.parts)))
        or ".local" in p.parts
        or ".agents" in p.parts
        or p.name == ".DS_Store"
        or (p.name.startswith(".env") and p.name != ".env.example")
    )


def credential_values():
    """Collect private local values and decoded database URI components for byte matching.

    Return byte strings to the scanner without logging them or reading provider state.
    """
    file = Path(".env.local")
    if not file.exists():
        return []
    values = []
    for line in file.read_text().splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip("\"'")
        if (
            any(
                word in key.upper()
                for word in (
                    "SECRET",
                    "TOKEN",
                    "API_KEY",
                    "CLIENT_ID",
                    "TENANT_URL",
                    "VAULT_ADDR",
                    "PASSWORD",
                    "DB_URI",
                    "DATABASE_URL",
                )
            )
            and len(value) >= 8
        ):
            values.append(value.encode())
            if value.startswith(("postgres://", "postgresql://")):
                # Also catch decoded credentials copied separately from a URI.
                try:
                    parsed = urlsplit(value)
                    for component in (parsed.password, parsed.hostname):
                        if component and len(component) >= 8:
                            values.append(unquote(component).encode())
                except ValueError:
                    pass
    return values


def main():
    """Scan indexed blobs and optionally every reachable revision against path and
    credential rules.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args()
    entries = git("ls-files", "-z").decode().split("\0")
    failures = []
    secrets = credential_values()
    # Scan index rather than worktree to detect staged secrets even after worktree cleanup.
    for name in filter(None, entries):
        if forbidden(name) or not publishable(name):
            failures.append("private path: " + name)
            continue
        data = git("show", ":" + name)
        if any(secret in data for secret in secrets):
            failures.append("local credential value in: " + name)
        if re.search(
            (
                rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|hvs\.[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{30,}|"
                rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
            ),
            data,
        ):
            failures.append("credential pattern in: " + name)
    if args.history:
        history = git("rev-list", "--all", check=False).decode().splitlines()
        for revision in history:
            paths = git("ls-tree", "-r", "--name-only", "-z", revision).decode().split("\0")
            for name in filter(None, paths):
                if forbidden(name) or not publishable(name):
                    failures.append("private path in history: " + name)
                data = git("show", revision + ":" + name)
                if any(secret in data for secret in secrets):
                    failures.append("local credential in history: " + name)
    if failures:
        raise SystemExit("Privacy gate failed:\n" + "\n".join(sorted(set(failures))))
    print("Privacy gate passed")


if __name__ == "__main__":
    main()
