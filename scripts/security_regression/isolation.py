"""Fresh maintained snapshots and accidental-effect guards installed before collection.

These guards protect trusted tests against ambient configuration and live effects. They
are deliberately not a security sandbox for hostile Python running as the same user.
"""

import hashlib
import os
import shutil
import socket
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .models import RegressionError

ROOTS = ("src/agent", "tests", "scripts", "config")
EXCLUDED = {
    ".local",
    ".git",
    "design",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "browser",
    "private",
    "evidence",
}
GIT_COMMANDS = {
    "init",
    "add",
    "commit",
    "config",
    "status",
    "diff",
    "ls-files",
    "rev-parse",
    "check-ignore",
    "log",
    "show",
    "cat-file",
    "ls-tree",
}


def eligible(project):
    """Enumerate regular maintained source bytes, including new untracked support files."""
    project = Path(project)
    paths = []
    for name in ROOTS:
        root = project / name
        if root.is_symlink():
            raise RegressionError("unsafe_path")
        if not root.exists():
            continue
        for base, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not d.startswith("."))
            for directory in dirs:
                if (Path(base) / directory).is_symlink():
                    raise RegressionError("unsafe_path")
            for filename in files:
                path = Path(base) / filename
                if path.suffix not in {".py", ".json", ".sql", ".js", ".css", ".html", ".sh"}:
                    continue
                if filename.startswith(".env") or filename.endswith((".pyc", ".tmp", ".trace.zip")):
                    continue
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise RegressionError("unsafe_path")
                if path.suffix in {".json", ".jsonl"}:
                    try:
                        from publish_policy import private_content
                    except ImportError:
                        from scripts.publish_policy import private_content
                    if private_content(path.relative_to(project).as_posix(), path.read_bytes()):
                        raise RegressionError("unsafe_path")
                if path.stat().st_size > 10 * 1024 * 1024:
                    raise RegressionError("limits_exceeded")
                paths.append(path.relative_to(project))
    for name in ("pyproject.toml", "uv.lock"):
        path = project / name
        if path.exists() or path.is_symlink():
            if not stat.S_ISREG(path.lstat().st_mode):
                raise RegressionError("unsafe_path")
            paths.append(Path(name))
    if sum((project / path).stat().st_size for path in paths) > 100 * 1024 * 1024:
        raise RegressionError("limits_exceeded")
    return sorted(paths)


def content_digest(project):
    """Hash length-delimited relative paths and exact bytes on every invocation."""
    result = hashlib.sha256()
    for relative in eligible(project):
        name = relative.as_posix().encode()
        raw = (Path(project) / relative).read_bytes()
        result.update(len(name).to_bytes(8, "big") + name + len(raw).to_bytes(8, "big") + raw)
    return result.hexdigest()


@contextmanager
def snapshot(project):
    """Copy eligible bytes to owned scratch and reject source mutation while copying."""
    before = content_digest(project)
    root = Path(tempfile.mkdtemp(prefix="security-regression-")).resolve()
    try:
        for relative in eligible(project):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((Path(project) / relative).read_bytes())
        if content_digest(root) != before or content_digest(project) != before:
            raise RegressionError("content_changed")
        yield root, before
    finally:
        # Never erase scratch still potentially in use by an undrained owned process.
        if not (root / ".retain").exists():
            shutil.rmtree(root)


def environment(profile):
    """Build an explicit child environment; caller secrets and pytest options are dropped."""
    return {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "SECURITY_REGRESSION_PROFILE": profile,
    }


class Guards:
    """Record denied attempts even when a test catches the rejection exception."""

    def __init__(self, root):
        """Bind allowed local fixture work to this one owned snapshot."""
        self.root = Path(root).resolve()
        self.failed = False
        self.originals = []

    def deny(self, *args, **kwargs):
        """Mark isolation violated before returning a payload-free failure."""
        self.failed = True
        raise RegressionError("isolation_failed")

    async def async_deny(self, *args, **kwargs):
        """Reject async HTTP connections at the transport boundary."""
        return self.deny()

    def patch(self, obj, name, value):
        """Track reversible guards so unit tests can exercise installation safely."""
        self.originals.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def install(self):
        """Disable dotenv, redirect default journals, and guard native effects before imports."""
        import httpx

        import agent.recovery.store as recovery
        import agent.validation.store as validation
        from agent.settings import Settings

        self.patch(Settings, "model_config", Settings.model_config | {"env_file": None})
        scratch = self.root / "scratch"
        scratch.mkdir(mode=0o700, exist_ok=True)
        self.patch(validation, "project_root", lambda: scratch)
        self.patch(recovery, "project_root", lambda: scratch)
        # Memory-only sockets never need external DNS or Internet address families.
        for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
            self.patch(socket, name, self.deny)
        for name in ("connect", "connect_ex", "sendto"):
            original = getattr(socket.socket, name)

            def socket_guard(sock, address, *args, _original=original, **kwargs):
                """Allow only Unix sockets whose path belongs to the owned scratch tree."""
                if (
                    sock.family == socket.AF_UNIX
                    and isinstance(address, str)
                    and Path(address).resolve().is_relative_to(self.root)
                ):
                    return _original(sock, address, *args, **kwargs)
                return self.deny()

            self.patch(socket.socket, name, socket_guard)
        self.patch(httpx.AsyncHTTPTransport, "handle_async_request", self.async_deny)
        self.patch(httpx.HTTPTransport, "handle_request", self.deny)
        try:
            import psycopg

            self.patch(psycopg, "connect", self.deny)
            self.patch(psycopg.Connection, "connect", self.deny)
            self.patch(psycopg.AsyncConnection, "connect", self.async_deny)
        except ImportError:
            pass
        original = subprocess.Popen
        git = shutil.which("git")

        def local_process(args, *positional, **kwargs):
            """Permit compiled local Git fixture commands only, with no shell or escaped cwd."""
            cwd = Path(kwargs.get("cwd") or Path.cwd()).resolve()
            valid = (
                isinstance(args, (list, tuple))
                and len(args) >= 2
                and str(args[0]) in {"git", git}
                and not kwargs.get("shell")
                and not kwargs.get("start_new_session")
                and kwargs.get("process_group") in (None, -1)
                and cwd.is_relative_to(self.root)
            )
            if valid:
                words = list(args[1:])
                if words[:1] == ["-C"] and len(words) >= 3:
                    target = Path(words[1])
                    target = target if target.is_absolute() else cwd / target
                    valid = target.resolve().is_relative_to(self.root)
                    words = words[2:]
                valid = valid and bool(words) and words[0] in GIT_COMMANDS
                # Git configuration may otherwise introduce a remote/helper/hook effect.
                if words[:1] == ["config"]:
                    valid = (
                        valid
                        and len(words) >= 2
                        and words[1] in {"user.name", "user.email", "commit.gpgsign"}
                    )
            if not valid:
                return self.deny()
            return original(args, *positional, **kwargs)

        self.patch(subprocess, "Popen", local_process)
        self.patch(os, "system", self.deny)
        self.patch(os, "popen", self.deny)
        return self

    def restore(self):
        """Restore guarded seams in reverse order after a disposable unit test."""
        for obj, name, value in reversed(self.originals):
            setattr(obj, name, value)
        self.originals.clear()
