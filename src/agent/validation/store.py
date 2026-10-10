"""Owner-only bounded storage. No automatic retention or source fetching."""

import fcntl
import hashlib
import json
import os
import subprocess
import threading
from functools import wraps
from pathlib import Path
from uuid import UUID, uuid4

from .models import canonical

MAX_ARTIFACT = 10 * 1024 * 1024
MAX_TOTAL = 100 * 1024 * 1024
MAX_ARTIFACTS = 100
MAX_EVENTS = 10_000
MAX_EVENT = 64 * 1024


class StoreError(ValueError):
    def __init__(self, code="storage_error"):
        super().__init__(code)


def decode_json(raw: bytes):
    if len(raw) > MAX_ARTIFACT:
        raise StoreError("limits_exceeded")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise StoreError("schema_invalid")
            result[key] = value
        return result

    def invalid(_):
        raise StoreError("schema_invalid")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 16:
                raise StoreError("limits_exceeded")
            if isinstance(item, dict):
                pending.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, list):
                pending.extend((v, depth + 1) for v in item)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise StoreError("schema_invalid") from None


def no_symlinks(path: Path):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise StoreError()


def project_root() -> Path:
    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    return Path(result.stdout.strip()) if result.returncode == 0 else Path.cwd()


def private_dirs(path: Path, boundary: Path):
    no_symlinks(path)
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for part in reversed(missing):
        part.mkdir(mode=0o700)
    for part in (path, *path.parents):
        if part == boundary:
            break
        if part.stat().st_uid != os.getuid():
            raise StoreError()
        part.chmod(0o700)


def safe_name(name):
    if not isinstance(name, str) or not name or name in {".", ".."} or Path(name).name != name:
        raise StoreError()
    return name


def read_private(path: Path) -> bytes:
    no_symlinks(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as file:
            raw = file.read(MAX_ARTIFACT + 1)
        if len(raw) > MAX_ARTIFACT:
            raise StoreError("limits_exceeded")
        return raw
    except OSError:
        raise StoreError() from None


def synchronized(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self.mutex:
            return method(self, *args, **kwargs)

    return locked


class RunWriter:
    def __init__(self, path):
        self.path = path
        self.mutex = threading.RLock()
        self.journal_counts = {}
        no_symlinks(path)
        self.dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.lock_fd = os.open(
                ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=self.dir_fd
            )
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            if hasattr(self, "lock_fd"):
                os.close(self.lock_fd)
            os.close(self.dir_fd)
            raise StoreError() from None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
        os.close(self.lock_fd)
        os.close(self.dir_fd)

    def _quota(self, added, name=None):
        files = [p for p in self.path.iterdir() if p.name != ".lock"]
        if any(p.is_symlink() or not p.is_file() for p in files):
            raise StoreError()
        total = sum(p.stat().st_size for p in files)
        old = next((p.stat().st_size for p in files if p.name == name), 0)
        if (
            added > MAX_ARTIFACT
            or total - old + added > MAX_TOTAL
            or len(files) + (not any(p.name == name for p in files)) > MAX_ARTIFACTS
        ):
            raise StoreError("limits_exceeded")

    @synchronized
    def write_bytes(self, name, raw, *, replace=False):
        safe_name(name)
        target = self.path / name
        no_symlinks(target)
        if target.exists() and not replace:
            raise StoreError()
        self._quota(len(raw), name)
        temp = f"{uuid4()}.tmp"
        try:
            fd = os.open(
                temp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self.dir_fd,
            )
            with os.fdopen(fd, "wb") as file:
                file.write(raw)
                file.flush()
                os.fsync(file.fileno())
            if replace:
                os.replace(temp, name, src_dir_fd=self.dir_fd, dst_dir_fd=self.dir_fd)
            else:
                os.link(
                    temp,
                    name,
                    src_dir_fd=self.dir_fd,
                    dst_dir_fd=self.dir_fd,
                    follow_symlinks=False,
                )
                os.unlink(temp, dir_fd=self.dir_fd)
            os.fsync(self.dir_fd)
        except OSError:
            raise StoreError() from None
        finally:
            try:
                os.unlink(temp, dir_fd=self.dir_fd)
            except FileNotFoundError:
                pass
        return hashlib.sha256(raw).hexdigest()

    @synchronized
    def write_json(self, name, value, *, replace=False):
        return self.write_bytes(name, canonical(value), replace=replace)

    @synchronized
    def read_bytes(self, name):
        safe_name(name)
        return read_private(self.path / name)

    @synchronized
    def read_json(self, name):
        return decode_json(self.read_bytes(name))

    @synchronized
    def append_event(self, value, name="events.jsonl"):
        safe_name(name)
        raw = canonical(value) + b"\n"
        if len(raw) > MAX_EVENT:
            raise StoreError("limits_exceeded")
        path = self.path / name
        no_symlinks(path)
        if name not in self.journal_counts:
            self.journal_counts[name] = self.read_bytes(name).count(b"\n") if path.exists() else 0
        if self.journal_counts[name] >= MAX_EVENTS:
            raise StoreError("limits_exceeded")
        size = path.stat().st_size if path.exists() else 0
        self._quota(size + len(raw), name)
        try:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                0o600,
                dir_fd=self.dir_fd,
            )
            with os.fdopen(fd, "wb") as file:
                file.write(raw)
                file.flush()
                os.fsync(file.fileno())
            self.journal_counts[name] += 1
        except OSError:
            raise StoreError() from None


class PrivateStore:
    def __init__(self, root=None, *, project=None):
        self.project = Path(project or project_root()).absolute()
        candidate = Path(root or self.project / ".local/validation").absolute()
        no_symlinks(candidate)
        candidate = candidate.resolve()
        private = self.project.resolve() / ".local"
        if candidate == private or not candidate.is_relative_to(private):
            raise StoreError()
        git = subprocess.run(
            ["git", "-C", str(self.project), "rev-parse", "--git-dir"], capture_output=True
        )
        if git.returncode == 0:
            ignored = subprocess.run(
                ["git", "-C", str(self.project), "check-ignore", "-q", str(candidate / ".probe")],
                capture_output=True,
            )
            if ignored.returncode:
                raise StoreError()
        private_dirs(candidate, self.project)
        self.root = candidate

    def create(self, run_id: UUID):
        path = self.root / str(UUID(str(run_id)))
        try:
            path.mkdir(mode=0o700)
        except OSError:
            raise StoreError() from None
        return RunWriter(path)

    def open(self, run_id: UUID):
        path = self.root / str(UUID(str(run_id)))
        no_symlinks(path)
        if not path.is_dir():
            raise StoreError()
        return RunWriter(path)

    def definition_ref(self, private_name: str) -> UUID:
        # A separate lock prevents concurrent runs from changing assigned definition IDs.
        mapping_root = self.root / "definitions"
        private_dirs(mapping_root, self.project)
        with RunWriter(mapping_root) as writer:
            name = "definitions.json"
            value = writer.read_json(name) if (mapping_root / name).exists() else {}
            if private_name not in value:
                value[private_name] = str(uuid4())
                writer.write_json(name, value, replace=True)
            return UUID(value[private_name])
