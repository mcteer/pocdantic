"""Bounded private storage for immutable validation artifacts and journals.

Directory permissions, symlink rejection, descriptor-based I/O, quotas, and locks
protect evidence from accidental exposure or overwrite. Reports are derived views;
raw source records and native credential handles belong only in this store.
"""

import fcntl
import hashlib
import json
import os
import stat
import subprocess
import threading
from contextlib import ExitStack, contextmanager
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
        """Represent a storage failure using the caller's safe code, not filesystem details.

        Callers must supply a supported code; this constructor does not validate it.
        """
        super().__init__(code)


def decode_json(raw: bytes):
    """Decode bounded strict JSON, rejecting duplicate keys, excessive depth, and nonfinite
    values.
    """
    if len(raw) > MAX_ARTIFACT:
        raise StoreError("limits_exceeded")

    def pairs(items):
        """Build each object while rejecting duplicate keys instead of silently taking the
        last value.
        """
        result = {}
        for key, value in items:
            if key in result:
                raise StoreError("schema_invalid")
            result[key] = value
        return result

    def invalid(_):
        """Reject nonstandard numeric constants such as NaN and Infinity."""
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
    """Reject symlinks in the selected path and its ancestors."""
    for part in (path, *path.parents):
        if part.is_symlink():
            raise StoreError()


def project_root() -> Path:
    """Resolve the repository root used to anchor private validation storage."""
    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    return Path(result.stdout.strip()) if result.returncode == 0 else Path.cwd()


def private_dirs(path: Path, boundary: Path):
    """Create private directories beneath the allowed boundary and reject unsafe ownership
    or links.
    """
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
    """Require a simple bounded artifact filename without traversal or path separators."""
    if not isinstance(name, str) or not name or name in {".", ".."} or Path(name).name != name:
        raise StoreError()
    return name


def read_private(path: Path) -> bytes:
    """Read a bounded regular file using a no-follow descriptor, rejecting unsafe file
    types.
    """
    no_symlinks(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                raise StoreError()
            raw = file.read(MAX_ARTIFACT + 1)
        if len(raw) > MAX_ARTIFACT:
            raise StoreError("limits_exceeded")
        return raw
    except OSError:
        raise StoreError() from None


def synchronized(method):
    """Wrap a writer method in its shared reentrant lock."""

    @wraps(method)
    def locked(self, *args, **kwargs):
        """Hold the writer lock while the wrapped storage operation completes."""
        with self.mutex:
            return method(self, *args, **kwargs)

    return locked


class RunWriter:
    def __init__(self, path):
        """Bind bounded storage operations to one private run directory."""
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
        """Return the writer whose directory descriptor and file lock were acquired at
        construction.
        """
        return self

    def __exit__(self, *_):
        """Release descriptors and locks even when a storage operation raised."""
        fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
        os.close(self.lock_fd)
        os.close(self.dir_fd)

    def _quota(self, added, name=None):
        """Reject writes that would exceed file, byte, or run-level storage limits."""
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
        """Atomically persist bounded bytes, refusing overwrite unless explicitly
        requested.

        Temporary files are synced before publication so immutable artifacts are not
        visible as partially written content.
        """
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
        """Serialize a contract canonically and persist it through the bounded byte writer."""
        return self.write_bytes(name, canonical(value), replace=replace)

    @synchronized
    def read_bytes(self, name):
        """Read a named bounded artifact relative to the locked run directory."""
        safe_name(name)
        return read_private(self.path / name)

    @synchronized
    def read_json(self, name):
        """Decode a private artifact with the strict bounded JSON parser."""
        return decode_json(self.read_bytes(name))

    @synchronized
    def inventory(self):
        """Hash durable input files, excluding transient locks and derived report
        artifacts.
        """
        entries = [p for p in self.path.iterdir() if p.name != ".lock"]
        if (
            len(entries) > MAX_ARTIFACTS
            or any(p.is_symlink() or not p.is_file() for p in entries)
            or sum(p.stat().st_size for p in entries) > MAX_TOTAL
        ):
            raise StoreError("limits_exceeded")
        return {
            p.name: hashlib.sha256(self.read_bytes(p.name)).hexdigest()
            for p in sorted(self.path.iterdir())
            if p.name != ".lock" and not p.name.endswith(".tmp") and not p.name.startswith("report")
        }

    @synchronized
    def append_event(self, value, name="events.jsonl"):
        """Append and sync a bounded JSONL event to the selected private journal."""
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
        """Prepare a private, Git-ignored validation root beneath the project’s .local
        directory.
        """
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
        """Create a new private validation directory and return its locking writer."""
        path = self.root / str(UUID(str(run_id)))
        try:
            path.mkdir(mode=0o700)
        except OSError:
            raise StoreError() from None
        return RunWriter(path)

    def open(self, run_id: UUID):
        """Open an existing validation run by its opaque UUID without accepting arbitrary
        paths.
        """
        path = self.root / str(UUID(str(run_id)))
        no_symlinks(path)
        if not path.is_dir():
            raise StoreError()
        return RunWriter(path)

    def definition_ref(self, private_name: str) -> UUID:
        # A separate lock prevents concurrent runs from changing assigned definition IDs.
        """Return a stable private UUID for a profile or workload definition under a lock."""
        mapping_root = self.root / "definitions"
        private_dirs(mapping_root, self.project)
        with RunWriter(mapping_root) as writer:
            name = "definitions.json"
            value = writer.read_json(name) if (mapping_root / name).exists() else {}
            if private_name not in value:
                value[private_name] = str(uuid4())
                writer.write_json(name, value, replace=True)
            return UUID(value[private_name])

    @contextmanager
    def open_many(self, run_ids):
        """Lock a bounded set of runs in deterministic order to avoid closeout deadlocks."""
        ids = [UUID(str(i)) for i in run_ids]
        if not 1 <= len(ids) <= 4 or len(set(ids)) != len(ids):
            raise StoreError("invalid_selection")
        with ExitStack() as stack:
            yield {i: stack.enter_context(self.open(i)) for i in sorted(ids, key=str)}

    def create_closeout(self, snapshot_id):
        """Create a separate immutable closeout directory with an opaque ID."""
        root = self.root / "closeouts"
        private_dirs(root, self.project)
        path = root / str(UUID(str(snapshot_id)))
        try:
            path.mkdir(mode=0o700)
        except OSError:
            raise StoreError() from None
        return RunWriter(path)

    def open_closeout(self, snapshot_id):
        """Open an existing closeout by its opaque ID within the private boundary."""
        path = self.root / "closeouts" / str(UUID(str(snapshot_id)))
        no_symlinks(path)
        if not path.is_dir():
            raise StoreError("evidence_missing")
        return RunWriter(path)
