"""Owner-only immutable records with byte seals, bounded writes and read-only inspection.

A dossier head is the only replaceable file. Every mutation compares its revision under an
exclusive lock and publishes a sealed object before advancing that head. Partial objects stay
visible; no old evidence, permissions or source files are repaired by this module.
"""

import fcntl
import os
import stat
import time
from contextlib import contextmanager
from contextvars import ContextVar
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from uuid import UUID

from .models import (
    CloseoutError,
    Head,
    Inventory,
    RecordRef,
    byte_digest,
    canonical,
    decode,
    digest,
    fresh_id,
    require,
    validate,
)

OPERATION_DEADLINE = ContextVar("closeout_deadline", default=None)
PUBLICATION_GUARD = ContextVar("closeout_publication_guard", default=None)


@contextmanager
def operation():
    """Share one thirty-second local deadline across nested reads and writes."""
    token = OPERATION_DEADLINE.set(time.monotonic() + 30)
    try:
        yield
    finally:
        OPERATION_DEADLINE.reset(token)


MAX_FILE = 10 * 1024 * 1024
MAX_BYTES = 100 * 1024 * 1024
MAX_FILES = 100
LIMITS = {
    "inventory": 100,
    "source": 100,
    "experiment": 4,
    "measurement": 100,
    "assessment": 100,
    "review": 100,
    "package": 20,
    "handoff": 20,
}


def deadline_check(deadline):
    """Bound every loop/transaction, including its final publication checks."""
    limit = min(deadline, OPERATION_DEADLINE.get() or deadline)
    require(time.monotonic() <= limit, "deadline_exceeded")


def checked_stat(info, directory=False):
    """Validate file kind, current owner, exact private mode and hard-link count."""
    require(info.st_uid == os.getuid(), "storage_invalid")
    require(
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "storage_invalid"
    )
    require(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600), "storage_invalid")
    if not directory:
        require(info.st_nlink == 1, "storage_invalid")


def no_links(path):
    """Reject symlink ancestors rather than silently resolving caller-selected input paths."""
    require(".." not in path.parts, "storage_invalid")
    for part in (path, *path.parents):
        require(not part.is_symlink(), "storage_invalid")


def identity(info):
    """Compare inode, byte size and mutation metadata around a descriptor read."""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_owned(path, limit=MAX_FILE, deadline=None):
    """Read a private regular file using a stable no-follow descriptor and bounded bytes."""
    path = Path(path).absolute()
    no_links(path)
    deadline = deadline or OPERATION_DEADLINE.get() or time.monotonic() + 30
    try:
        checked_stat(path.parent.lstat(), directory=True)
        before = path.lstat()
        checked_stat(before)
        require(before.st_size <= limit, "capacity_exceeded")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            checked_stat(opened)
            require(identity(before) == identity(opened), "input_changed")
            data = bytearray()
            while True:
                if deadline is not None:
                    deadline_check(deadline)
                chunk = os.read(fd, min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                require(len(data) <= limit, "capacity_exceeded")
            require(
                identity(opened) == identity(os.fstat(fd)) == identity(path.lstat()),
                "input_changed",
            )
            no_links(path)
            return bytes(data)
        finally:
            os.close(fd)
    except OSError:
        raise CloseoutError("storage_invalid") from None


def private_dir(path):
    """Create only absent private directories and reject existing unsafe ones without chmod."""
    path = Path(path)
    no_links(path)
    if not path.exists():
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    checked_stat(path.lstat(), directory=True)
    return path


def write_new(path, data):
    """Exclusively write and sync immutable bytes; partial files remain after interruption."""
    require(len(data) <= MAX_FILE, "capacity_exceeded")
    no_links(path)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                require(n > 0, "storage_invalid")
                view = view[n:]
            os.fsync(fd)
            checked_stat(os.fstat(fd))
        finally:
            os.close(fd)
    except OSError:
        raise CloseoutError("storage_invalid") from None


def sync_directory(path):
    """Durably publish newly sealed directory entries before their head can reference them."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        checked_stat(os.fstat(fd), directory=True)
        os.fsync(fd)
    finally:
        os.close(fd)


def runtime_digest():
    """Fingerprint installed maintained code without reading dotenv or private evidence."""
    root = Path(__file__).parent.parent
    hashes = {
        str(p.relative_to(root)): byte_digest(p.read_bytes()) for p in sorted(root.rglob("*.py"))
    }
    project = root.parent.parent
    for name in ("pyproject.toml", "uv.lock"):
        path = project / name
        if path.is_file():
            hashes[name] = byte_digest(path.read_bytes())
    for name in ("pydantic", "pydantic-ai-slim", "cryptography", "httpx", "PyJWT"):
        try:
            hashes["installed:" + name] = version(name)
        except PackageNotFoundError:
            hashes["installed:" + name] = "absent"
    return digest(hashes)


class Store:
    """Access one fixed project-private closeout root without initialization on reads."""

    def __init__(self, project=None):
        """Select the project directory; defer all disk mutation to explicit commands."""
        self.project = Path(project or Path.cwd()).absolute()
        self.root = self.project / ".local" / "closeout"

    def dossier_path(self, dossier_id):
        """Resolve an opaque UUID beneath the fixed root and verify private parents."""
        path = self.root / str(UUID(str(dossier_id)))
        for parent in (self.root.parent, self.root, path):
            no_links(parent)
            checked_stat(parent.lstat(), directory=True)
        return path

    def record_path(self, dossier_id, object_id):
        """Resolve a typed object ID, never a caller-selected relative path."""
        path = self.dossier_path(dossier_id) / "records" / str(UUID(str(object_id)))
        for parent in (path.parent, path):
            no_links(parent)
            checked_stat(parent.lstat(), directory=True)
        return path

    def head(self, dossier_id):
        """Read/verify the revision head without creating locks or repairing permissions."""
        raw = decode(read_owned(self.dossier_path(dossier_id) / "state.json"))
        require(
            set(raw) == {"head", "digest"} and digest(raw["head"]) == raw["digest"],
            "integrity_failed",
        )
        head = validate(Head, raw["head"])
        require(str(head.dossier_id) == str(dossier_id), "integrity_failed")
        require(len({r.object_id for r in head.records}) == len(head.records), "integrity_failed")
        return head

    def ref(self, head, object_id, kind=None):
        """Require one object in the dossier's immutable typed index."""
        ref = next((r for r in head.records if str(r.object_id) == str(object_id)), None)
        require(ref is not None, "evidence_missing")
        require(kind is None or ref.kind == kind, "schema_invalid")
        return ref

    def read_files(self, dossier_id, ref):
        """Verify exact file set and byte seal before returning any original contents."""
        deadline = time.monotonic() + 30
        path = self.record_path(dossier_id, ref.object_id)
        directory_identity = identity(path.lstat())
        seal_raw = read_owned(path / "seal.json", deadline=deadline)
        require(byte_digest(seal_raw) == ref.seal_digest, "integrity_failed")
        seal = decode(seal_raw)
        require(
            set(seal) == {"schema_version", "files"}
            and type(seal["schema_version"]) is int
            and seal["schema_version"] == 1,
            "integrity_failed",
        )
        expected = seal["files"]
        require(isinstance(expected, dict) and 0 < len(expected) <= MAX_FILES, "integrity_failed")
        actual = set()
        result = {}
        for file in path.iterdir():
            deadline_check(deadline)
            require(file.is_file() and not file.is_symlink(), "integrity_failed")
            actual.add(file.name)
        require(actual == set(expected) | {"seal.json"}, "integrity_failed")
        for name, hash_value in expected.items():
            require(
                name == Path(name).name and name not in {".", "..", "seal.json"}, "integrity_failed"
            )
            data = read_owned(path / name, deadline=deadline)
            require(byte_digest(data) == hash_value, "integrity_failed")
            result[name] = data
        require(read_owned(path / "seal.json", deadline=deadline) == seal_raw, "input_changed")
        require(identity(path.lstat()) == directory_identity, "input_changed")
        require({p.name for p in path.iterdir()} == actual, "input_changed")
        for name, data in result.items():
            require(read_owned(path / name, deadline=deadline) == data, "input_changed")
        return result

    def read(self, dossier_id, ref):
        """Return structured payload only after every sealed original byte is verified."""
        return decode(self.read_files(dossier_id, ref)["payload.json"])

    def inventory(self, head):
        """Load the currently selected immutable environment inventory."""
        return validate(
            Inventory, self.read(head.dossier_id, self.ref(head, head.inventory_id, "inventory"))
        )

    def records(self, head, kind):
        """Enumerate a typed immutable record family; no selector hides failed history."""
        return [(r, self.read(head.dossier_id, r)) for r in head.records if r.kind == kind]

    def prepare(self, inventory):
        """Create a new dossier exclusively, leaving every established dossier untouched."""
        private_dir(self.root.parent)
        private_dir(self.root)
        dossier_id = fresh_id()
        path = private_dir(self.root / str(dossier_id))
        private_dir(path / "records")
        private_dir(path / "revisions")
        write_new(path / "control.lock", b"")
        env = digest(inventory)
        ref = self._write_record(path, "inventory", inventory, env, {}, time.monotonic() + 30)
        head = Head(dossier_id=dossier_id, revision=1, inventory_id=ref.object_id, records=[ref])
        self._publish(path, head, None)
        return head

    @contextmanager
    def transaction(self, dossier_id, revision):
        """Lock the stable existing descriptor and reject stale/busy mutation requests."""
        path = self.dossier_path(dossier_id)
        info = path.lstat()
        lock = path / "control.lock"
        read_owned(lock)
        fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
        try:
            checked_stat(os.fstat(fd))
            require(identity(os.fstat(fd)) == identity(lock.lstat()), "input_changed")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CloseoutError("revision_conflict") from None
            head = self.head(dossier_id)
            require(head.revision == revision, "revision_conflict")
            require(head.revision < 100, "capacity_exceeded")
            deadline = time.monotonic() + 30

            def guard():
                """Recheck the acquired lock/root immediately before publishing any head."""
                require(identity(os.fstat(fd)) == identity(lock.lstat()), "input_changed")
                current = path.lstat()
                checked_stat(current, directory=True)
                require(
                    (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), "input_changed"
                )
                deadline_check(deadline)

            token = PUBLICATION_GUARD.set(guard)
            try:
                yield path, head, deadline
                guard()
            finally:
                PUBLICATION_GUARD.reset(token)
            require(identity(os.fstat(fd)) == identity(lock.lstat()), "input_changed")
            require(
                info.st_ino == path.lstat().st_ino and info.st_dev == path.lstat().st_dev,
                "input_changed",
            )
            deadline_check(deadline)
        finally:
            os.close(fd)

    def _usage(self, path, deadline):
        """Count all bytes, including orphaned partial writes, without traversing links."""
        total = 0
        for file in path.rglob("*"):
            deadline_check(deadline)
            require(not file.is_symlink(), "storage_invalid")
            info = file.lstat()
            checked_stat(info, directory=stat.S_ISDIR(info.st_mode))
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
        return total

    def _write_record(self, path, kind, payload, env, files, deadline, object_id=None):
        """Seal a new object's exact file set last; no overwrite or partial resume occurs."""
        require(kind in LIMITS)
        object_id = object_id or fresh_id()
        require("payload.json" not in files, "storage_invalid")
        content = {"payload.json": canonical(payload), **files}
        require(len(content) + 1 <= MAX_FILES and "seal.json" not in content, "capacity_exceeded")
        for name, data in content.items():
            require(name == Path(name).name and name not in {".", ".."}, "storage_invalid")
            require(len(data) <= MAX_FILE, "capacity_exceeded")
        reserve = sum(len(v) for v in content.values()) + 65536
        if kind in {"package", "handoff"}:
            require(sum(len(v) for v in content.values()) <= 50 * 1024 * 1024, "capacity_exceeded")
        require(self._usage(path, deadline) + reserve <= MAX_BYTES, "capacity_exceeded")
        require(not (path / "records" / str(object_id)).exists(), "integrity_failed")
        out = private_dir(path / "records" / str(object_id))
        for name, data in content.items():
            deadline_check(deadline)
            write_new(out / name, data)
        deadline_check(deadline)
        seal = canonical(
            {
                "schema_version": 1,
                "files": {name: byte_digest(data) for name, data in content.items()},
            }
        )
        write_new(out / "seal.json", seal)
        sync_directory(out)
        sync_directory(out.parent)
        return RecordRef(
            object_id=object_id, kind=kind, seal_digest=byte_digest(seal), environment_digest=env
        )

    def _publish(self, path, head, previous):
        """Publish immutable revision bytes then atomically replace the compare-checked head."""
        raw = canonical({"head": head.model_dump(mode="json"), "digest": digest(head)})
        require(
            self._usage(path, time.monotonic() + 30) + 2 * len(raw) <= MAX_BYTES,
            "capacity_exceeded",
        )
        write_new(path / "revisions" / f"{head.revision}-{head.records[-1].object_id}.json", raw)
        temp = path / f"head-{fresh_id()}.tmp"
        write_new(temp, raw)
        sync_directory(path / "revisions")
        deadline_check(time.monotonic() + 30)
        if previous is not None:
            require(self.head(head.dossier_id) == previous, "input_changed")
        if guard := PUBLICATION_GUARD.get():
            guard()
        os.replace(temp, path / "state.json")
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def append(self, dossier_id, revision, kind, payload, files=None, object_id=None):
        """Append an immutable typed record and advance only the mutation revision."""
        with self.transaction(dossier_id, revision) as (path, head, deadline):
            require(
                sum(r.kind == kind for r in head.records) < LIMITS.get(kind, 0), "capacity_exceeded"
            )
            if kind in {"package", "handoff"}:
                require(
                    sum(r.kind in {"package", "handoff"} for r in head.records) < 20,
                    "capacity_exceeded",
                )
            env = digest(self.inventory(head)) if kind != "inventory" else digest(payload)
            ref = self._write_record(path, kind, payload, env, files or {}, deadline, object_id)
            new = Head(
                dossier_id=head.dossier_id,
                revision=head.revision + 1,
                inventory_id=ref.object_id if kind == "inventory" else head.inventory_id,
                records=[*head.records, ref],
            )
            deadline_check(deadline)
            self._publish(path, new, head)
            return ref

    def partials(self, head):
        """Expose unindexed interrupted objects by opaque ID without resuming them."""
        indexed = {str(r.object_id) for r in head.records}
        paths = (self.dossier_path(head.dossier_id) / "records").iterdir()
        return [str(UUID(p.name)) for p in paths if p.name not in indexed]
