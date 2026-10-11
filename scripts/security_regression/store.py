"""Strict preflight around the existing immutable private evidence writer."""

import os
import stat
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

from agent.validation.store import PrivateStore, StoreError

from .models import RegressionError, canonical, decode


def check(path, directory=False):
    """Reject links, foreign ownership, excessive permissions and hard-linked records."""
    info = path.lstat()
    expected = 0o700 if directory else 0o600
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not kind(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != expected
        or (not directory and info.st_nlink != 1)
    ):
        raise RegressionError("unsafe_path")
    return info.st_dev, info.st_ino


class Writer:
    """Expose immutable bounded operations while checking the original directory inode."""

    def __init__(self, writer):
        """Bind to a locked writer after safe directory preflight."""
        self.writer = writer
        self.path = writer.path
        self.identity = check(self.path, True)

    def preflight(self):
        """Reject replaced directories or unsafe existing files before every operation."""
        if check(self.path, True) != self.identity:
            raise RegressionError("unsafe_path")
        entries = list(self.path.iterdir())
        if len(entries) > 101 or sum(p.lstat().st_size for p in entries) > 100 * 1024 * 1024:
            raise RegressionError("limits_exceeded")
        for path in entries:
            check(path)

    def write(self, name, value):
        """Persist a canonical record once; report and manifest have an eight-MiB limit."""
        self.preflight()
        raw = canonical(value)
        if len(raw) > (8 if name in {"manifest.json", "report.json"} else 10) * 1024 * 1024:
            raise RegressionError("limits_exceeded")
        try:
            return self.writer.write_bytes(name, raw)
        except StoreError as error:
            raise RegressionError(
                "limits_exceeded" if str(error) == "limits_exceeded" else "storage_error"
            ) from None

    def read(self, name):
        """Check path and descriptor identity around a bounded read."""
        self.preflight()
        if Path(name).name != name or name in {".", ".."}:
            raise RegressionError("unsafe_path")
        path = self.path / name
        before = check(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != before or not stat.S_ISREG(info.st_mode):
                raise RegressionError("unsafe_path")
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise RegressionError("unsafe_path")
            if info.st_nlink != 1:
                raise RegressionError("unsafe_path")
            with os.fdopen(fd, "rb", closefd=False) as source:
                raw = source.read(10 * 1024 * 1024 + 1)
        finally:
            os.close(fd)
        if check(path) != before:
            raise RegressionError("unsafe_path")
        return decode(raw, (8 if name in {"manifest.json", "report.json"} else 10) * 1024 * 1024)


class Store:
    """Own only the separate ignored security-regression root, never application journals."""

    def __init__(self, project, *, readonly=False):
        """Preflight private ancestors before helpers can modify existing permissions."""
        self.project = Path(project).absolute()
        self.root = self.project / ".local/security-regression"
        for path in (self.project, *self.project.parents):
            if path.is_symlink():
                raise RegressionError("unsafe_path")
        for path in (self.project / ".local", self.root):
            if path.exists() or path.is_symlink():
                check(path, True)
            elif readonly:
                raise RegressionError("storage_error")
        # Read-only inspection must not even create a missing lock or directory.
        self.store = None if readonly else PrivateStore(self.root, project=self.project)

    @contextmanager
    def create(self, run_id):
        """Create a fresh UUID directory and hold exclusive ownership until final seal."""
        try:
            if str(UUID(run_id)) != run_id:
                raise RegressionError("unsafe_path")
            with self.store.create(UUID(run_id)) as writer:
                yield Writer(writer)
        except StoreError:
            raise RegressionError("storage_error") from None

    @contextmanager
    def open(self, run_id):
        """Acquire an existing lock without writes; active runs report busy."""
        import fcntl

        if str(UUID(run_id)) != run_id:
            raise RegressionError("unsafe_path")
        path = self.root / run_id
        check(path, True)
        check(path / ".lock")
        fd = os.open(path / ".lock", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RegressionError("run_busy") from None

            # Minimal reader adapts existing bounded reads without opening a writing lock.
            class Reader:
                """Read immutable bytes through inherited no-follow storage operations."""

                def __init__(self, root):
                    """Bind this read-only adapter to the verified run directory."""
                    self.path = root

                def read_bytes(self, name):
                    """Use the existing bounded descriptor reader."""
                    from agent.validation.store import read_private

                    return read_private(self.path / name)

            yield Writer(Reader(path))
        finally:
            os.close(fd)
