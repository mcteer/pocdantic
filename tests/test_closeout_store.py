"""Immutable private record, descriptor identity and compare-and-swap storage tests."""

import os

import pytest
from closeout_support import inventory, private_file

from agent.closeout.models import CloseoutError, Inventory, validate
from agent.closeout.store import Store, read_owned


def test_revision_and_immutable_record(closeout_project):
    """A stale writer cannot overwrite an already sealed record or environment."""
    store = Store(closeout_project)
    inv = validate(Inventory, inventory())
    head = store.prepare(inv)
    ref = store.append(head.dossier_id, 1, "review", {"synthetic": True})
    assert store.head(head.dossier_id).revision == 2
    assert store.read(head.dossier_id, ref)["synthetic"] is True
    with pytest.raises(CloseoutError, match="revision_conflict"):
        store.append(head.dossier_id, 1, "review", {})
    assert store.inventory(store.head(head.dossier_id)) == inv


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "world-readable"])
def test_unsafe_input_rejected(tmp_path, kind):
    """Owned input must be a private regular file with stable one-link identity."""
    target = private_file(tmp_path / "source", b"safe")
    link = tmp_path / "input"
    if kind == "symlink":
        link.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, link)
    else:
        os.chmod(target, 0o644)
        link = target
    with pytest.raises(CloseoutError, match="storage_invalid"):
        read_owned(link)


def test_corrupt_record_and_extra_file_rejected(closeout_project):
    """Both altered payload and an extra file invalidate the exact sealed file set."""
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    ref = store.append(head.dossier_id, 1, "review", {"synthetic": True})
    private_file(store.record_path(head.dossier_id, ref.object_id) / "extra", b"oops")
    with pytest.raises(CloseoutError, match="integrity_failed"):
        store.read(head.dossier_id, ref)


def test_unsafe_id_cannot_escape_store(closeout_project):
    """Paths are formed from validated UUIDs, not caller-selected path fragments."""
    with pytest.raises(ValueError):
        Store(closeout_project).head("../../elsewhere")


def test_nonblocking_concurrent_writer_is_rejected(closeout_project):
    """A competing lock owner cannot mutate the same revision or block indefinitely."""
    import fcntl

    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    with open(store.dossier_path(head.dossier_id) / "control.lock", "rb") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(CloseoutError, match="revision_conflict"):
            store.append(head.dossier_id, 1, "review", {})
    assert store.head(head.dossier_id).revision == 1


def test_interrupted_write_is_private_partial_not_current(closeout_project, monkeypatch):
    """Seal interruption preserves the old head; a fresh attempt never resumes a partial."""
    import agent.closeout.store as module

    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    write = module.write_new

    def interrupted(path, data):
        """Interrupt exactly before terminal object seal publication."""
        if path.name == "seal.json":
            raise KeyboardInterrupt
        return write(path, data)

    monkeypatch.setattr(module, "write_new", interrupted)
    with pytest.raises(KeyboardInterrupt):
        store.append(head.dossier_id, 1, "review", {})
    assert store.head(head.dossier_id).revision == 1
    assert len(store.partials(head)) == 1
    monkeypatch.setattr(module, "write_new", write)
    fresh = store.append(head.dossier_id, 1, "review", {})
    assert str(fresh.object_id) not in store.partials(store.head(head.dossier_id))


def test_inode_replacement_during_read_rejected(tmp_path, monkeypatch):
    """A byte-identical renamed file is still a different acquired descriptor."""
    import agent.closeout.store as module

    path = private_file(tmp_path / "input", b"content")
    read = module.os.read
    replaced = False

    def raced(fd, size):
        """Replace the selected inode after its first descriptor read."""
        nonlocal replaced
        data = read(fd, size)
        if not replaced:
            replacement = private_file(tmp_path / "replacement", b"content")
            replacement.replace(path)
            replaced = True
        return data

    monkeypatch.setattr(module.os, "read", raced)
    with pytest.raises(CloseoutError, match="input_changed"):
        read_owned(path)


def test_wrong_owner_and_special_file_rejected(tmp_path, monkeypatch):
    """Ownership and file type checks precede even a bounded read."""
    import agent.closeout.store as module

    path = private_file(tmp_path / "input", b"x")
    monkeypatch.setattr(module.os, "getuid", lambda: path.stat().st_uid + 1)
    with pytest.raises(CloseoutError, match="storage_invalid"):
        read_owned(path)
    monkeypatch.undo()
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(CloseoutError, match="storage_invalid"):
        read_owned(fifo)


def test_restart_after_head_publication_failure_uses_new_operation(closeout_project, monkeypatch):
    """A saved draft revision never prevents a fresh same-revision retry after a crash."""
    import agent.closeout.store as module

    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    replace = module.os.replace

    def crash(*args, **kwargs):
        """Simulate failure immediately before the replaceable head publication."""
        raise OSError("synthetic interruption")

    monkeypatch.setattr(module.os, "replace", crash)
    with pytest.raises(OSError):
        store.append(head.dossier_id, 1, "review", {})
    assert store.head(head.dossier_id).revision == 1
    assert len(store.partials(head)) == 1
    monkeypatch.setattr(module.os, "replace", replace)
    store.append(head.dossier_id, 1, "review", {})
    assert store.head(head.dossier_id).revision == 2
    assert len(list((store.dossier_path(head.dossier_id) / "revisions").iterdir())) == 3


def test_lock_replacement_before_publication_keeps_previous_head(closeout_project, monkeypatch):
    """Replacing the acquired lock cannot publish even byte-identical new lock contents."""
    import agent.closeout.store as module

    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    original = module.sync_directory
    lock = store.dossier_path(head.dossier_id) / "control.lock"

    def replace_lock(path):
        """Swap the lock after sealing the new object, before its head becomes current."""
        original(path)
        if path.name == "revisions":
            private_file(lock.parent / "replacement", lock.read_bytes()).replace(lock)

    monkeypatch.setattr(module, "sync_directory", replace_lock)
    with pytest.raises(CloseoutError, match="input_changed"):
        store.append(head.dossier_id, 1, "review", {})
    assert store.head(head.dossier_id).revision == 1
