import json
import os
from uuid import uuid4

import pytest

from agent.validation.store import PrivateStore, StoreError, decode_json


@pytest.fixture
def store(tmp_path):
    return PrivateStore(tmp_path / ".local/validation", project=tmp_path)


def test_private_atomic_immutable_and_lock(store):
    run = uuid4()
    with store.create(run) as writer:
        writer.write_json("run.json", {"state": "running"})
        with pytest.raises(StoreError):
            store.open(run)
        writer.write_bytes("source.json", b"{}")
        with pytest.raises(StoreError):
            writer.write_bytes("source.json", b"changed")
        with pytest.raises(StoreError):
            writer.write_bytes("../escape", b"bad")
        assert writer.path.stat().st_mode & 0o777 == 0o700
        assert (writer.path / "source.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(StoreError):
        store.create(run)
    with store.open(run) as reader:
        assert reader.read_json("run.json")["state"] == "running"


def test_symlinks_and_roots(tmp_path):
    with pytest.raises(StoreError):
        PrivateStore(tmp_path / "outside", project=tmp_path)
    (tmp_path / ".local").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(StoreError):
        PrivateStore(tmp_path / ".local/validation", project=tmp_path)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b"\xff", b"NaN", b"[" * 17 + b"0" + b"]" * 17])
def test_strict_input(raw):
    with pytest.raises(StoreError):
        decode_json(raw)


def test_quota_and_atomic_failure(store, monkeypatch):
    with store.create(uuid4()) as writer:
        with pytest.raises(StoreError):
            writer.write_bytes("big", b"x" * (10 * 1024 * 1024 + 1))
        writer.write_json("report.json", {"revision": 1})

        def fail(*args, **kwargs):
            raise OSError("private canary")

        monkeypatch.setattr(os, "replace", fail)
        with pytest.raises(StoreError, match="storage_error"):
            writer.write_json("report.json", {"revision": 2}, replace=True)
        assert json.loads((writer.path / "report.json").read_text()) == {"revision": 1}
        assert not list(writer.path.glob("*.tmp"))


def test_stable_definition_map_and_ignored_root(store, tmp_path):
    ref = store.definition_ref("private-name")
    assert store.definition_ref("private-name") == ref
    assert store.definition_ref("another-name") != ref
    import subprocess

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    with pytest.raises(StoreError):
        PrivateStore(tmp_path / ".local/validation", project=tmp_path)
    (tmp_path / ".gitignore").write_text(".local/\n")
    assert PrivateStore(tmp_path / ".local/validation", project=tmp_path)


def test_multi_lock_contention_releases_and_inventory(store):
    ids = [uuid4(), uuid4()]
    for i in ids:
        with store.create(i) as w:
            w.write_json("run.json", {"value": str(i)})
    with store.open(ids[1]):
        with pytest.raises(StoreError):
            with store.open_many(ids):
                pass
    with store.open_many(ids) as writers:
        assert list(writers) == sorted(ids, key=str)
        before = writers[ids[0]].inventory()
        writers[ids[0]].write_json("new.json", {})
        assert before != writers[ids[0]].inventory()


def test_closeout_storage_immutable_and_quota(store, monkeypatch):
    snapshot = uuid4()
    with store.create_closeout(snapshot) as writer:
        writer.write_json("closeout.json", {"revision": "a" * 64})
        with pytest.raises(StoreError):
            writer.write_json("closeout.json", {})
        assert writer.path.stat().st_mode & 0o777 == 0o700
        monkeypatch.setattr("agent.validation.store.MAX_ARTIFACTS", 1)
        with pytest.raises(StoreError):
            writer.write_json("another.json", {})
    with store.open_closeout(snapshot) as writer:
        assert writer.read_json("closeout.json")["revision"] == "a" * 64
