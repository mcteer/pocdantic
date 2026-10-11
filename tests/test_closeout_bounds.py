"""Quota, deadline, exact revision and repeatable bounded-report contracts."""

import time

import pytest
from closeout_support import inventory

from agent.closeout.assessment import assemble, report
from agent.closeout.counting import parse_records
from agent.closeout.models import CloseoutError, Inventory, decode, validate
from agent.closeout.store import Store, deadline_check


def test_byte_partial_usage_and_file_quota(closeout_project, monkeypatch):
    """Orphan bytes consume quota, and rejected growth never advances a sealed head."""
    import agent.closeout.store as module

    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    before = store.head(head.dossier_id)
    monkeypatch.setattr(
        module,
        "MAX_BYTES",
        store._usage(store.dossier_path(head.dossier_id), time.monotonic() + 30) + 1,
    )
    with pytest.raises(CloseoutError, match="capacity_exceeded"):
        store.append(head.dossier_id, 1, "review", {})
    assert store.head(head.dossier_id) == before
    monkeypatch.undo()
    with pytest.raises(CloseoutError, match="capacity_exceeded"):
        store.append(head.dossier_id, 1, "package", {}, {f"file-{i}": b"" for i in range(99)})


def test_json_depth_record_and_deadline():
    """Pathological structures and overlong records are refused before normalization."""
    with pytest.raises(CloseoutError, match="capacity_exceeded"):
        decode(b"[" * 10 + b"0" + b"]" * 10)
    with pytest.raises(CloseoutError, match="capacity_exceeded"):
        parse_records("execution-roster-v1", b"x" * 65537, None)
    with pytest.raises(CloseoutError, match="deadline_exceeded"):
        deadline_check(time.monotonic() - 1)


def test_repeatable_report_preserves_all_bytes(closeout_project):
    """Repeated inspection produces identical output and changes no store metadata."""
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    ref = assemble(store, head)
    head = store.head(head.dossier_id)
    root = store.dossier_path(head.dossier_id)
    before = {
        str(p): (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino)
        for p in root.rglob("*")
        if p.is_file()
    }
    expected = report(store, head, ref.object_id)
    started = time.monotonic()
    for _ in range(10):
        assert report(store, head, ref.object_id) == expected
    assert time.monotonic() - started < 5
    assert before == {
        str(p): (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino)
        for p in root.rglob("*")
        if p.is_file()
    }


def test_revision_cap_preserves_previous_sealed_head(closeout_project):
    """The hundredth revision is retained and the hundred-and-first write is refused."""
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    for revision in range(1, 100):
        store.append(head.dossier_id, revision, "review", {})
    assert store.head(head.dossier_id).revision == 100
    with pytest.raises(CloseoutError, match="capacity_exceeded"):
        store.append(head.dossier_id, 100, "review", {})
    assert store.head(head.dossier_id).revision == 100


def test_ten_thousand_activity_records_under_budget():
    """A full bounded activity input is normalized and reconciled without quadratic joins."""
    import json
    from types import SimpleNamespace
    from uuid import uuid4

    from agent.closeout.counting import activity_set
    from agent.closeout.models import ImportManifest

    manifest = validate(
        ImportManifest,
        {
            "profile_id": str(uuid4()),
            "format": "vault-activity-v1",
            "provenance": "synthetic",
            "input_digest": "a" * 64,
            "observed_at": "2026-10-10T12:00:00Z",
            "environment_digest": "b" * 64,
            "scope": str(uuid4()),
            "first_use_field": "client_first_usage_time",
            "period_start": "2026-10-01T00:00:00Z",
            "period_end": "2026-11-01T00:00:00Z",
            "mounts": ["mount"],
        },
    )
    raw = b"\n".join(
        json.dumps(
            {
                "client_id": f"client-{i}",
                "client_type": "entity",
                "namespace_id": "ns",
                "mount_accessor": "mount",
                "client_first_usage_time": "2026-10-10T11:00:00Z",
            }
        ).encode()
        for i in range(10000)
    )
    start = time.monotonic()
    rows = parse_records("vault-activity-v1", raw, manifest)
    keys, other = activity_set(
        SimpleNamespace(normalized=rows),
        SimpleNamespace(namespace="ns", cluster="cluster"),
        ["mount"],
    )
    assert len(keys) == 10000 and not other
    assert time.monotonic() - start < 5


@pytest.mark.parametrize("quota", ["individual", "package"])
def test_actual_byte_limits_refuse_growth_before_any_partial(closeout_project, quota):
    """Actual oversized bytes cannot enter a file or a fifty-MiB package, even privately."""
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    files = (
        {"oversized.raw": b"x" * (10 * 1024 * 1024 + 1)}
        if quota == "individual"
        else {f"support-{i}.raw": b"x" * (9 * 1024 * 1024) for i in range(6)}
    )
    with pytest.raises(CloseoutError, match="capacity_exceeded"):
        store.append(head.dossier_id, 1, "package", {}, files)
    assert store.head(head.dossier_id) == head
    assert store.partials(head) == []
