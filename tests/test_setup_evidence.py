"""Capability evidence cannot promote synthetic, stale, foreign or corrupt records."""

import pytest

from agent.setup.readiness import local_check
from tests.portability_support import deployment
from tests.test_setup_readiness import configured


def test_arbitrary_evidence_files_do_not_promote(tmp_path):
    """A hand-written support claim is not a trusted sealed run."""
    settings, _, _, _, _ = deployment(tmp_path)
    root = tmp_path / ".local/validation"
    root.mkdir()
    (root / "claims.json").write_text('{"supported":true}')
    report = local_check(configured(settings), project=tmp_path)
    assert all(o.state != "supported" for o in report.observations)


def test_context_contains_mode_and_trust_but_no_credentials(tmp_path):
    """Private fingerprints separate routes while excluding credential values."""
    from agent.validation.context import capture_context

    settings, _, _, _, _ = deployment(tmp_path)
    context = capture_context(settings)
    assert context.selectors["authentication_mode"] == "user-jwt"
    assert context.selectors["vault_read_path"] == "team-db/creds/reader"
    assert "synthetic-native-token" not in context.model_dump_json()


@pytest.mark.parametrize("damage", [None, "stale", "foreign", "synthetic", "cleanup", "unmatched"])
def test_native_projection_requires_recent_same_context_and_both_cleanup(
    tmp_path, monkeypatch, damage
):
    """Trusted reconstruction is still insufficient with stale/foreign/synthetic context."""
    from contextlib import contextmanager
    from datetime import UTC, datetime, timedelta
    from types import SimpleNamespace
    from uuid import uuid4

    from agent.setup.models import CapabilityObservation
    from agent.setup.readiness import demonstrated
    from agent.validation.context import capture_context
    from agent.validation.models import ValidationRun

    settings, _, _, _, _ = deployment(tmp_path)
    root = tmp_path / ".local/validation"
    root.mkdir()
    (root / str(uuid4())).mkdir()
    run = ValidationRun(
        suite="live-portability",
        suite_revision="a" * 64,
        mode="live",
        selected=("user-jwt-read",),
        configuration_fingerprint="b" * 64,
        authentication_mode="user-jwt",
        source_product="generic",
        execution_origin="synthetic" if damage == "synthetic" else "provider",
        state="finalized",
        completed_at=datetime.now(UTC) - timedelta(hours=25 if damage == "stale" else 1),
    )
    context = capture_context(settings)
    if damage == "foreign":
        context = capture_context(settings.model_copy(update={"database_host": "foreign.example"}))
    observation = uuid4()
    bindings = [
        SimpleNamespace(
            observation_id=observation,
            source_kind="vault",
            phase="credential" if i < 3 else "cleanup",
            operation_ref=uuid4(),
        )
        for i in range(5)
    ]

    class Writer:
        def read_json(self, name):
            return (run if name == "run.json" else context).model_dump(mode="json")

    class Store:
        def __init__(self, **kwargs):
            pass

        @contextmanager
        def open(self, run_id):
            yield Writer()

    monkeypatch.setattr("agent.validation.store.PrivateStore", Store)
    monkeypatch.setattr("agent.validation.report.read_bindings", lambda writer: bindings)
    monkeypatch.setattr(
        "agent.validation.report.rebuild_report",
        lambda *a, **kw: SimpleNamespace(
            scenarios=[
                SimpleNamespace(
                    observation_id=observation,
                    scenario="user-jwt-read",
                    outcome="pass",
                    cleanup="failed" if damage == "cleanup" else "revoked",
                )
            ],
            blockers=[],
            correlations=[
                SimpleNamespace(
                    operation_ref=b.operation_ref,
                    status="missing" if damage == "unmatched" else "matched",
                )
                for b in bindings
            ],
        ),
    )
    rows = [
        CapabilityObservation(
            feature="baseline-database",
            state="configured",
            reason_code="external_unverified",
            repair_key="check_network",
        )
    ]
    result = demonstrated(settings, tmp_path, rows, __import__("time").monotonic() + 2)
    assert (result[0].state == "supported") == (damage is None)


def test_readonly_evidence_store_preserves_permissions_and_cannot_write(tmp_path):
    """Inspection neither chmods existing state nor creates missing locks or artifacts."""
    from uuid import uuid4

    from agent.validation.store import PrivateStore, StoreError

    writer_store = PrivateStore(project=tmp_path)
    run = uuid4()
    with writer_store.create(run) as writer:
        writer.write_json("sample.json", {"synthetic": True})
    files = {str(p): (p.stat().st_mode, p.stat().st_mtime_ns) for p in writer_store.root.rglob("*")}
    readonly = PrivateStore(project=tmp_path, read_only=True)
    with readonly.open(run) as reader:
        assert reader.read_json("sample.json") == {"synthetic": True}
        with pytest.raises(StoreError):
            reader.write_json("sample.json", {}, replace=True)
    assert files == {
        str(p): (p.stat().st_mode, p.stat().st_mtime_ns) for p in writer_store.root.rglob("*")
    }
    writer_store.root.chmod(0o755)
    with pytest.raises(StoreError):
        PrivateStore(project=tmp_path, read_only=True)
    assert writer_store.root.stat().st_mode & 0o777 == 0o755
