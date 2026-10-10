"""Private journal durability, revision races, unsafe storage, and exclusive ownership."""

import os

import pytest

from agent.recovery.store import RecoveryError, RecoveryStore


def test_explicit_initialization_is_repeat_safe(tmp_path, recovery_settings):
    store = RecoveryStore(recovery_settings, project=tmp_path)
    with pytest.raises(RecoveryError, match="recovery_uninitialized"):
        store.read()
    assert not store.root.exists()
    assert store.initialize() is True
    before = (store.root / "state.json").read_bytes()
    assert store.initialize() is False
    assert (store.root / "state.json").read_bytes() == before
    assert (store.root / "state.json").stat().st_mode & 0o777 == 0o600


def test_revision_and_bound_effect_admission(recovery_store):
    with recovery_store.effect() as owner:
        first = recovery_store.begin(owner)
        assert recovery_store.read().attempts[0].state == "intent"
        with pytest.raises(RecoveryError, match="recovery_busy"):
            with recovery_store.effect():
                pass
        with pytest.raises(RecoveryError):
            recovery_store.begin(owner)
        updated = recovery_store.update(first.incident_id, first.revision, state="unresolved")
        with pytest.raises(RecoveryError, match="recovery_evidence_invalid"):
            recovery_store.update(first.incident_id, first.revision, state="unresolved")
        assert updated.revision == 2
    with pytest.raises(RecoveryError, match="acquisition_uncertain"):
        with recovery_store.effect() as owner:
            recovery_store.begin(owner)


@pytest.mark.parametrize(
    "damage", ["anchor", "state", "root", "mode", "symlink", "hardlink", "schema", "duplicate"]
)
def test_damaged_storage_never_reinitializes(recovery_store, damage):
    root = recovery_store.root
    if damage in {"anchor", "state"}:
        (root / (damage + ".json")).unlink()
    elif damage == "root":
        import shutil

        shutil.rmtree(root)
    elif damage == "mode":
        (root / "state.json").chmod(0o644)
    elif damage == "symlink":
        (root / "state.json").rename(root / "original")
        (root / "state.json").symlink_to(root / "original")
    elif damage == "hardlink":
        os.link(root / "state.json", root / "copy")
    else:
        (root / "state.json").write_text(
            '{"schema_version":2}'
            if damage == "schema"
            else '{"schema_version":1,"schema_version":1}'
        )
    with pytest.raises(RecoveryError):
        recovery_store.read()
    with pytest.raises(RecoveryError):
        recovery_store.initialize()


def test_environment_change_is_not_clean_state(recovery_store, recovery_settings, tmp_path):
    changed = recovery_settings.model_copy(update={"database_host": "other.example"})
    with pytest.raises(RecoveryError, match="recovery_environment_mismatch"):
        RecoveryStore(changed, project=tmp_path).read()


def test_fsync_failure_keeps_local_block_and_durable_intent(recovery_store, monkeypatch):
    with recovery_store.effect() as owner:
        item = recovery_store.begin(owner)

        def fail(fd):
            raise OSError("PRIVATE disk failure")

        monkeypatch.setattr(os, "fsync", fail)
        with pytest.raises(RecoveryError, match="recovery_storage_error"):
            recovery_store.update(item.incident_id, item.revision, state="unresolved")
        assert recovery_store.failed
    with pytest.raises(RecoveryError):
        recovery_store.read()


def test_retention_never_prunes_unresolved(recovery_store):
    with recovery_store.effect() as owner:
        item = recovery_store.begin(owner)
        item = recovery_store.update(item.incident_id, 1, state="unresolved")
    assert recovery_store.normalize().attempts[0].incident_id == item.incident_id


def test_workspace_lock_independent_of_idle_operator(recovery_store):
    with recovery_store.workspace():
        with pytest.raises(RecoveryError, match="recovery_busy"):
            with recovery_store.workspace():
                pass
        with recovery_store.effect():
            assert recovery_store.read().attempts == ()


@pytest.mark.parametrize(
    "field", ["database_host", "database_name", "vault_addr", "oauth_client_id"]
)
def test_configuration_removal_cannot_bypass_existing_journal(recovery_store, field):
    changed = recovery_store.settings.model_copy(update={field: None})
    view = RecoveryStore(changed, project=recovery_store.project).status()
    assert view.recovery == "storage_error" and view.reason_code in {
        "recovery_environment_mismatch",
        "recovery_storage_error",
    }


def test_pruning_resolved_only_and_receipt_reservation(recovery_store):
    from datetime import timedelta
    from uuid import uuid4

    from agent.recovery.models import Attempt, Journal, Receipt, now
    from agent.validation.models import canonical

    journal = recovery_store.read()
    attempts = []
    for index in range(1000):
        incident, operation = uuid4(), uuid4()
        receipt = Receipt(
            outcome="not_issued",
            incident_id=incident,
            incident_revision=1,
            operation_id=operation,
            environment_digest=journal.environment_digest,
        )
        attempts.append(
            Attempt(
                incident_id=incident,
                operation_id=operation,
                environment_digest=journal.environment_digest,
                credential_path="database/creds/read",
                state="resolved",
                resolution="not_issued",
                receipt=receipt,
                updated_at=now() - timedelta(days=8) if index == 0 else now(),
            )
        )
    full = Journal.model_validate(journal.model_dump() | {"attempts": tuple(attempts)})
    pruned = recovery_store._prune(full, reserve=True)
    assert len(pruned) == 999 and attempts[0] not in pruned
    assert len(canonical(full.model_copy(update={"attempts": pruned}))) < 2 * 1024 * 1024 - 16384
    unresolved = attempts[0].model_copy(
        update={"state": "unresolved", "resolution": None, "receipt": None}
    )
    assert unresolved in recovery_store._prune(full.model_copy(update={"attempts": (unresolved,)}))


def test_oversized_snapshot_and_unsafe_lock_rejected(recovery_store):
    (recovery_store.root / "state.json").write_bytes(b" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(RecoveryError):
        recovery_store.read()
    (recovery_store.root / "effect.lock").chmod(0o644)
    with pytest.raises(RecoveryError):
        with recovery_store.effect():
            pytest.fail("unsafe lock admitted")


def test_workspace_lifetime_contention_and_effect_independence(recovery_store):
    other = RecoveryStore(recovery_store.settings, project=recovery_store.project)
    recovery_store.claim_workspace()
    try:
        with pytest.raises(RecoveryError, match="recovery_busy"):
            other.claim_workspace()
        with other.effect():
            assert other.read().attempts == ()
    finally:
        recovery_store.release_workspace()
    other.claim_workspace()
    other.release_workspace()


def test_explicit_check_prunes_expired_terminal_receipts_only(recovery_store):
    from datetime import timedelta

    from agent.recovery.models import Journal, Receipt, now

    with recovery_store.effect() as owner:
        item = recovery_store.begin(owner)
        item = recovery_store.update(item.incident_id, item.revision, state="unresolved")
        receipt = Receipt(
            outcome="not_issued",
            incident_id=item.incident_id,
            incident_revision=item.revision,
            operation_id=item.operation_id,
            environment_digest=item.environment_digest,
        )
        resolved = recovery_store.update(
            item.incident_id,
            item.revision,
            state="resolved",
            resolution="not_issued",
            receipt=receipt,
        )
    journal = recovery_store.read()
    old = resolved.model_copy(update={"updated_at": now() - timedelta(days=8)})
    with recovery_store._lock("journal.lock"), recovery_store._directory() as directory:
        recovery_store._write(
            directory, Journal.model_validate(journal.model_dump() | {"attempts": (old,)})
        )
    recovery_store.prune()
    assert recovery_store.read().attempts == ()
