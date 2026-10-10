"""Recovery v2 migration preserves all old fields without inferring ownership."""

import pytest

from agent.recovery.models import Journal
from agent.recovery.store import RecoveryStore
from agent.validation.models import canonical


def test_lossless_idempotent_migration(tmp_path, recovery_settings):
    store = RecoveryStore(recovery_settings, project=tmp_path)
    store.initialize()
    journal = store.read()
    legacy = Journal.model_validate(journal.model_dump() | {"schema_version": 1, "attempts": ()})
    with store._lock("journal.lock"), store._directory() as fd:
        store._write(fd, legacy)
    anchor = (store.root / "anchor.json").read_bytes()
    assert store.migrate() is True
    assert store.read().schema_version == 2
    assert store.migrate() is False
    assert (store.root / "anchor.json").read_bytes() == anchor
    assert canonical(store.read().attempts) == b"[]"


def test_populated_migration_preserves_native_fields_and_receipt(tmp_path, recovery_settings):
    """Migration labels unknown provenance instead of inventing root/user ownership."""
    from uuid import uuid4

    from agent.recovery.models import Attempt, Receipt

    store = RecoveryStore(recovery_settings, project=tmp_path)
    store.initialize()
    current = store.read()
    item = Attempt(
        incident_id=uuid4(),
        operation_id=uuid4(),
        credential_path=recovery_settings.vault_read_path,
        environment_digest=current.environment_digest,
        lease_handle="database/creds/read/native",
        native_request_id="native-request",
    )
    unresolved = item.model_copy(update={"state": "unresolved"})
    receipt = Receipt(
        outcome="revoked",
        incident_id=item.incident_id,
        incident_revision=item.revision,
        operation_id=item.operation_id,
        environment_digest=item.environment_digest,
    )
    resolved = item.model_copy(
        update={
            "incident_id": uuid4(),
            "operation_id": uuid4(),
            "state": "resolved",
            "resolution": "revoked",
        }
    )
    receipt = receipt.model_copy(
        update={"incident_id": resolved.incident_id, "operation_id": resolved.operation_id}
    )
    resolved = resolved.model_copy(update={"receipt": receipt})
    legacy = Journal.model_validate(
        current.model_dump() | {"schema_version": 1, "attempts": [unresolved, resolved]}
    )
    with store._lock("journal.lock"), store._directory() as fd:
        store._write(fd, legacy)
    store.migrate()
    migrated = store.read()
    for before, after in zip(legacy.attempts, migrated.attempts, strict=True):
        assert after.ownership.kind == "legacy_unattributed"
        assert before.model_dump(exclude={"schema_version"}) == after.model_dump(
            exclude={"schema_version", "ownership"}
        )
    assert migrated.attempts[1].receipt == receipt


def test_migration_requires_idle_effect_owner(tmp_path, recovery_settings):
    """Even idempotent migration cannot run while an effect descriptor is owned."""
    import pytest

    from agent.recovery.store import RecoveryError

    store = RecoveryStore(recovery_settings, project=tmp_path)
    store.initialize()
    before = (store.root / "state.json").read_bytes()
    with store.effect():
        with pytest.raises(RecoveryError, match="recovery_busy"):
            store.migrate()
    assert (store.root / "state.json").read_bytes() == before


@pytest.mark.parametrize("after_replace", [False, True])
def test_migration_atomic_replace_failure_is_lossless(
    tmp_path, recovery_settings, monkeypatch, after_replace
):
    """A restart sees either complete version, never partial or inferred attribution."""
    import os

    from agent.recovery.store import RecoveryError

    store = RecoveryStore(recovery_settings, project=tmp_path)
    store.initialize()
    legacy = Journal.model_validate(store.read().model_dump() | {"schema_version": 1})
    with store._lock("journal.lock"), store._directory() as fd:
        store._write(fd, legacy)
    original = os.replace

    def fail(*args, **kwargs):
        """Fail immediately before or after the real atomic rename."""
        if after_replace:
            original(*args, **kwargs)
        raise OSError("injected-rename-failure")

    with monkeypatch.context() as patched:
        patched.setattr(os, "replace", fail)
        with pytest.raises(RecoveryError):
            store.migrate()
    restarted = RecoveryStore(recovery_settings, project=tmp_path)
    assert restarted.read().schema_version == (2 if after_replace else 1)
    restarted.migrate()
    assert restarted.read().schema_version == 2


@pytest.mark.parametrize(
    "state", ["intent", "acquired", "cleanup_pending", "unresolved", "resolved"]
)
def test_all_legacy_states_migrate_without_inference(tmp_path, recovery_settings, state):
    """Each historical acquisition state retains its exact data and no guessed identity."""
    from uuid import uuid4

    from agent.recovery.models import Attempt, Receipt

    store = RecoveryStore(recovery_settings, project=tmp_path)
    store.initialize()
    journal = store.read()
    incident_id, operation_id = uuid4(), uuid4()
    receipt = Receipt(
        outcome="not_issued",
        incident_id=incident_id,
        operation_id=operation_id,
        incident_revision=1,
        environment_digest=journal.environment_digest,
    )
    attempt = Attempt(
        incident_id=incident_id,
        operation_id=operation_id,
        credential_path=recovery_settings.vault_read_path,
        environment_digest=journal.environment_digest,
        state=state,
        lease_handle="database/creds/read/fixture"
        if state in {"acquired", "cleanup_pending"}
        else None,
        **({"resolution": "not_issued", "receipt": receipt} if state == "resolved" else {}),
    )
    legacy = Journal.model_validate(
        journal.model_dump() | {"schema_version": 1, "attempts": [attempt]}
    )
    with store._lock("journal.lock"), store._directory() as directory:
        store._write(directory, legacy)
    store.migrate()
    migrated = store.read().attempts[0]
    assert migrated.state == state and migrated.ownership.kind == "legacy_unattributed"
    assert attempt.model_dump(exclude={"schema_version"}) == migrated.model_dump(
        exclude={"schema_version", "ownership"}
    )


def test_migration_growth_exceeds_capacity_without_replacement(tmp_path, recovery_settings):
    """V2 attribution overhead is checked before replacing a valid legacy snapshot."""
    from uuid import uuid4

    from agent.recovery.models import Attempt
    from agent.recovery.store import RecoveryError

    store = RecoveryStore(recovery_settings, project=tmp_path)
    store.initialize()
    journal = store.read()
    item = Attempt(
        incident_id=uuid4(),
        operation_id=uuid4(),
        credential_path=recovery_settings.vault_read_path,
        environment_digest=journal.environment_digest,
    )
    legacy = Journal.model_validate(
        journal.model_dump() | {"schema_version": 1, "attempts": [item]}
    )
    with store._lock("journal.lock"), store._directory() as fd:
        store._write(fd, legacy)
    before = (store.root / "state.json").read_bytes()
    store.max_bytes = len(before) + 1
    with pytest.raises(RecoveryError, match="recovery_capacity"):
        store.migrate()
    assert (store.root / "state.json").read_bytes() == before
