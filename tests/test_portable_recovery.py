"""Restart, linked ownership and context adoption preserve independently uncertain effects."""

import pytest
from pydantic import SecretStr

from agent.recovery.lifecycle import CredentialLifecycle
from agent.recovery.store import RecoveryStore
from agent.security import SecurityError
from tests.portability_support import deployment


def test_restart_keeps_native_authority_and_blocks_replay(tmp_path):
    """Protected persistence restores the exact captured token, without acquiring new authority."""
    settings, store, _, factory, _ = deployment(tmp_path)
    with store.effect() as owner:
        owner.binding = factory().run_guard.ownership()
        token = CredentialLifecycle(store, owner, kind="native-user-token")
        token.start()
        token.acquired(SecretStr("synthetic-custody"), token_accessor="synthetic-accessor")
    restarted = RecoveryStore(settings, project=tmp_path)
    assert restarted.read().attempts[0].native_token.get_secret_value() == "synthetic-custody"
    with pytest.raises(SecurityError):
        with restarted.effect() as owner:
            owner.binding = factory().run_guard.ownership()
            restarted.begin_portable(owner, kind="native-user-token")


def test_two_children_share_owner_and_reject_third(tmp_path):
    """Only the owned acquired token admits its one database credential child."""
    _, store, _, factory, _ = deployment(tmp_path)
    with store.effect() as owner:
        owner.binding = factory().run_guard.ownership()
        token = CredentialLifecycle(store, owner, kind="native-user-token")
        token.start()
        token.acquired(SecretStr("synthetic-custody"))
        lease = CredentialLifecycle(
            store, owner, kind="database-lease", parent_id=token.item.incident_id
        )
        lease.start()
        assert len(owner.incident_ids) == 2
        with pytest.raises(SecurityError):
            store.begin_portable(owner, kind="database-lease", parent_id=token.item.incident_id)
    assert len(store.read().attempts) == 2


def test_unresolved_context_cannot_be_adopted(tmp_path):
    """Changing target cannot erase uncertain issuance or adopt new provider context."""
    settings, store, _, factory, _ = deployment(tmp_path)
    with store.effect() as owner:
        owner.binding = factory().run_guard.ownership()
        store.begin_portable(owner, kind="native-user-token")
    original = (store.root / "state.json").read_bytes()
    changed = RecoveryStore(
        settings.model_copy(update={"vault_read_path": "new/creds/reader"}), project=tmp_path
    )
    with pytest.raises(SecurityError):
        changed.migrate()
    assert (store.root / "state.json").read_bytes() == original


def test_v3_migration_is_idempotent(tmp_path):
    """Repeated offline migration keeps enrollment and history unchanged."""
    _, store, _, _, _ = deployment(tmp_path)
    original = store.read()
    assert store.migrate() is False
    assert store.read() == original


@pytest.mark.parametrize("denied", [False, True])
def test_native_proof_identifies_accessor_or_exact_nonissuance(tmp_path, denied):
    """Native login proof is kind-aware and does not create lease receipts."""
    from agent.recovery.proof import verify_sources
    from tests.test_recovery_proof import pair, source

    _, store, _, factory, _ = deployment(tmp_path)
    with store.effect() as owner:
        owner.binding = factory().run_guard.ownership()
        item = store.begin_portable(owner, kind="native-user-token")
    data = pair(store, item, denied=denied)
    for row in data["records"]:
        row["request"]["operation"] = "update"
    if not denied:
        data["records"][1]["response"] = {"auth": {"accessor": "synthetic-accessor"}}
    proof = verify_sources(store, item, [source(store, data)], "operator")
    assert proof.receipt.outcome == ("not_issued" if denied else "token_identified")
    assert proof.receipt.credential_kind == "native-user-token" and proof.lease_handle is None


async def test_known_token_recovery_uses_captured_authority(tmp_path):
    """Restart cleanup never performs another login or substitutes an operator credential."""
    import httpx

    from agent.recovery.commands import revoke_exact

    settings, store, state, factory, http = deployment(tmp_path)
    with store.effect() as owner:
        owner.binding = factory().run_guard.ownership()
        lifecycle = CredentialLifecycle(store, owner, kind="native-user-token")
        lifecycle.start()
        lifecycle.acquired(SecretStr("synthetic-custody"))
    seen = []

    def cleanup(request):
        seen.append(request)
        assert request.url.path == "/v1/auth/token/revoke-self"
        assert request.headers["x-vault-token"] == "synthetic-custody"
        return httpx.Response(204)

    await revoke_exact(
        RecoveryStore(settings, project=tmp_path),
        store.read().attempts[0],
        transport=httpx.MockTransport(cleanup),
    )
    assert len(seen) == 1 and store.read().attempts[0].state == "resolved"


def test_capacity_reserves_real_secret_bytes_before_new_issuance(tmp_path):
    """Masked debug serialization cannot underestimate protected token storage."""
    from agent.recovery.store import RECEIPT_RESERVE

    _, store, _, factory, _ = deployment(tmp_path)
    with store.effect() as owner:
        owner.binding = factory().run_guard.ownership()
        lifecycle = CredentialLifecycle(store, owner, kind="native-user-token")
        lifecycle.start()
        lifecycle.acquired(SecretStr("synthetic-" + "x" * 4000))
        lifecycle.pending()
        lifecycle.completed()
    path = store.root / "state.json"
    original = path.read_bytes()
    assert len(store._encode_snapshot(store.read())) > len(store.read().model_dump_json()) + 3000
    store.max_bytes = len(original) + RECEIPT_RESERVE + 200
    with store.effect() as owner:
        owner.binding = factory().run_guard.ownership()
        with pytest.raises(SecurityError, match="recovery_capacity"):
            store.begin_portable(owner, kind="native-user-token")
    assert path.read_bytes() == original
