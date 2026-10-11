"""Standard Vault custody verifies independent token/lease cleanup and rejects weaker routes."""

import asyncio

import pytest
from portability_support import deployment

from agent.security import SecurityError


@pytest.fixture
def portable(tmp_path, monkeypatch):
    """Prevent database networking while exercising identity, Vault and durable custody."""

    async def read(lease, **kwargs):
        assert lease.username.get_secret_value() == "synthetic-user"
        return [{"id": kwargs["record_id"]}]

    monkeypatch.setattr("agent.broker.read_postgres", read)
    return deployment(tmp_path)


async def test_standard_login_uses_no_exchange_and_closes_both_credentials(portable):
    """A renewable flag is compatible; no renewal or agent-client request occurs."""
    _, store, state, broker, http = portable
    async with http:
        assert await broker()(1) == [{"id": 1}]
    assert all(a.state == "resolved" for a in store.read().attempts)
    assert len(store.read().attempts) == 2
    assert state["calls"][-2:] == [
        ("PUT", "/v1/sys/leases/revoke"),
        ("POST", "/v1/auth/token/revoke-self"),
    ]
    assert not any(path == "/token" for _, path in state["calls"])
    assert store.read().schema_version == 3
    raw = (store.root / "state.json").read_text()
    assert "synthetic-native-token" in raw
    assert "synthetic-native-token" not in store.read().model_dump_json()


@pytest.mark.parametrize(
    "change",
    [
        {"type": "batch"},
        {"explicit_max_ttl": 0},
        {"explicit_max_ttl": 301},
        {"ttl": 20},
        {"policies": ["root"]},
    ],
)
async def test_invalid_native_authority_is_cleaned_before_database_issuance(portable, change):
    """Rejected login credentials still get cleanup; no database lease is issued."""
    _, store, state, broker, http = portable
    state["lookup"].update(change)
    async with http:
        with pytest.raises(SecurityError, match="vault_token_invalid"):
            await broker()(1)
    assert state["calls"][-1][1] == "/v1/auth/token/revoke-self"
    assert not any("/creds/" in path for _, path in state["calls"])
    assert all(a.state == "resolved" for a in store.read().attempts)


async def test_denied_user_never_logs_into_vault(portable):
    """Scope denial occurs before either credential intent or provider issuance."""
    _, store, state, broker, http = portable
    async with http:
        with pytest.raises(SecurityError, match="database_subject_invalid"):
            await broker({"scope": "tickets:read"})(1)
    assert not store.read().attempts
    assert not any(path.startswith("/v1/") for _, path in state["calls"])


async def test_failed_lease_cleanup_still_revokes_token_and_remains_blocked(portable):
    """Cascade acknowledgement cannot invent the missing exact-lease receipt."""
    _, store, state, broker, http = portable
    state["revoke_status"] = 403
    async with http:
        with pytest.raises(SecurityError, match="cleanup_failed"):
            await broker()(1)
    assert state["calls"][-1][1] == "/v1/auth/token/revoke-self"
    attempts = store.read().attempts
    assert attempts[0].state == "resolved" and attempts[1].state == "unresolved"
    assert store.status().recovery == "blocked"


async def test_token_cleanup_failure_blocks_replay(portable):
    """Successful SQL and lease cleanup cannot reopen issuance after token uncertainty."""
    _, store, state, broker, http = portable
    state["token_status"] = 403
    async with http:
        with pytest.raises(SecurityError, match="cleanup_failed"):
            await broker()(1)
        count = len(state["calls"])
        with pytest.raises(SecurityError):
            await broker()(1)
        assert len(state["calls"]) == count
    assert store.status().recovery == "blocked"


async def test_cancellation_cleans_both_credentials(portable, monkeypatch):
    """User cancellation drains both custody lifecycles before releasing admission."""

    async def cancel(*args, **kwargs):
        raise asyncio.CancelledError

    monkeypatch.setattr("agent.broker.read_postgres", cancel)
    _, store, _, broker, http = portable
    async with http:
        with pytest.raises(asyncio.CancelledError):
            await broker()(1)
    assert all(a.state == "resolved" for a in store.read().attempts)


async def test_cleanup_budget_is_shared_and_ordered(portable, monkeypatch):
    """The database lease receives twenty seconds; the outer native cleanup follows it."""
    from contextlib import asynccontextmanager

    from agent.vault import VaultClient

    original = VaultClient.credentials
    budgets = []

    @asynccontextmanager
    async def credentials(self, *args, **kwargs):
        budgets.append((kwargs["cleanup_timeout"], kwargs["cleanup_drain_timeout"]))
        async with original(self, *args, **kwargs) as lease:
            yield lease

    monkeypatch.setattr(VaultClient, "credentials", credentials)
    _, _, state, factory, http = portable
    async with http:
        await factory()(1)
    assert budgets == [(20, 0)]
    assert state["calls"][-1][1] == "/v1/auth/token/revoke-self"


async def test_lost_login_response_blocks_without_rediscovery(portable, monkeypatch):
    """A lost native response cannot be repaired by issuing another token."""
    from agent.vault import VaultClient

    original = VaultClient.request

    async def lost(self, method, path, *args, **kwargs):
        if path.endswith("/login"):
            raise SecurityError("vault_unreachable")
        return await original(self, method, path, *args, **kwargs)

    monkeypatch.setattr(VaultClient, "request", lost)
    _, store, state, factory, http = portable
    async with http:
        with pytest.raises(SecurityError):
            await factory()(1)
        count = len(state["calls"])
        with pytest.raises(SecurityError):
            await factory()(1)
        assert count == len(state["calls"])
    assert store.status().recovery == "blocked"


async def test_lost_lease_response_still_attempts_token_cleanup(portable, monkeypatch):
    """Unknown dynamic credentials remain blocked despite confirmed token revocation."""
    from agent.vault import VaultClient

    original = VaultClient.request

    async def lost(self, method, path, *args, **kwargs):
        if "/creds/" in path:
            raise SecurityError("vault_unreachable")
        return await original(self, method, path, *args, **kwargs)

    monkeypatch.setattr(VaultClient, "request", lost)
    _, store, state, factory, http = portable
    async with http:
        with pytest.raises(SecurityError):
            await factory()(1)
    assert state["calls"][-1][1] == "/v1/auth/token/revoke-self"
    assert store.read().attempts[0].state == "resolved"
    assert store.read().attempts[1].state == "unresolved"


async def test_malformed_accessor_cannot_abandon_known_token(portable):
    """Even a custody validation fault still attempts captured-token cleanup."""
    _, store, state, factory, http = portable
    state["login"]["accessor"] = []
    async with http:
        with pytest.raises(SecurityError):
            await factory()(1)
    assert state["calls"][-1][1] == "/v1/auth/token/revoke-self"
    item = store.read().attempts[0]
    assert item.native_token.get_secret_value() == "synthetic-native-token"
    assert item.state == "resolved" and item.receipt.outcome == "revoked"


async def test_malformed_native_metadata_keeps_public_cleanup_counts(portable):
    """An issued but rejected token still counts as acquired before its confirmed cleanup."""
    from dataclasses import replace
    from types import SimpleNamespace

    events = []
    observer = SimpleNamespace(
        validation_id=None,
        observation_id=None,
        failed=False,
        record=lambda phase, detail, **kw: events.append((phase, detail)),
        fact=lambda *a, **kw: None,
    )
    _, _, state, factory, http = portable
    state["login"]["accessor"] = []
    async with http:
        with pytest.raises(SecurityError, match="vault_token_invalid"):
            await replace(factory(), operation_observer=observer)(1)
    assert events.count(("credential", "acquired")) == events.count(("cleanup", "revoked")) == 1
