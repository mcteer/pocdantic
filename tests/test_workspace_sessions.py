import pytest
from pydantic import SecretStr

from agent.schemas import Principal
from agent.security import SecurityError
from agent.workspace.auth import Credentials
from agent.workspace.sessions import SessionStore


def credentials():
    return Credentials(
        SecretStr("access"),
        SecretStr("refresh"),
        Principal(issuer="https://id.example", subject="user", expires_at=9999999999),
        "nonce",
        9999999999,
    )


def test_capacity_rotation_and_idle_expiry():
    clock = [0.0]
    store = SessionStore(clock=lambda: clock[0])
    first = store.bootstrap(None)
    old = first.cookie
    s = store.authenticate(first, credentials())
    assert s.cookie != old and store.session(old) is None
    for _ in range(3):
        store.authenticate(store.bootstrap(None), credentials())
    with pytest.raises(SecurityError, match="capacity_exceeded"):
        store.authenticate(store.bootstrap(None), credentials())
    clock[0] = 1799
    assert store.session(s.cookie) is s
    clock[0] = 1801
    assert store.session(s.cookie) is None


def test_bootstrap_limit_and_lifetime():
    clock = [0.0]
    store = SessionStore(clock=lambda: clock[0])
    for _ in range(16):
        store.bootstrap(None)
    with pytest.raises(SecurityError):
        store.bootstrap(None)
    clock[0] = 301
    assert store.bootstrap(None)


def test_absolute_expiry_even_with_user_mutations_and_restart():
    clock = [0.0]
    store = SessionStore(clock=lambda: clock[0])
    session = store.authenticate(store.bootstrap(None), credentials())
    for step in range(1, 29):
        clock[0] = step * 1000
        store.touch(session)
    clock[0] = 28801
    assert store.session(session.cookie) is None
    assert SessionStore().session(session.cookie) is None
