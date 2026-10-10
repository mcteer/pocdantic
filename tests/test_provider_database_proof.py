"""Independent database proofs distinguish native loss from cancellation and outages."""

import pytest


class Failure(Exception):
    """Synthetic PostgreSQL server rejection with an inspectable SQLSTATE."""

    def __init__(self, state):
        """Retain only a server-state code, without a connection or provider message."""
        self.sqlstate = state


@pytest.mark.parametrize(
    "state,healthy,expected",
    [
        ("28P01", True, "proven"),
        ("28P01", False, "inconclusive"),
        (None, True, "inconclusive"),
        ("57P01", True, "inconclusive"),
    ],
)
def test_fresh_login_denial_needs_native_authentication_and_health(state, healthy, expected):
    """A network ban or provider outage must not pass password invalidation."""
    from agent.response.providers.proof import database_failure

    assert database_failure(Failure(state), path="fresh", before=True, healthy=healthy) == expected


@pytest.mark.parametrize(
    "state,healthy,expected",
    [
        ("57P01", True, "proven"),
        ("57P01", False, "inconclusive"),
        (None, True, "inconclusive"),
        ("28P01", True, "inconclusive"),
    ],
)
def test_open_session_loss_needs_independent_server_signal(state, healthy, expected):
    """Local process death and transport loss cannot stand in for native termination."""
    from agent.response.providers.proof import database_failure

    assert (
        database_failure(Failure(state), path="session", before=True, healthy=healthy) == expected
    )


class Session:
    """Independent synthetic connection with native authentication/termination failures."""

    def __init__(self, role, database="fixture"):
        """Start healthy and retain exact server identity."""
        self.role, self.database, self.closed, self.terminated = role, database, False, False
        self.sql = None

    async def execute(self, sql):
        """The server terminates its held session independently of application cancellation."""
        if self.terminated:
            raise Failure("57P01")
        self.sql = sql
        return self

    async def fetchone(self):
        """Return native identity or the fixed liveness result."""
        return (self.role, self.database) if "current_user" in self.sql else (1,)

    async def close(self):
        """Record disposal without erasing native termination evidence."""
        self.closed = True


async def test_independent_old_new_and_held_session_outcomes():
    """Old password denial, new password success and held-session loss are distinct."""
    from agent.response.providers.proof import DatabaseProbe

    denied = False
    connections = []

    async def connect(parameters):
        """Reject only the old credential while preserving the healthy role."""
        if denied and parameters.get("password") == "old":
            raise Failure("28P01")
        connection = Session(parameters["user"])
        connections.append(connection)
        return connection

    parameters = {
        "host": "db.example",
        "port": "5432",
        "dbname": "fixture",
        "user": "isolated",
        "password": "old",
    }
    probe = DatabaseProbe(
        parameters, parameters | {"user": "healthy", "password": "peer"}, connect=connect
    )
    assert await probe.prepare()
    denied = True
    probe.old.terminated = True
    outcomes, healthy = await probe.observe(replacement=parameters | {"password": "new"})
    assert healthy and outcomes == {"fresh": "proven", "session": "proven", "new": "proven"}
    await probe.close()
    assert all(c.closed for c in connections)


async def test_different_dsn_spellings_cannot_fake_healthy_peer():
    """Two logins resolving to the same actual server role cannot establish control health."""
    from agent.response.models import ResponseError
    from agent.response.providers.proof import DatabaseProbe

    async def connect(parameters):
        """Simulate authentication aliases mapped to one native identity."""
        return Session("same-role")

    parameters = {"host": "db.example", "port": "5432", "dbname": "fixture", "user": "alias-a"}
    probe = DatabaseProbe(parameters, parameters | {"user": "alias-b"}, connect=connect)
    try:
        with pytest.raises(ResponseError, match="mapping_missing"):
            await probe.prepare()
    finally:
        await probe.close()
