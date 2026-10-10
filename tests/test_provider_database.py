"""Exact parameterized session selection rejects shared roles and PID reuse."""

from datetime import UTC, datetime
from uuid import uuid4

from provider_support import resource
from pydantic import SecretStr

from agent.response.providers.models import ProviderAction


class Connection:
    """Synthetic database connection recording SQL and controlled row changes."""

    def __init__(self, rows):
        """Retain fixed returned rows and an isolated call ledger."""
        self.rows, self.calls = rows, []

    async def execute(self, sql, params=None):
        """Return fixture rows while making parameterization inspectable."""
        self.calls.append((sql, params))
        return self

    async def fetchall(self):
        """Provide synthetic enrolled activity rows."""
        return self.rows

    async def fetchone(self):
        """Provide only a successful exact termination result."""
        return (True,)

    async def close(self):
        """Close without an external effect."""


async def test_fixed_sql_exact_role(workspace_settings):
    """Every role/database/PID/time enters as a bound parameter, never SQL syntax."""
    from agent.response.providers.database import DatabaseAdapter

    connection = Connection([(123, datetime(2026, 1, 1, tzinfo=UTC))])

    async def connect(dsn):
        """Inject an isolated DB without loading credentials or opening sockets."""
        return connection

    binding = resource(workspace_settings, "static_role", secret_alias="database-admin")
    action = ProviderAction(
        kind="terminate_static_sessions",
        binding=binding,
        enrollment_digest="1" * 64,
        incidents=(uuid4(),),
    )
    result = await DatabaseAdapter(
        {"database-admin": SecretStr("host=database.example dbname=fixture user=admin")},
        connect=connect,
    ).execute(action)
    assert result.state == "acknowledged" and result.proof == "not_run"
    statements = [sql for sql, _ in connection.calls]
    assert any("backend_start = %s" in sql and "pg_terminate_backend" in sql for sql in statements)
    assert all("isolated" not in sql for sql in statements)


async def test_overflow_does_not_terminate(workspace_settings):
    """More than 32 selected sessions produces an incomplete result before mutation."""
    from agent.response.providers.database import DatabaseAdapter

    connection = Connection([(i, datetime(2026, 1, 1, tzinfo=UTC)) for i in range(33)])

    async def connect(dsn):
        """Return a bounded fixture with too many sessions."""
        return connection

    binding = resource(workspace_settings, "static_role", secret_alias="database-admin")
    action = ProviderAction(
        kind="terminate_static_sessions",
        binding=binding,
        enrollment_digest="1" * 64,
        incidents=(uuid4(),),
    )
    result = await DatabaseAdapter(
        {"database-admin": SecretStr("host=database.example dbname=fixture user=admin")},
        connect=connect,
    ).execute(action)
    assert result.state == "failed"
    assert not any("pg_terminate_backend" in sql for sql, _ in connection.calls)


async def test_readiness_only_checks_metadata(workspace_settings):
    """Privilege diagnostics never enumerate passwords or terminate a backend."""
    from agent.response.providers.database import DatabaseAdapter

    class Metadata(Connection):
        """One exact safe role/authority fixture."""

        async def fetchone(self):
            """Return version, target flags, visibility, signal and execute authority."""
            return (160000, True, False, False, False, True, True, True)

    connection = Metadata([])

    async def connect(dsn):
        """Use a network-denied metadata connection."""
        return connection

    binding = resource(workspace_settings, "static_role", secret_alias="database-admin")
    result = await DatabaseAdapter(
        {"database-admin": SecretStr("host=database.example dbname=fixture user=admin")},
        connect=connect,
    ).readiness(binding)
    assert result.capability == "supported"
    assert all("pg_terminate_backend(pid" not in sql for sql, _ in connection.calls)
    assert any("has_function_privilege" in sql for sql, _ in connection.calls)


async def test_pid_reuse_leaves_unknown_outcome(workspace_settings):
    """A backend_start mismatch returns no exact termination row and cannot pass cleanup."""
    from agent.response.providers.database import DatabaseAdapter

    class Reused(Connection):
        """The selected PID now belongs to a different backend instance."""

        async def fetchone(self):
            """Fixed identity recheck yields no match."""
            return None

    connection = Reused([(123, datetime(2026, 1, 1, tzinfo=UTC))])

    async def connect(dsn):
        """Provide an isolated reused-PID fixture."""
        return connection

    action = ProviderAction(
        kind="terminate_static_sessions",
        binding=resource(workspace_settings, "static_role", secret_alias="database-admin"),
        enrollment_digest="1" * 64,
        incidents=(uuid4(),),
    )
    result = await DatabaseAdapter(
        {"database-admin": SecretStr("host=database.example dbname=fixture user=admin")},
        connect=connect,
    ).execute(action)
    assert result.state == "uncertain"


def test_pool_and_options_rejected(workspace_settings):
    """A proof DSN cannot select a pool or override compiled connection controls."""
    import pytest

    from agent.response.models import ResponseError
    from agent.response.providers.database import connection_parameters

    binding = resource(workspace_settings, "static_role")
    for suffix in ("port=6543", "options='-c search_path=evil'", "host=pooler.example"):
        with pytest.raises(ResponseError):
            connection_parameters(
                binding, "host=database.example dbname=fixture " + suffix, synthetic=True
            )
