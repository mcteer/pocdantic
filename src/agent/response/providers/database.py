"""Bounded exact isolated-static-role PostgreSQL session controls.

Dynamic leases remain owned by Vault revocation SQL. This adapter never infers legacy
usernames. PID/backend_start recheck reduces reuse risk but cannot strengthen the
server's PID-only termination primitive into an atomic native identity guarantee.
"""

import asyncio
import hashlib

from agent.response.models import ResponseError

from .common import Result
from .models import require

SELECT = """SELECT pid, backend_start FROM pg_stat_activity
WHERE datname = %s AND usename = %s AND pid <> pg_backend_pid()
ORDER BY pid LIMIT 33"""
TERMINATE = """SELECT pg_terminate_backend(pid, %s) FROM pg_stat_activity
WHERE datname = %s AND usename = %s AND pid = %s AND backend_start = %s
AND pid <> pg_backend_pid()"""


# Metadata only: do not invoke the signaling function to discover permissions.
READINESS = """SELECT current_setting('server_version_num')::int,
r.rolcanlogin, r.rolsuper, r.rolreplication, r.rolbypassrls,
(a.rolsuper OR pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER')),
(a.rolsuper OR pg_has_role(current_user, r.oid, 'MEMBER')
 OR pg_has_role(current_user, 'pg_signal_backend', 'MEMBER')),
has_function_privilege(current_user, 'pg_terminate_backend(integer,bigint)', 'EXECUTE')
FROM pg_roles r JOIN pg_roles a ON a.rolname = current_user WHERE r.rolname = %s"""


def connection_parameters(binding, dsn, *, synthetic=False):
    """Reject a shared/pool destination or options that could bypass compiled controls.

    The private reviewed DSN supplies one direct TLS destination. Explicit transaction
    pool ports and known pool endpoints are unsupported for held-session evidence.
    """
    from psycopg.conninfo import conninfo_to_dict

    parts = conninfo_to_dict(dsn)
    require(
        parts.get("dbname") == binding.database
        and parts.get("host")
        and not parts.get("options")
        and "," not in parts["host"]
        and not parts["host"].startswith("/")
        and "pooler" not in parts["host"].lower()
        and parts.get("port", "5432") != "6543",
        "unsupported",
    )
    if not synthetic:
        require(parts.get("sslmode") == "verify-full", "missing_authority")
    return parts


class DatabaseAdapter:
    """Terminate only a reviewed isolated role through fixed parameterized SQL."""

    def __init__(self, secrets, *, connect=None, termination_timeout_ms=5000):
        """Keep credentials private; test connections never load local provider settings."""
        require(
            type(termination_timeout_ms) is int and 0 < termination_timeout_ms <= 5000,
            "mapping_missing",
        )
        self.secrets, self.connect, self.timeout = secrets, connect, termination_timeout_ms

    async def execute(self, action, *, read_only=False):
        """Enumerate at most 32 exact identities and recheck each before terminating."""
        binding = action.binding
        require(
            action.kind == "terminate_static_sessions"
            and binding.kind == "static_role"
            and binding.isolated
            and binding.database
            and binding.username,
            "unsupported",
        )
        secret = self.secrets.get(binding.secret_alias)
        require(secret is not None, "missing_authority")
        try:
            import psycopg

            dsn = secret.get_secret_value()
            connection_parameters(binding, dsn, synthetic=self.connect is not None)
            async with asyncio.timeout(10):
                connection = await (
                    self.connect(dsn)
                    if self.connect
                    else psycopg.AsyncConnection.connect(dsn, connect_timeout=5, autocommit=True)
                )
                try:
                    await connection.execute("SET statement_timeout = '5000ms'")
                    cursor = await connection.execute(SELECT, (binding.database, binding.username))
                    rows = await cursor.fetchall()
                    if len(rows) > 32:
                        return Result(state="failed", reason="provider_capacity")
                    if read_only:
                        return Result(
                            state="reconciled" if not rows else "acknowledged",
                            reason="provider_reconciled" if not rows else "proof_required",
                            path="static_session_readback",
                            proof="proven" if not rows else "inconclusive",
                            source_digest=hashlib.sha256(str(len(rows)).encode()).hexdigest(),
                        )
                    complete = True
                    for pid, started in rows:
                        require(
                            type(pid) is int and pid > 0 and started.tzinfo is not None,
                            "mapping_missing",
                        )
                        cursor = await connection.execute(
                            TERMINATE,
                            (self.timeout, binding.database, binding.username, pid, started),
                        )
                        result = await cursor.fetchone()
                        complete = complete and result is not None and result[0] is True
                    return Result(
                        state="acknowledged" if complete else "uncertain",
                        reason="provider_acknowledged" if complete else "provider_uncertain",
                    )
                finally:
                    await connection.close()
        except ResponseError:
            raise
        except Exception:
            raise ResponseError("provider_uncertain") from None

    async def readiness(self, binding):
        """Read exact role flags and authority only; never signal, rotate or read credentials.

        Metadata permission is a prerequisite, not a guarantee that every future backend
        can be terminated. Target isolation remains an explicit operator assertion.
        """
        from agent.recovery.models import now
        from agent.validation.models import canonical

        capability = "missing_authority"
        fingerprint = None
        try:
            import psycopg

            require(binding.kind == "static_role" and binding.isolated, "unsupported")
            secret = self.secrets.get(binding.secret_alias)
            require(secret is not None, "missing_authority")
            dsn = secret.get_secret_value()
            connection_parameters(binding, dsn, synthetic=self.connect is not None)
            async with asyncio.timeout(10):
                connection = await (
                    self.connect(dsn)
                    if self.connect
                    else psycopg.AsyncConnection.connect(dsn, connect_timeout=5, autocommit=True)
                )
                try:
                    await connection.execute("SET statement_timeout = '5000ms'")
                    cursor = await connection.execute(READINESS, (binding.username,))
                    row = await cursor.fetchone()
                    fingerprint = hashlib.sha256(canonical(row)).hexdigest()
                    supported = (
                        row is not None
                        and type(row[0]) is int
                        and row[0] >= 140000
                        and row[1] is True
                        and all(v is False for v in row[2:5])
                        and all(v is True for v in row[5:8])
                    )
                    capability = "supported" if supported else "missing_authority"
                finally:
                    await connection.close()
        except ResponseError as error:
            capability = "unsupported" if str(error) == "unsupported" else "missing_authority"
        except Exception:
            capability = "missing_authority"
        return type(binding).model_validate(
            binding.model_dump()
            | {"capability": capability, "capability_digest": fingerprint, "checked_at": now()}
        )
