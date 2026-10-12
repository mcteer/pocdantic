"""Actual PostgreSQL/compiler semantics in an explicitly selected isolated test service.

SANDBOX_POSTGRES_PORT and SANDBOX_POSTGRES_CA select a disposable TLS fixture.
This test never discovers or uses an application's configured database.
"""

import os
import secrets
import time
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import SecretStr

from agent.sandbox.models import QueryRequest
from agent.sandbox.sql import admit
from agent.security import SecurityError
from agent.vault import Lease, read_admitted_postgres


@pytest.mark.asyncio
async def test_actual_read_only_compiler():
    if not os.environ.get("SANDBOX_POSTGRES_PORT"):
        pytest.skip("explicit isolated PostgreSQL service not supplied")
    import psycopg

    port = int(os.environ["SANDBOX_POSTGRES_PORT"])
    ca = os.environ["SANDBOX_POSTGRES_CA"]
    assert Path(ca).is_file()
    database = "sandbox_" + uuid4().hex
    role = "reader_" + uuid4().hex
    password = secrets.token_urlsafe(24)
    async with await psycopg.AsyncConnection.connect(
        host="localhost",
        port=port,
        user="postgres",
        dbname="postgres",
        autocommit=True,
        sslmode="verify-full",
        sslrootcert=ca,
    ) as admin:
        await admin.execute(
            psycopg.sql.SQL("CREATE DATABASE {}").format(psycopg.sql.Identifier(database))
        )
        await admin.execute(
            psycopg.sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                psycopg.sql.Identifier(role), psycopg.sql.Literal(password)
            )
        )
    try:
        async with await psycopg.AsyncConnection.connect(
            host="localhost",
            port=port,
            user="postgres",
            dbname=database,
            autocommit=True,
            sslmode="verify-full",
            sslrootcert=ca,
        ) as admin:
            await admin.execute(Path("config/sandbox-demo.sql").read_text())
            await admin.execute(
                psycopg.sql.SQL("GRANT SELECT ON public.poc_records TO {}").format(
                    psycopg.sql.Identifier(role)
                )
            )
        lease = Lease(
            lease_id="database/creds/fixture/test",
            lease_duration=120,
            renewable=False,
            username=SecretStr(role),
            password=SecretStr(password),
        )
        plan = await admit(
            QueryRequest(sql="SELECT status, COUNT(*) FROM poc_records GROUP BY status")
        )
        value = await read_admitted_postgres(
            lease, plan=plan, host="localhost", port=port, database=database, sslrootcert=ca
        )
        assert {r["status"]: r["count"] for r in value["rows"]} == {
            "open": 2,
            "closed": 1,
            "pending": 1,
        }
        plan = await admit(
            QueryRequest(sql="SELECT id FROM poc_records WHERE id > $1 ORDER BY id", parameters=[2])
        )
        assert (
            await read_admitted_postgres(
                lease, plan=plan, host="localhost", port=port, database=database, sslrootcert=ca
            )
        )["rows"] == [{"id": 3}, {"id": 4}]
        limited = await admit(QueryRequest(sql="SELECT id FROM poc_records ORDER BY id LIMIT 1"))
        assert await read_admitted_postgres(
            lease, plan=limited, host="localhost", port=port, database=database, sslrootcert=ca
        ) == {"rows": [{"id": 1}], "row_count": 1, "truncated": True}
        # An administrator-held table lock must fail within the adapter's lock bound,
        # without extending generated SQL authority to sleeps or session settings.
        async with await psycopg.AsyncConnection.connect(
            host="localhost",
            port=port,
            user="postgres",
            dbname=database,
            sslmode="verify-full",
            sslrootcert=ca,
        ) as admin:
            await admin.execute("LOCK public.poc_records IN ACCESS EXCLUSIVE MODE")
            started = time.monotonic()
            with pytest.raises(SecurityError, match="database_request_failed"):
                await read_admitted_postgres(
                    lease,
                    plan=limited,
                    host="localhost",
                    port=port,
                    database=database,
                    sslrootcert=ca,
                )
            assert time.monotonic() - started < 4
            await admin.rollback()
        async with await psycopg.AsyncConnection.connect(
            host="localhost",
            port=port,
            user=role,
            password=password,
            dbname=database,
            sslmode="verify-full",
            sslrootcert=ca,
        ) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                await conn.execute("DELETE FROM public.poc_records")
    finally:
        async with await psycopg.AsyncConnection.connect(
            host="localhost",
            port=port,
            user="postgres",
            dbname="postgres",
            autocommit=True,
            sslmode="verify-full",
            sslrootcert=ca,
        ) as admin:
            await admin.execute(
                psycopg.sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                    psycopg.sql.Identifier(database)
                )
            )
            await admin.execute(
                psycopg.sql.SQL("DROP ROLE {}").format(psycopg.sql.Identifier(role))
            )
