#!/usr/bin/env python3
"""Provision and verify the PoC database through the existing Vault instance."""

import asyncio
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import httpx
import psycopg
from dotenv import dotenv_values
from pydantic import SecretStr

from agent.security import SecurityError
from agent.settings import Settings
from agent.vault import VaultClient, read_postgres

CONNECTION = "pocdantic-postgres"
ROLE = "poc-readonly"
POLICY = "pocdantic-database-readonly"
MARKER = "pocdantic synthetic credential-flow fixture"
CREATION = (
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' "
    "VALID UNTIL '{{expiration}}'; "
    'GRANT USAGE ON SCHEMA public TO "{{name}}"; '
    'GRANT SELECT ON public.poc_records TO "{{name}}";'
)
REVOCATION = (
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; "
    'REVOKE SELECT ON public.poc_records FROM "{{name}}"; '
    'REVOKE USAGE ON SCHEMA public FROM "{{name}}"; DROP ROLE IF EXISTS "{{name}}";'
)
ACL = (
    'path "auth/token/revoke-self" { capabilities = ["update"] }\n'
    'path "database/creds/poc-readonly" { capabilities = ["read"] }\n'
    'path "sys/leases/revoke" { capabilities = ["update"] '
    'required_parameters = ["lease_id"] '
    'allowed_parameters = { "lease_id" = ["database/creds/poc-readonly/*"] } }'
)


def target(uri):
    try:
        parsed = urlsplit(uri)
        port = parsed.port or 5432
        if parsed.scheme not in ("postgres", "postgresql") or not all(
            (parsed.hostname, parsed.username, parsed.password, parsed.path.strip("/"))
        ):
            raise ValueError
        if parsed.query or parsed.fragment or parsed.netloc.count("@") != 1:
            raise ValueError
        user = unquote(parsed.username)
        suffix = ""
        if ".pooler.supabase.com" in parsed.hostname:
            if port != 5432 or not re.fullmatch(r"[A-Za-z0-9_]+\.[a-z0-9]+", user):
                raise ValueError
            user, project = user.rsplit(".", 1)
            suffix = "." + project
        return {
            "host": parsed.hostname,
            "port": port,
            "database": unquote(parsed.path.strip("/")),
            "user": user,
            "suffix": suffix,
            "password": unquote(parsed.password),
        }
    except (ValueError, TypeError, AttributeError):
        raise SecurityError("database_uri_invalid") from None


async def main():
    settings = Settings()
    uri = dotenv_values(".env.local").get("SUPABASE_DB_URI")
    ca = settings.database_sslrootcert
    if not uri or not ca or not Path(ca).is_file():
        raise SecurityError("database_provisioning_configuration_missing")
    if not settings.vault_addr or not settings.vault_token:
        raise SecurityError("vault_operator_configuration_missing")
    db = target(uri)
    connect_args = dict(
        host=db["host"],
        port=db["port"],
        dbname=db["database"],
        user=db["user"] + db["suffix"],
        password=db["password"],
        sslmode="verify-full",
        sslrootcert=ca,
        connect_timeout=10,
    )
    # Never alter a table that was created by another application.
    async with await psycopg.AsyncConnection.connect(**connect_args) as conn:
        cur = await conn.execute(
            "SELECT obj_description(to_regclass('public.poc_records'), 'pg_class'), "
            "to_regclass('public.poc_records') IS NOT NULL"
        )
        comment, exists = await cur.fetchone()
        if exists and comment != MARKER:
            raise SecurityError("database_fixture_name_conflict")
        if not exists:
            await conn.execute(
                "CREATE TABLE public.poc_records (id integer PRIMARY KEY, status text NOT NULL)"
            )
            await conn.execute(
                "COMMENT ON TABLE public.poc_records IS "
                "'pocdantic synthetic credential-flow fixture'"
            )
            await conn.execute("INSERT INTO public.poc_records VALUES (1,'healthy'),(2,'review')")
            await conn.execute("ALTER TABLE public.poc_records ENABLE ROW LEVEL SECURITY")
            await conn.execute("REVOKE ALL ON public.poc_records FROM PUBLIC, anon, authenticated")
            await conn.execute(
                "CREATE POLICY pocdantic_select ON public.poc_records "
                "FOR SELECT TO PUBLIC USING (true)"
            )
    print(json.dumps({"fixture": "ready", "tls": "verified"}), flush=True)
    evidence = {
        "observed_at": datetime.now(UTC).isoformat(),
        "source": "live_hcp_vault_postgres",
        "obo_enforced": False,
    }
    async with httpx.AsyncClient(timeout=30, follow_redirects=False) as http:
        vault = VaultClient(settings.vault_addr, settings.vault_namespace, http)
        operator = settings.vault_token
        mounts = await vault.read(operator, "sys/mounts")
        mount = mounts.get("data", {}).get("database/")
        if mount and mount.get("type") != "database":
            raise SecurityError("vault_mount_name_conflict")
        if not mount:
            await vault.request("POST", "sys/mounts/database", operator, {"type": "database"})
        connection_url = (
            "postgresql://{{username}}"
            + db["suffix"]
            + ":{{password}}@"
            + db["host"]
            + ":"
            + str(db["port"])
            + "/"
            + quote(db["database"], safe="")
            + "?sslmode=verify-full"
        )
        await vault.request(
            "POST",
            f"database/config/{CONNECTION}",
            operator,
            {
                "plugin_name": "postgresql-database-plugin",
                "allowed_roles": [ROLE],
                "connection_url": connection_url,
                "username": db["user"],
                "password": db["password"],
                "tls_ca": Path(ca).read_text(),
                "password_authentication": "scram-sha-256",
                "max_open_connections": 2,
                "max_connection_lifetime": "1m",
            },
        )
        await vault.request(
            "POST",
            f"database/roles/{ROLE}",
            operator,
            {
                "db_name": CONNECTION,
                "default_ttl": "2m",
                "max_ttl": "5m",
                "creation_statements": [CREATION],
                "revocation_statements": [REVOCATION],
            },
        )
        await vault.request("PUT", f"sys/policies/acl/{POLICY}", operator, {"policy": ACL})
        issued = await vault.request(
            "POST",
            "auth/token/create",
            operator,
            {
                "policies": [POLICY],
                "ttl": "5m",
                "no_default_policy": True,
                "display_name": "pocdantic-db-validation",
            },
        )
        reader = SecretStr(issued["auth"]["client_token"])
        try:
            async with vault.credentials(reader, "database/creds/" + ROLE) as lease:
                rows = await read_postgres(
                    lease,
                    host=db["host"],
                    port=db["port"],
                    database=db["database"],
                    record_id=1,
                    sslrootcert=ca,
                    username_suffix=db["suffix"],
                )
                if rows != [{"id": 1, "status": "healthy"}]:
                    raise SecurityError("database_fixture_result_invalid")
                evidence["select_succeeded"] = True
                leased_args = dict(
                    connect_args,
                    user=lease.username.get_secret_value() + db["suffix"],
                    password=lease.password.get_secret_value(),
                )
                async with await psycopg.AsyncConnection.connect(**leased_args) as conn:
                    try:
                        await conn.execute("UPDATE public.poc_records SET status='bad' WHERE id=1")
                        raise SecurityError("database_write_unexpectedly_allowed")
                    except psycopg.errors.InsufficientPrivilege:
                        evidence["update_denied_by_postgres"] = True
            evidence["lease_revoked"] = True
            # Confirm the server is healthy before testing the revoked credential.
            async with await psycopg.AsyncConnection.connect(**connect_args) as conn:
                cur = await conn.execute(
                    "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = %s)",
                    (lease.username.get_secret_value(),),
                )
                if (await cur.fetchone())[0]:
                    raise SecurityError("revoked_database_role_still_exists")
                evidence["revoked_role_removed"] = True
            try:
                async with await psycopg.AsyncConnection.connect(**leased_args) as conn:
                    await conn.execute("SELECT status FROM public.poc_records WHERE id=1")
                    raise SecurityError("revoked_credential_reusable")
            except psycopg.OperationalError as error:
                message = str(error).lower()
                auth_rejected = any(
                    term in message
                    for term in (
                        "password authentication failed",
                        "tenant or user not found",
                        "role does not exist",
                        "wrong password",
                    )
                ) or bool(re.search(r"user[^\n]*not found", message))
                if not auth_rejected:
                    raise SecurityError("revoked_credential_result_inconclusive") from None
                evidence["revoked_credential_rejected"] = True
            try:
                await vault.read(reader, "database/creds/not-allowed")
                raise SecurityError("vault_out_of_policy_allowed")
            except SecurityError as error:
                if str(error) != "vault_http_403":
                    raise
                evidence["out_of_policy_denied_by_vault"] = True
        finally:
            await vault.request("POST", "auth/token/revoke-self", reader)
    directory = Path(".local")
    directory.mkdir(mode=0o700, exist_ok=True)
    file = directory / "database-evidence.json"
    file.write_text(json.dumps(evidence, indent=2))
    file.chmod(0o600)
    config = directory / "database-runtime.env"
    config.write_text(
        f"DATABASE_HOST={db['host']}\n"
        f"DATABASE_PORT={db['port']}\n"
        f"DATABASE_NAME={db['database']}\n"
        f"DATABASE_USERNAME_SUFFIX={db['suffix']}\n"
        f"DATABASE_SSLROOTCERT={ca}\n"
    )
    config.chmod(0o600)
    print(json.dumps(evidence))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as error:
        code = str(error) if isinstance(error, SecurityError) else type(error).__name__
        print(json.dumps({"status": "failed", "error_code": code}))
        raise SystemExit(1) from None
