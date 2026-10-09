#!/usr/bin/env python3
"""Local TLS PostgreSQL fixture for the existing HCP Vault integration."""

import argparse
import asyncio
import ipaddress
import json
import secrets
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from dotenv import dotenv_values

from pocdantic.security import SecurityError

LOCAL = Path(".local")
ENV = LOCAL / "lab.env"
PG_CA = LOCAL / "lab-tls" / "ca.crt"


def compose(*args):
    result = subprocess.run(
        ["docker", "compose", "--env-file", str(ENV), *args], capture_output=True
    )
    if result.returncode:
        # Docker interpolation or container diagnostics may include credentials.
        raise SecurityError("local_lab_container_command_failed")
    return result.stdout


def generate_files():
    LOCAL.mkdir(mode=0o700, exist_ok=True)
    if not ENV.exists():
        ENV.write_text("LAB_POSTGRES_ADMIN_PASSWORD=" + secrets.token_urlsafe(32) + "\n")
        ENV.chmod(0o600)
    directory = PG_CA.parent
    directory.mkdir(mode=0o700, exist_ok=True)
    if PG_CA.exists():
        return
    now = datetime.now(UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pocdantic local lab CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "postgres")]))
        .issuer_name(name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("postgres"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    PG_CA.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (directory / "postgres.crt").write_bytes(server.public_bytes(serialization.Encoding.PEM))
    private = directory / "postgres.key"
    private.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private.chmod(0o600)
    # The CA private key is intentionally discarded; certificates can be regenerated for a new lab.


async def verify():
    import psycopg

    values = dotenv_values(ENV)
    async with await psycopg.AsyncConnection.connect(
        host="127.0.0.1",
        port=55432,
        dbname="poc",
        user="poc_admin",
        password=values["LAB_POSTGRES_ADMIN_PASSWORD"],
        sslmode="verify-full",
        sslrootcert=str(PG_CA),
        connect_timeout=5,
    ) as connection:
        result = await connection.execute("SELECT id, status FROM public.poc_records ORDER BY id")
        rows = await result.fetchall()
        if rows != [(1, "healthy"), (2, "review")]:
            raise SecurityError("local_postgres_fixture_invalid")
    print(
        json.dumps(
            {
                "postgres": "ready",
                "address": "127.0.0.1:55432/poc",
                "tls_verified": True,
                "vault_target": "existing_hcp_instance",
            }
        )
    )


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["up", "verify", "down"])
    args = parser.parse_args()
    if args.command == "up":
        generate_files()
        compose("up", "-d", "--wait", "--wait-timeout", "90")
        await verify()
    elif args.command == "verify":
        await verify()
    else:
        compose("down")
        print(json.dumps({"lab": "stopped", "postgres_volume": "retained"}))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as error:
        code = str(error) if isinstance(error, SecurityError) else type(error).__name__
        raise SystemExit(json.dumps({"status": "failed", "error_code": code})) from None
