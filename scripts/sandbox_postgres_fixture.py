#!/usr/bin/env python3
"""Run one compiler test against an isolated disposable TLS PostgreSQL container.

No application environment or database target is used. The container binds a random
loopback port, generates its own TLS material, and is removed even when pytest fails.
"""

import os
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

IMAGE = "postgres:18@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336"


def docker(*args):
    """Invoke a fixed Docker argument vector, without shell expansion or credentials."""
    return subprocess.run(["docker", *args], check=True, capture_output=True).stdout


def main():
    """Prepare only synthetic TLS/admin state and pass explicit fixture coordinates to pytest."""
    name = "agent-sandbox-test-" + uuid4().hex[:12]
    started = False
    try:
        command = (
            "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost "
            "-addext subjectAltName=DNS:localhost,IP:127.0.0.1 "
            "-keyout /tmp/fixture.key -out /tmp/fixture.crt >/dev/null 2>&1 && "
            "chown postgres:postgres /tmp/fixture.key /tmp/fixture.crt && "
            "chmod 600 /tmp/fixture.key && "
            "exec docker-entrypoint.sh postgres -c ssl=on "
            "-c ssl_cert_file=/tmp/fixture.crt -c ssl_key_file=/tmp/fixture.key"
        )
        docker(
            "run",
            "-d",
            "--name",
            name,
            "-p",
            "127.0.0.1::5432",
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "--entrypoint",
            "sh",
            IMAGE,
            "-c",
            command,
        )
        started = True
        docker(
            "exec",
            name,
            "sh",
            "-c",
            "for n in $(seq 1 100); do pg_isready -U postgres >/dev/null 2>&1 "
            "&& exit 0; sleep .1; done; exit 1",
        )
        mapping = docker("port", name, "5432").decode().strip()
        assert mapping.startswith("127.0.0.1:")
        port = mapping.rsplit(":", 1)[1]
        with tempfile.TemporaryDirectory(prefix="agent-postgres-tls-") as folder:
            ca = Path(folder) / "ca.pem"
            ca.write_bytes(docker("exec", name, "cat", "/tmp/fixture.crt"))
            ca.chmod(0o600)
            env = os.environ | {"SANDBOX_POSTGRES_PORT": port, "SANDBOX_POSTGRES_CA": str(ca)}
            result = subprocess.run(
                ["uv", "run", "pytest", "-q", "tests/test_sandbox_postgres.py"], env=env
            )
            return result.returncode
    finally:
        if started:
            docker("rm", "-f", name)


if __name__ == "__main__":
    raise SystemExit(main())
