"""Explicit operational heartbeat using dedicated credentials, never application dotenv.

The caller supplies a read-only DSN and trusted PEM CA through environment variables.
Only a constant SELECT is executed; failures return a fixed code without provider text.
The workflow additionally bounds the entire process to thirty seconds.
"""

import os
from pathlib import Path
from tempfile import TemporaryDirectory


def main() -> int:
    """Read one constant and close the connection, returning 0, 1 or missing-input 2.

    The temporary certificate is owner-only and removed even on connection/query failure.
    Credentials and provider exceptions are never printed or used in command arguments.
    """
    dsn = os.environ.get("SUPABASE_KEEPALIVE_DSN", "")
    ca = os.environ.get("SUPABASE_KEEPALIVE_CA", "")
    if not dsn.strip() or not ca.strip():
        print("keepalive_missing_configuration")
        return 2
    try:
        import psycopg

        with TemporaryDirectory(prefix="keepalive-") as directory:
            certificate = Path(directory) / "ca.pem"
            certificate.touch(mode=0o600)
            certificate.write_text(ca)
            # Keyword arguments override DSN settings: TLS and read bounds cannot weaken.
            with psycopg.connect(
                dsn,
                sslmode="verify-full",
                sslrootcert=str(certificate),
                connect_timeout=10,
                options="-c default_transaction_read_only=on -c statement_timeout=5000",
                autocommit=True,
            ) as connection:
                if connection.execute("SELECT 1").fetchone() != (1,):
                    print("keepalive_unexpected_result")
                    return 1
    except Exception:
        # Database errors can contain hosts, usernames, passwords or certificate details.
        print("keepalive_failed")
        return 1
    print("keepalive_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
