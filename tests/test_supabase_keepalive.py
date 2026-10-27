"""Heartbeat checks replace the driver; ordinary tests never contact Supabase."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def load_keepalive():
    """Load the contributor helper without making it an installed runtime command."""
    path = Path(__file__).parents[1] / "scripts" / "supabase_keepalive.py"
    spec = importlib.util.spec_from_file_location("keepalive", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_configuration_never_connects(monkeypatch, capsys):
    """Absent secrets fail before any driver import or network attempt."""
    monkeypatch.delenv("SUPABASE_KEEPALIVE_DSN", raising=False)
    monkeypatch.delenv("SUPABASE_KEEPALIVE_CA", raising=False)
    assert load_keepalive().main() == 2
    assert capsys.readouterr().out == "keepalive_missing_configuration\n"


@pytest.mark.parametrize("fail", [False, True])
def test_bounded_read_cleanup_and_safe_errors(monkeypatch, capsys, fail):
    """Enforce TLS/read limits and remove the CA on both success and private failure."""
    import sys

    certificate = None
    closed = False
    monkeypatch.setenv("SUPABASE_KEEPALIVE_DSN", "synthetic-private-dsn")
    monkeypatch.setenv("SUPABASE_KEEPALIVE_CA", "synthetic-private-ca")

    class Connection:
        """Synthetic driver records query and context cleanup without effects."""

        def __enter__(self):
            return self

        def __exit__(self, *args):
            nonlocal closed
            closed = True

        def execute(self, sql):
            assert sql == "SELECT 1"
            if fail:
                raise RuntimeError("synthetic-private-provider-response")
            return SimpleNamespace(fetchone=lambda: (1,))

    def connect(dsn, **kwargs):
        """Check enforced arguments and owner-only certificate before returning a fake."""
        nonlocal certificate
        assert dsn == "synthetic-private-dsn"
        certificate = Path(kwargs.pop("sslrootcert"))
        assert certificate.read_text() == "synthetic-private-ca"
        assert certificate.stat().st_mode & 0o777 == 0o600
        assert kwargs == {
            "sslmode": "verify-full",
            "connect_timeout": 10,
            "options": "-c default_transaction_read_only=on -c statement_timeout=5000",
            "autocommit": True,
        }
        return Connection()

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=connect))
    assert load_keepalive().main() == (1 if fail else 0)
    assert closed and not certificate.exists()
    assert capsys.readouterr().out == ("keepalive_failed\n" if fail else "keepalive_ok\n")
