"""Provider TLS bundles remain separate and never disable server authentication."""

import ssl

import pytest

from agent.security import SecurityError
from agent.settings import Settings
from agent.setup.http import ca_digest, tls_context


def test_separate_ca_selection(monkeypatch):
    """Each provider loads only its own configured bundle with normal verification."""
    calls = []
    monkeypatch.setattr(ssl, "create_default_context", lambda **kw: calls.append(kw) or kw)
    monkeypatch.setattr("agent.setup.http.ca_digest", lambda path: "a" * 64)
    settings = Settings(_env_file=None, oauth_ca_file="identity.pem", vault_ca_file="vault.pem")
    tls_context(settings, "oauth")
    tls_context(settings, "vault")
    assert calls == [{"cafile": "identity.pem"}, {"cafile": "vault.pem"}]


def test_bad_ca_is_closed_and_private(tmp_path):
    """Invalid trust cannot fall back to insecure verification or disclose private paths."""
    file = tmp_path / "private-provider-name.pem"
    file.write_text("not a certificate")
    settings = Settings(_env_file=None, oauth_ca_file=str(file))
    with pytest.raises(SecurityError, match="^configuration_missing$"):
        tls_context(settings, "oauth")
    assert tls_context(settings, "vault").verify_mode == ssl.CERT_REQUIRED
    assert tls_context(settings, "vault").check_hostname
    file.write_bytes(b"x" * 262145)
    with pytest.raises(SecurityError, match="^configuration_missing$"):
        ca_digest(str(file))


def test_fifo_ca_cannot_hang_local_check(tmp_path):
    """Configured trust must be a bounded regular file, not a pipe waiting for a writer."""
    import os

    file = tmp_path / "ca.pipe"
    os.mkfifo(file, 0o600)
    with pytest.raises(SecurityError, match="^configuration_missing$"):
        ca_digest(str(file))
