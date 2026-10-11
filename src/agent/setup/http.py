"""Provider-specific verified TLS clients; private CA failures become closed errors."""

import hashlib
import ssl
from pathlib import Path

import httpx

from agent.security import SecurityError
from agent.validation.store import StoreError, read_private


def tls_context(settings, provider):
    """Load only the selected provider's CA bundle without disabling hostname verification."""
    path = getattr(settings, f"{provider}_ca_file")
    try:
        if path:
            ca_digest(path)  # Reject oversized bundles before the TLS library reads them.
        return ssl.create_default_context(cafile=path) if path else ssl.create_default_context()
    except (OSError, ValueError, ssl.SSLError):
        raise SecurityError("configuration_missing") from None


def ca_digest(path):
    """Fingerprint CA content for private recovery context, rejecting unbounded files."""
    if not path:
        return None
    try:
        raw = read_private(Path(path).absolute())
        if len(raw) > 262144:
            raise ValueError()
        return hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, StoreError):
        raise SecurityError("configuration_missing") from None


def client(settings, provider, *, transport=None, timeout=10):
    """Construct a bounded no-redirect client with explicit provider-specific trust."""
    return httpx.AsyncClient(
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
        verify=tls_context(settings, provider),
        **({"transport": transport} if transport is not None else {}),
    )
