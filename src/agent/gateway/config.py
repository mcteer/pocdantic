"""Explicit hosted model admission, digest binding and bounded private names."""

import hashlib
import json
import re
from uuid import UUID

from .models import GatewayError, RoutePolicy


def digest(value) -> str:
    """Hash canonical public configuration or already-private source bytes."""
    raw = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def safe_name(value: str) -> bool:
    """Accept one bounded basename, excluding traversal and hidden control files."""
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value)) and ".." not in value


def route_policy(settings) -> RoutePolicy | None:
    """Resolve only explicit authority; legacy direct mode never implies Gateway protection."""
    if settings.model_mode is None:
        raise GatewayError("model_mode_required")
    if settings.model_mode == "direct":
        return None
    try:
        key = settings.gateway_api_key
        raw = key.get_secret_value() if key else ""
        if not raw or raw.strip() != raw or any(ord(c) < 33 or ord(c) > 126 for c in raw):
            raise ValueError()
        prefix, separator, model = settings.model.partition(":")
        if not separator:
            raise ValueError()
        return RoutePolicy(
            region=settings.gateway_region,
            route=settings.gateway_route,
            protocol=prefix,
            model=model,
            allowed_models=settings.gateway_models,
        )
    except Exception:
        raise GatewayError("gateway_configuration_invalid") from None


def bindings(settings, policy) -> dict[str, str]:
    """Bind approval to exact route/key/source bytes without exporting credential digests."""
    from agent.validation.models import implementation_revision

    return {
        "policy_digest": digest(policy.model_dump()),
        "credential_digest": digest(settings.gateway_api_key.get_secret_value().encode()),
        "implementation_digest": implementation_revision(),
    }


def opaque_ref(value: str) -> UUID:
    """Derive a stable opaque reference from a private digest, not a public tenant label."""
    return UUID(value[:32])
