"""Bounded provider HTTP and isolated administrative execution.

Only fixed enrolled targets enter requests. Raw responses are parsed privately and
replaced with closed outcomes; credentials travel to child workers through stdin only.
"""

import hashlib
from typing import Literal

import httpx

from agent.recovery.models import Digest, Private
from agent.response.models import ResponseError
from agent.validation.store import decode_json

from .models import REASONS, Proof, https_origin


class Result(Private):
    """Safe adapter result; control readback never fills an unrelated enforcement proof."""

    state: Literal["acknowledged", "denied", "failed", "uncertain", "reconciled"] = "acknowledged"
    reason: Literal[tuple(sorted(REASONS))] = "provider_acknowledged"
    path: (
        Literal[
            "registration",
            "native_token",
            "native_token_readback",
            "tenant_session_readback",
            "static_session_readback",
            "tenant_user",
            "tenant_sessions",
            "static_session",
            "notification",
        ]
        | None
    ) = None
    proof: Proof = "not_run"
    source_digest: Digest = "0" * 64


async def request(http, method, url, *, headers=None, body=None):
    """Read at most 256 KiB, forbid redirects and discard secret-bearing error text."""
    parts = httpx.URL(url)
    https_origin(str(parts.copy_with(path="/", query=None, fragment=None)))
    try:
        async with http.stream(
            method,
            url,
            headers={"Accept-Encoding": "identity", **(headers or {})},
            json=body,
            timeout=10,
        ) as response:
            if response.headers.get("content-encoding", "identity") not in {"", "identity"}:
                raise ResponseError("provider_uncertain")
            raw = b""
            async for chunk in response.aiter_bytes(chunk_size=8192):
                raw += chunk
                if len(raw) > 262144:
                    raise ResponseError("provider_uncertain")
            if 300 <= response.status_code < 400:
                raise ResponseError("destination_invalid")
            data = decode_json(raw) if raw else {}
            if not isinstance(data, (dict, list)):
                raise ResponseError("provider_uncertain")
            return response.status_code, data, hashlib.sha256(raw).hexdigest()
    except ResponseError:
        raise
    except Exception:
        raise ResponseError("provider_uncertain") from None


def acknowledged(status, source_digest):
    """Classify an actual HTTP rejection separately from an ambiguous transport failure."""
    if status in {401, 403}:
        return Result(state="denied", reason="provider_denied", source_digest=source_digest)
    if not 200 <= status < 300:
        return Result(state="uncertain", reason="provider_uncertain", source_digest=source_digest)
    return Result(source_digest=source_digest)


class Router:
    """Select only the compiled adapter for an immutable action kind."""

    def __init__(self, settings, http, secrets=None):
        """Inject trusted authority/transport; callers cannot supply adapters in event input."""
        self.settings, self.http, self.secrets = settings, http, secrets or {}

    async def execute(self, action, *, read_only=False):
        """Dispatch one compiled operation, or bounded independent readback without mutation."""
        if action.kind in {"block_registration", "revoke_native_token", "rotate_static"}:
            from .vault import VaultAdapter

            return await VaultAdapter(self.settings, self.http).execute(action, read_only=read_only)
        if action.kind in {"suspend_user", "revoke_user_sessions"}:
            from .verify import VerifyAdapter

            return await VerifyAdapter(self.settings, self.http).execute(
                action, read_only=read_only
            )
        if action.kind == "terminate_static_sessions":
            from .database import DatabaseAdapter

            return await DatabaseAdapter(self.secrets).execute(action, read_only=read_only)
        if action.kind == "notify_teams":
            from .teams import TeamsAdapter

            return await TeamsAdapter(self.http, self.secrets).execute(action, read_only=read_only)
        raise ResponseError("unsupported")
