"""Final hosted model HTTP boundary with single-send context and safe remote failures.

The inner SDK may add environment headers or try compatibility retries. This boundary is
last before network dispatch and therefore owns exact destination, auth and attempt count.
"""

import asyncio
import json
import re
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

import httpx2
from pydantic import SecretStr

from .models import GatewayError, RoutePolicy


@dataclass
class Dispatch:
    """Context-local mutable send guard; never shared between logical model attempts."""

    check: Callable
    sent: bool = False
    on_send: Callable = lambda: None
    signatures: tuple = ()
    status: int | None = None
    reason: str | None = None
    deadline: float | None = None
    private_ids: dict = field(default_factory=dict, repr=False)


_current: ContextVar[Dispatch | None] = ContextVar("gateway_dispatch", default=None)


@contextmanager
def dispatch_scope(state):
    """Install one trusted model attempt, restoring parent state even on cancellation."""
    token = _current.set(state)
    try:
        yield state
    finally:
        _current.reset(token)


def inspect_payload(value):
    """Reject binary/remote media and provider-hosted features; ordinary text/tools remain."""
    if isinstance(value, dict):
        forbidden = {
            "image_url",
            "inline_data",
            "inlineData",
            "file_data",
            "fileData",
            "audio",
            "video",
            "attachments",
            "container",
            "thinking",
            "file_id",
        }
        if forbidden & value.keys() or value.get("stream") is True:
            raise GatewayError("gateway_payload_unsupported")
        kind = value.get("type")
        if isinstance(kind, str) and kind in {
            "image",
            "input_image",
            "input_audio",
            "document",
            "code_execution",
            "web_search",
            "computer",
        }:
            raise GatewayError("gateway_payload_unsupported")
        # Only application-defined tools are admitted; provider-hosted tools add opaque data paths.
        if "tools" in value:
            for tool in value["tools"]:
                if isinstance(tool, dict) and not (
                    tool.get("type") == "function"
                    or "function" in tool
                    or ("name" in tool and "input_schema" in tool)
                    or "function_declarations" in tool
                    or "functionDeclarations" in tool
                ):
                    raise GatewayError("gateway_payload_unsupported")
        for item in value.values():
            inspect_payload(item)
    elif isinstance(value, list):
        for item in value:
            inspect_payload(item)


class GatewayTransport(httpx2.AsyncBaseTransport):
    """Strip every unapproved header and refuse errors before native SDK instrumentation."""

    def __init__(self, policy: RoutePolicy, key: SecretStr, *, inner=None):
        """Own an explicit verified transport; inner injection is a trusted synthetic test seam."""
        self.policy, self.key = policy, key
        self.inner = inner or httpx2.AsyncHTTPTransport(trust_env=False, retries=0)

    def valid_path(self, request):
        """Check exact host, port, route and native operation, without URL normalization tricks."""
        url = request.url
        if (
            url.scheme != "https"
            or url.host != f"gateway-{self.policy.region}.pydantic.dev"
            or url.port not in (None, 443)
            or url.username
            or url.password
            or request.method != "POST"
            or (
                url.query
                and not (self.policy.protocol == "anthropic" and url.query == b"beta=true")
            )
        ):
            return False
        base = f"/proxy/{self.policy.route}"
        paths = {
            "openai-chat": "/chat/completions",
            "openai-responses": "/responses",
            "anthropic": "/v1/messages",
        }
        if self.policy.protocol in paths:
            return url.path == base + paths[self.policy.protocol]
        model = re.escape(self.policy.model)
        return bool(
            re.fullmatch(
                re.escape(base)
                + rf"/v1(?:beta1)?/publishers/google/models/{model}:generateContent",
                url.path,
            )
        )

    async def handle_async_request(self, request):
        """Preserve a closed outcome even if a native SDK wraps the transport exception."""
        try:
            return await self._handle(request)
        except GatewayError as error:
            state = _current.get()
            if state is not None:
                state.reason = str(error)
            raise

    async def _handle(self, request):
        """Authorize one send, normalize refusals and contain uncertainty without retries."""
        state = _current.get()
        if state is None or state.sent or not self.valid_path(request):
            raise GatewayError("gateway_configuration_invalid")
        try:
            raw = await request.aread()
            if len(raw) > 1024 * 1024:
                raise GatewayError("gateway_payload_unsupported")
            payload = json.loads(raw)
            inspect_payload(payload)
            if self.policy.protocol != "google-cloud" and payload.get("model") != self.policy.model:
                raise GatewayError("gateway_model_denied")
        except GatewayError:
            raise
        except Exception:
            raise GatewayError("gateway_payload_unsupported") from None
        state.check()
        request.headers.clear()
        # Rebuild required HTTP framing from validated bytes/origin. Retaining an SDK's
        # Host or length permits poisoning; omitting them fails native HTTP/1.1 serialization.
        request.headers["host"] = f"gateway-{self.policy.region}.pydantic.dev"
        request.headers["content-length"] = str(len(raw))
        request.headers["content-type"] = "application/json"
        request.headers["accept"] = "application/json"
        if self.policy.protocol == "anthropic":
            request.headers["anthropic-version"] = "2023-06-01"
        request.headers["authorization"] = "Bearer " + self.key.get_secret_value()
        # Cookies/custom auth/baggage cannot survive the final hook, including SDK env injection.
        state.on_send()
        state.sent = True
        try:
            timeout = asyncio.timeout_at(state.deadline) if state.deadline else asyncio.timeout(300)
            async with timeout:
                response = await self.inner.handle_async_request(request)
                state.status = response.status_code
                if not 200 <= response.status_code < 300:
                    reason = "gateway_request_failed"
                    # No vendor signature is guessed: reviewed exact schema mappings may supplement
                    # generic refusal. A status alone never proves guardrail or budget denial.
                    body = bytearray()
                    async for part in response.aiter_bytes():
                        body.extend(part[: 16385 - len(body)])
                        if len(body) > 16384:
                            break
                    await response.aclose()
                    for signature in state.signatures:
                        if signature.matches(response.status_code, bytes(body)):
                            reason = signature.reason
                            break
                    state.reason = reason
                    raise GatewayError(reason)
                return response
        except (GatewayError, asyncio.CancelledError):
            raise
        except Exception:
            state.reason = "gateway_dispatch_unknown"
            raise GatewayError("gateway_dispatch_unknown") from None

    async def aclose(self):
        """Close all owned model connections after active work has drained."""
        await self.inner.aclose()
