"""Final model transport refuses alternate destinations, ambient headers and retries."""

import httpx2
import pytest
from pydantic import SecretStr

from agent.gateway.models import GatewayError, RoutePolicy
from agent.gateway.transport import Dispatch, GatewayTransport, dispatch_scope


def policy():
    """Use only a fake native model; no fixture holds a usable credential."""
    return RoutePolicy(
        region="us",
        route="synthetic",
        protocol="openai-chat",
        model="synthetic",
        allowed_models=("openai-chat:synthetic",),
    )


@pytest.mark.asyncio
async def test_final_headers_and_single_send():
    """SDK hooks cannot retain a poisoned Authorization header or replay a turn."""
    calls = []

    async def receive(request):
        calls.append(request)
        assert request.headers["authorization"] == "Bearer synthetic-gateway-key"
        assert "x-api-key" not in request.headers
        assert "baggage" not in request.headers
        return httpx2.Response(200, json={"ok": True})

    transport = GatewayTransport(
        policy(), SecretStr("synthetic-gateway-key"), inner=httpx2.MockTransport(receive)
    )
    async with httpx2.AsyncClient(transport=transport) as client:
        with dispatch_scope(Dispatch(check=lambda: None)):
            await client.post(
                policy().base_url + "/proxy/synthetic/chat/completions",
                headers={
                    "authorization": "private-other",
                    "x-api-key": "private-other",
                    "baggage": "private-other",
                },
                json={"model": "synthetic", "messages": []},
            )
            with pytest.raises(GatewayError):
                await client.post(policy().base_url + "/proxy/synthetic/chat/completions", json={})
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "suffix", ["/files", "/chat/completions?api_key=bad", "/../other/chat/completions"]
)
async def test_wrong_path_never_dispatches(suffix):
    """Unapproved URLs are refused before the inner transport."""

    async def fail(request):
        pytest.fail("unexpected dispatch")

    async with httpx2.AsyncClient(
        transport=GatewayTransport(
            policy(), SecretStr("synthetic-key"), inner=httpx2.MockTransport(fail)
        )
    ) as client:
        with dispatch_scope(Dispatch(check=lambda: None)):
            with pytest.raises(GatewayError):
                await client.post(policy().base_url + "/proxy/synthetic" + suffix, json={})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "protocol", ["openai-chat", "openai-responses", "anthropic", "google-cloud"]
)
async def test_native_protocols_cannot_retry_or_leak_errors(protocol, monkeypatch):
    """Exercise real SDK request mapping, environment headers and generic remote errors."""
    from pydantic_ai.messages import ModelRequest, UserPromptPart
    from pydantic_ai.models import ModelRequestParameters

    from agent.gateway.config import route_policy
    from agent.model_config import gateway_model
    from agent.settings import Settings

    monkeypatch.setenv("OPENAI_CUSTOM_HEADERS", "Authorization: private-poison\nX-Private: bad")
    monkeypatch.setenv("ANTHROPIC_CUSTOM_HEADERS", "Authorization: private-poison\nX-Private: bad")
    settings = Settings(
        _env_file=None,
        model_mode="gateway",
        model=protocol + ":synthetic",
        gateway_region="us",
        gateway_route="synthetic",
        gateway_models=(protocol + ":synthetic",),
        gateway_api_key="synthetic-key",
    )
    calls = []

    async def receive(request):
        calls.append(request)
        assert request.headers["authorization"] == "Bearer synthetic-key"
        assert "x-private" not in request.headers
        return httpx2.Response(429, json={"error": {"message": "private-provider-body"}})

    model = gateway_model(settings, route_policy(settings), inner=httpx2.MockTransport(receive))
    try:
        with dispatch_scope(Dispatch(check=lambda: None)) as state:
            with pytest.raises(Exception) as error:
                await model.request(
                    [ModelRequest(parts=[UserPromptPart("benign")])], None, ModelRequestParameters()
                )
            assert "private-provider-body" not in str(error.value)
            assert state.reason == "gateway_request_failed"
    finally:
        await model._agent_gateway.aclose()
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"model": "other"},
        {"model": "synthetic", "stream": True},
        {"model": "synthetic", "input": [{"type": "input_image"}]},
    ],
)
async def test_unreviewed_model_or_surface_has_zero_sends(payload):
    """Final serialized bytes cannot select another model or an unreviewed content path."""
    calls = []

    async def receive(request):
        calls.append(request)
        return httpx2.Response(200)

    transport = GatewayTransport(
        policy(), SecretStr("synthetic"), inner=httpx2.MockTransport(receive)
    )
    async with httpx2.AsyncClient(transport=transport) as client:
        with dispatch_scope(Dispatch(check=lambda: None)):
            with pytest.raises(GatewayError):
                await client.post(
                    policy().base_url + "/proxy/synthetic/chat/completions", json=payload
                )
    assert not calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason",
    [
        "gateway_budget_denied",
        "gateway_auth_denied",
        "gateway_model_denied",
        "gateway_rate_limited",
    ],
)
@pytest.mark.parametrize("signature_field", ["error.code", "response_sha256"])
async def test_exact_control_signature_and_shared_status(reason, signature_field):
    """Every reviewed refusal is terminal; unknown/malformed/oversized bodies stay generic."""
    from agent.gateway.models import ErrorSignature

    bodies = [
        b'{"error":{"code":"synthetic_refusal"}}',
        b'{"error":{"code":"other"}}',
        b"not-json",
        b"x" * 16385,
    ]
    calls = []

    async def receive(request):
        calls.append(request)
        return httpx2.Response(429, content=bodies[len(calls) - 1])

    transport = GatewayTransport(
        policy(), SecretStr("synthetic"), inner=httpx2.MockTransport(receive)
    )
    import hashlib

    signature = ErrorSignature(
        status=429,
        field=signature_field,
        value=(
            hashlib.sha256(bodies[0]).hexdigest()
            if signature_field == "response_sha256"
            else "synthetic_refusal"
        ),
        reason=reason,
    )
    async with httpx2.AsyncClient(transport=transport) as client:
        for index in range(len(bodies)):
            with dispatch_scope(Dispatch(check=lambda: None, signatures=(signature,))) as state:
                with pytest.raises(GatewayError):
                    await client.post(
                        policy().base_url + "/proxy/synthetic/chat/completions",
                        json={"model": "synthetic"},
                    )
                assert state.reason == (reason if index == 0 else "gateway_request_failed")
    assert len(calls) == len(bodies)


@pytest.mark.asyncio
async def test_real_http11_framing_survives_header_sanitization():
    """Exercise actual HTTP/1.1 serialization with an in-memory network, not a mock transport."""
    import httpcore2
    from httpcore2._backends.mock import AsyncMockBackend, AsyncMockStream

    written = []

    class Stream(AsyncMockStream):
        async def write(self, buffer, timeout=None):
            """Capture native framed bytes without opening a socket."""
            written.append(buffer)

    class Backend(AsyncMockBackend):
        async def connect_tcp(
            self, host, port, timeout=None, local_address=None, socket_options=None
        ):
            """Return the synthetic network stream; no DNS/TCP/provider request occurs."""
            return Stream([b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"])

    native = httpx2.AsyncHTTPTransport(trust_env=False, retries=0)
    native._pool = httpcore2.AsyncConnectionPool(network_backend=Backend([]), retries=0)
    transport = GatewayTransport(policy(), SecretStr("synthetic-key"), inner=native)
    async with httpx2.AsyncClient(transport=transport) as client:
        with dispatch_scope(Dispatch(check=lambda: None)):
            response = await client.post(
                policy().base_url + "/proxy/synthetic/chat/completions",
                headers={"Host": "other.invalid", "Content-Type": "PRIVATE", "Accept": "PRIVATE"},
                json={"model": "synthetic", "messages": []},
            )
            assert response.status_code == 200
    wire = b"".join(written)
    assert b"Host: gateway-us.pydantic.dev" in wire or b"host: gateway-us.pydantic.dev" in wire
    assert b"content-length:" in wire.lower()
    assert b"other.invalid" not in wire and b"PRIVATE" not in wire


def test_reviewed_response_fingerprint_never_matches_generic_status():
    """A native refusal without a machine code needs exact bytes, never keyword matching."""
    import hashlib

    from pydantic import ValidationError

    from agent.gateway.models import ErrorSignature

    raw = (
        b'{"error":{"code":400,"message":"synthetic guardrail refusal",'
        b'"status":"INVALID_ARGUMENT"}}'
    )
    signature = ErrorSignature(
        status=400,
        field="response_sha256",
        value=hashlib.sha256(raw).hexdigest(),
        reason="gateway_guardrail_denied",
    )
    assert signature.matches(400, raw)
    assert not signature.matches(403, raw)
    assert not signature.matches(400, raw.replace(b"refusal", b"other"))
    assert not signature.matches(400, b'{"error":{"code":400}}')
    assert not signature.matches(400, b"x" * 16385)
    assert "synthetic guardrail refusal" not in signature.model_dump_json()
    with pytest.raises(ValidationError):
        ErrorSignature(
            status=400,
            field="response_sha256",
            value="not-a-digest",
            reason="gateway_guardrail_denied",
        )
