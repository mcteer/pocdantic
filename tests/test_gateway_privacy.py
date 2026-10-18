"""Native serialized text surfaces, closed failures and secret-isolated observations."""

import json
from types import SimpleNamespace

import httpx2
import pytest

from agent.gateway.config import route_policy
from agent.gateway.models import ErrorSignature, ModelAttempt
from agent.gateway.probes import cases, probe
from agent.gateway.review import ReviewStore
from agent.model_config import gateway_model
from tests.gateway_support import configuration


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "protocol", ["openai-chat", "openai-responses", "anthropic", "google-cloud"]
)
async def test_every_synthetic_surface_and_benign_control(protocol, tmp_path, caplog):
    """Four real SDK serializers exercise the full fixed matrix against a fake vendor.

    The service here is a controlled response fixture, not an implementation of Pydantic DLP.
    This proves serialization/refusal contracts only; actual recognizer coverage remains live.
    """
    settings = configuration(protocol)
    store = ReviewStore(tmp_path)
    signatures = (
        ErrorSignature(
            status=403,
            field="error.code",
            value="synthetic_block",
            reason="gateway_guardrail_denied",
        ),
    )
    store.evidence = lambda _: (SimpleNamespace(error_signatures=signatures), "synthetic")
    current = {}
    calls = []

    async def receive(request):
        body = request.content.decode()
        payload = json.loads(body)
        if protocol == "google-cloud":
            assert payload["generationConfig"]["maxOutputTokens"] == 64
        elif protocol == "openai-responses":
            assert payload["max_output_tokens"] == 64
        elif protocol == "anthropic":
            assert payload["max_tokens"] == 64
        else:
            assert payload.get("max_completion_tokens", payload.get("max_tokens")) == 64
        assert "synthetic-private-key" not in body
        assert request.headers["authorization"] == "Bearer synthetic-private-key"
        calls.append(current["case"])
        if current["case"].endswith("_block"):
            return httpx2.Response(
                403, json={"error": {"code": "synthetic_block", "message": body}}
            )
        if protocol.startswith("openai") and protocol.endswith("responses"):
            return httpx2.Response(
                200,
                json={
                    "id": "resp_synthetic",
                    "object": "response",
                    "created_at": 0,
                    "model": "synthetic",
                    "status": "completed",
                    "output": [],
                },
            )
        if protocol == "openai-chat":
            return httpx2.Response(
                200,
                json={
                    "id": "synthetic",
                    "object": "chat.completion",
                    "created": 0,
                    "model": "synthetic",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop",
                        }
                    ],
                },
            )
        if protocol == "anthropic":
            return httpx2.Response(
                200,
                json={
                    "id": "synthetic",
                    "type": "message",
                    "role": "assistant",
                    "model": "synthetic",
                    "content": [{"type": "text", "text": "ok"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            )
        return httpx2.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {"role": "model", "parts": [{"text": "ok"}]},
                        "finishReason": "STOP",
                    }
                ]
            },
        )

    model = gateway_model(
        settings, route_policy(settings), inner=httpx2.MockTransport(receive), store=store
    )
    try:
        for name in cases(protocol):
            current["case"] = name
            result = await probe(settings, model, name)
            assert result["disposition"] == "pass", (name, result)
    finally:
        await model._agent_gateway.aclose()
    assert len(calls) == 100
    records = "".join(p.read_text() for p in (tmp_path / ".local/gateway").glob("probe-*.json"))
    assert "synthetic-private-key" not in records
    assert "synthetic-private-key" not in caplog.text
    assert "private-provider-body" not in records


def test_private_artifacts_never_publish():
    """Relocating a review outside .local must not make it a publishable artifact."""
    from scripts.publish_policy import publishable

    assert not publishable(".local/gateway/current.json")
    assert not publishable("specs/014-gateway-guardrails/evidence/current.json")


def test_cost_requires_observation_and_closed_reasons():
    """Missing cost cannot silently become zero or an unbounded provider message."""
    from uuid import uuid4

    values = dict(
        run_id=uuid4(),
        request_id=uuid4(),
        definition_ref=uuid4(),
        workload_ref=uuid4(),
        sequence=1,
        route_ref=uuid4(),
        model_ref=uuid4(),
        protocol="openai-chat",
        stage="completed",
    )
    with pytest.raises(ValueError):
        ModelAttempt(**values, cost_usd="0")
    with pytest.raises(ValueError):
        ModelAttempt(**values, reason="private upstream text")


def test_relocated_gateway_source_is_private():
    """Generic filenames cannot hide private review/attempt/registry/probe material."""
    from scripts.publish_policy import private_content

    shapes = [
        dict(
            review_id="synthetic", decision="rejected", credential_digest=None, evidence_digest=None
        ),
        dict(
            attempt_id="synthetic",
            route_ref="synthetic",
            model_ref="synthetic",
            protocol="openai-chat",
        ),
        dict(gateway_policy_digest="synthetic", route_policy={}),
        dict(
            gateway_probe=True, case_id="synthetic", disposition="unknown", observed_at="synthetic"
        ),
    ]
    for shape in shapes:
        assert private_content(
            "specs/014-gateway-guardrails/renamed.json", json.dumps(shape).encode()
        )
