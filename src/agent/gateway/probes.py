"""Fixed synthetic text probes; no caller-supplied prompt, tool execution or live secret.

Probe outcomes demonstrate HTTP behavior only. Native provider absence, remote retention and
budget scope still require explicit operator source review before activation.
"""

import asyncio
import base64
import json
from uuid import uuid4

from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    SystemPromptPart,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.tools import ToolDefinition

from .models import GatewayError, now
from .transport import Dispatch, dispatch_scope

PROTOCOLS = ("openai-chat", "openai-responses", "anthropic", "google-cloud")
CLASSES = (
    "openai_key",
    "anthropic_key",
    "google_key",
    "gateway_key",
    "vault_token",
    "bearer_jwt",
    "private_key",
    "database_uri",
    "password",
    "client_secret",
)
SURFACES = ("user", "instructions", "history", "tool_arguments", "tool_result")


def cases(protocol):
    """Enumerate every required positive and near-match negative case for one protocol."""
    return {
        f"{protocol}_{surface}_{kind}_{action}": (surface, kind, action)
        for surface in SURFACES
        for kind in CLASSES
        for action in ("block", "allow")
    }


def canary(kind, *, benign=False):
    """Generate invalid synthetic shape matches in memory; never read configured credentials."""
    nonce = uuid4().hex + uuid4().hex
    if benign:
        return f"Synthetic example of {kind}; reference {nonce[:8]}."
    values = {
        "openai_key": "sk-" + nonce,
        "anthropic_key": "sk-ant-api03-" + nonce,
        "google_key": "AI" + "za" + nonce[:35],
        "gateway_key": "py" + "lf_" + nonce,
        "vault_token": "hv" + "s." + nonce,
        "bearer_jwt": "Bearer "
        + base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
        + "."
        + base64.urlsafe_b64encode(b'{"synthetic":true}').decode().rstrip("=")
        + ".invalid",
        "private_key": "-----BEGIN "
        + "PRIVATE KEY-----\ninvalid-synthetic\n-----END PRIVATE KEY-----",
        "database_uri": "postgresql://synthetic:" + nonce + "@database.example/synthetic",
        "password": "password=" + nonce,
        "client_secret": "client_secret=" + nonce,
    }
    return values[kind]


def messages(surface, text):
    """Construct native structured message surfaces without ever executing the fake tool."""
    prompt = ModelRequest(parts=[UserPromptPart("Reply with a short synthetic acknowledgement.")])
    if surface == "user":
        return [ModelRequest(parts=[UserPromptPart(text)])]
    if surface == "instructions":
        return [ModelRequest(parts=[SystemPromptPart(text), *prompt.parts])]
    if surface == "history":
        return [
            ModelRequest(parts=[UserPromptPart("Synthetic earlier turn")]),
            ModelResponse(parts=[TextPart(text)]),
            prompt,
        ]
    args = {"value": text if surface == "tool_arguments" else "synthetic"}
    result = text if surface == "tool_result" else "synthetic"
    return [
        ModelRequest(parts=[UserPromptPart("Synthetic tool exchange")]),
        ModelResponse(parts=[ToolCallPart("synthetic_tool", args, tool_call_id="synthetic")]),
        ModelRequest(
            parts=[
                ToolReturnPart("synthetic_tool", result, tool_call_id="synthetic"),
                *prompt.parts,
            ]
        ),
    ]


async def probe(settings, model, case_id):
    """Send one named synthetic case and store its content-free observation, without approval."""
    boundary = model._agent_gateway
    catalog = cases(boundary.policy.protocol)
    if case_id not in catalog:
        raise GatewayError("gateway_configuration_invalid")
    surface, kind, expected = catalog[case_id]
    seconds = min(settings.timeout_seconds, 30)
    state = Dispatch(check=lambda: None, deadline=asyncio.get_running_loop().time() + seconds)
    # Candidate mappings are not approval and cannot activate normal work. They only classify
    # vendor codes whose source the operator will review separately in the final bundle.
    try:
        candidate, _ = boundary.store.evidence("candidate")
        state.signatures = candidate.error_signatures
    except GatewayError:
        pass
    outcome = "unknown"
    reason = None
    try:
        async with asyncio.timeout(seconds):
            with dispatch_scope(state):
                await model.request(
                    messages(surface, canary(kind, benign=expected == "allow")),
                    {"max_tokens": 64},
                    ModelRequestParameters(
                        function_tools=[
                            ToolDefinition(
                                name="synthetic_tool",
                                parameters_json_schema={
                                    "type": "object",
                                    "properties": {"value": {"type": "string"}},
                                },
                            )
                        ]
                    ),
                )
            outcome = "pass" if expected == "allow" else "fail"
    except asyncio.CancelledError:
        raise
    except Exception:
        reason = state.reason or (
            "gateway_dispatch_unknown" if state.sent else "gateway_request_failed"
        )
        if reason == "gateway_guardrail_denied":
            outcome = "pass" if expected == "block" else "fail"
    result = {
        "schema_version": 1,
        "gateway_probe": True,
        "case_id": case_id,
        "disposition": outcome,
        "reason": reason,
        "observed_at": now().isoformat(),
    }
    with boundary.store.directory(create=True) as fd:
        boundary.store.write(fd, f"probe-{uuid4()}.json", json.dumps(result).encode())
    return result
