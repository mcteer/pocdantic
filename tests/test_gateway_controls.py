"""Per-turn control tests use native SDKs and synthetic transports, never live providers."""

import asyncio
import json

import httpx2
import pytest

from agent.gateway.config import route_policy
from agent.gateway.models import ErrorSignature
from agent.gateway.transport import Dispatch, dispatch_scope
from agent.model_config import gateway_model
from tests.gateway_support import approval, configuration


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "protocol", ["openai-chat", "openai-responses", "anthropic", "google-cloud"]
)
@pytest.mark.parametrize("administration", ["reviewed", "operator-owned"])
async def test_reviewed_block_and_unknown_schema(protocol, tmp_path, administration):
    """Exact reviewed codes classify denials; unknown codes sharing a status stay generic."""
    settings = configuration(protocol)
    signature = ErrorSignature(
        status=403, field="error.code", value="synthetic_block", reason="gateway_guardrail_denied"
    )
    store, _, _ = approval(
        tmp_path, settings, signatures=(signature,), administration=administration
    )
    calls = []

    async def receive(request):
        calls.append(request)
        return httpx2.Response(
            403, json={"error": {"code": "synthetic_block", "message": "private-echo"}}
        )

    model = gateway_model(
        settings, route_policy(settings), inner=httpx2.MockTransport(receive), store=store
    )
    from pydantic_ai.messages import ModelRequest, UserPromptPart
    from pydantic_ai.models import ModelRequestParameters

    try:
        with dispatch_scope(
            Dispatch(check=model._agent_gateway.check, signatures=(signature,))
        ) as state:
            with pytest.raises(Exception) as error:
                await model.request(
                    [ModelRequest(parts=[UserPromptPart("benign")])], None, ModelRequestParameters()
                )
            assert state.reason == "gateway_guardrail_denied"
            assert "private-echo" not in str(error.value)
    finally:
        await model._agent_gateway.aclose()
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("administration", ["reviewed", "operator-owned"])
async def test_native_runtime_attempt_and_review_rejection(tmp_path, administration):
    """A successful model turn records usage, while revoked controls stop the next run."""
    from agent.response.guard import MemoryStore
    from agent.runtime import Runtime
    from agent.schemas import Principal, RequestEnvelope

    settings = configuration()
    store, _, _ = approval(tmp_path, settings, administration=administration)
    calls = []

    async def receive(request):
        calls.append(request)
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
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": "synthetic",
                                    "type": "function",
                                    "function": {
                                        "name": "final_result",
                                        "arguments": json.dumps({"summary": "done"}),
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )

    model = gateway_model(
        settings, route_policy(settings), inner=httpx2.MockTransport(receive), store=store
    )
    runtime = Runtime(settings, model=model, response_store=MemoryStore(settings))
    principal = Principal(
        issuer="synthetic", subject="synthetic", scopes=frozenset({"tickets:read"})
    )
    try:
        result = await runtime.run(
            RequestEnvelope(task="Synthetic result", profile="ticket-reader"), principal
        )
        assert result.status == "completed", result.error_code
        store.reject("operator")
        result = await runtime.run(
            RequestEnvelope(task="Synthetic result", profile="ticket-reader"), principal
        )
        assert result.error_code == "gateway_review_required"
    finally:
        await runtime.aclose()
    assert len(calls) == 1
    records = [
        json.loads(p.read_text()) for p in (tmp_path / ".local/gateway").glob("*-completed.json")
    ]
    assert len(records) == 1 and records[0]["input_tokens"] == 3
    assert records[0]["cost_usd"] is None and records[0]["cost_state"] == "unknown"


def test_local_admission_budget(tmp_path):
    """A thousand warm local checks stay within the planned p95 overhead budget."""
    import time
    from statistics import quantiles

    store, _, expected = approval(tmp_path, configuration())
    for _ in range(10):
        store.admit(expected)
    times = []
    for _ in range(1000):
        start = time.perf_counter()
        store.admit(expected)
        times.append((time.perf_counter() - start) * 1000)
    assert quantiles(times, n=100)[94] <= 25


@pytest.mark.asyncio
@pytest.mark.parametrize("administration", ["reviewed", "operator-owned"])
async def test_post_tool_block_does_not_repeat_read(tmp_path, administration):
    """A later model refusal cannot replay an already completed trusted tool read."""
    from agent.response.guard import MemoryStore
    from agent.runtime import Runtime
    from agent.schemas import Principal, RequestEnvelope

    settings = configuration()
    signature = ErrorSignature(
        status=403, field="error.code", value="synthetic_block", reason="gateway_guardrail_denied"
    )
    store, _, _ = approval(
        tmp_path, settings, signatures=(signature,), administration=administration
    )
    calls = []
    reads = []

    async def receive(request):
        body = json.loads(request.content)
        calls.append(body)
        if len(calls) > 1:
            return httpx2.Response(403, json={"error": {"code": "synthetic_block"}})
        names = [tool["function"]["name"] for tool in body["tools"]]
        tool = next(name for name in names if name != "final_result")
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
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": "synthetic",
                                    "type": "function",
                                    "function": {
                                        "name": tool,
                                        "arguments": json.dumps({"record_id": 1}),
                                    },
                                }
                            ],
                        },
                    }
                ],
            },
        )

    async def read(record_id):
        reads.append(record_id)
        return [{"id": record_id, "status": "open"}]

    model = gateway_model(
        settings, route_policy(settings), inner=httpx2.MockTransport(receive), store=store
    )
    runtime = Runtime(
        settings, model=model, response_store=MemoryStore(settings), database_reader=read
    )
    try:
        result = await runtime.run(
            RequestEnvelope(task="Read record 1", profile="database-reader"),
            Principal(issuer="synthetic", subject="synthetic", scopes=frozenset({"database:read"})),
        )
        assert result.error_code == "gateway_guardrail_denied"
    finally:
        await runtime.aclose()
    assert reads == [1] and len(calls) == 2


@pytest.mark.asyncio
async def test_cancellation_after_dispatch_is_unknown(tmp_path):
    """Cancellation drains the model task and preserves uncertainty rather than retrying."""
    from agent.response.guard import MemoryStore
    from agent.runtime import Runtime
    from agent.schemas import Principal, RequestEnvelope

    settings = configuration(timeout_seconds=1)
    store, _, _ = approval(tmp_path, settings)
    sent = asyncio.Event()
    drained = asyncio.Event()

    async def receive(request):
        sent.set()
        try:
            await asyncio.Future()
        finally:
            drained.set()

    model = gateway_model(
        settings, route_policy(settings), inner=httpx2.MockTransport(receive), store=store
    )
    runtime = Runtime(settings, model=model, response_store=MemoryStore(settings))
    task = asyncio.create_task(
        runtime.run(
            RequestEnvelope(task="Synthetic", profile="ticket-reader"),
            Principal(issuer="synthetic", subject="synthetic", scopes=frozenset({"tickets:read"})),
        )
    )
    await asyncio.wait_for(sent.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await runtime.aclose()
    assert drained.is_set()
    assert len(list((tmp_path / ".local/gateway").glob("*-unknown.json"))) == 1


@pytest.mark.asyncio
async def test_concurrent_parent_child_turns_are_independently_observed(tmp_path):
    """Shared native clients preserve each root/child identity and one-send turn context."""
    from agent.response.guard import MemoryStore
    from agent.runtime import Runtime
    from agent.schemas import Principal, RequestEnvelope

    settings = configuration()
    store, _, _ = approval(tmp_path, settings)
    calls = []

    async def receive(request):
        """Respond to actual tools while each conversation independently advances."""
        body = json.loads(request.content)
        calls.append(body)
        names = {tool["function"]["name"] for tool in body["tools"]}
        if any(message["role"] == "tool" for message in body["messages"]):
            name, args = "final_result", {"summary": "Synthetic facts"}
        elif "delegate_ticket" in names:
            name, args = "delegate_ticket", {"ticket_id": "POC-1"}
        else:
            name, args = "get_jira_ticket", {"ticket_id": "POC-1"}
        await asyncio.sleep(0)
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
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": "synthetic",
                                    "type": "function",
                                    "function": {"name": name, "arguments": json.dumps(args)},
                                }
                            ],
                        },
                    }
                ],
            },
        )

    model = gateway_model(
        settings, route_policy(settings), inner=httpx2.MockTransport(receive), store=store
    )
    runtime = Runtime(settings, model=model, response_store=MemoryStore(settings))
    principal = Principal(
        issuer="synthetic", subject="synthetic", scopes=frozenset({"tickets:read"})
    )
    try:
        results = await asyncio.gather(
            *(runtime.run(RequestEnvelope(task="Get POC-1"), principal) for _ in range(2))
        )
        assert all(result.status == "completed" for result in results)
    finally:
        await runtime.aclose()
    records = [
        json.loads(p.read_text()) for p in (tmp_path / ".local/gateway").glob("*-completed.json")
    ]
    assert len(calls) == len(records) == 8
    roots = {str(result.run_id) for result in results}
    assert {r["run_id"] for r in records if r["parent_run_id"] is None} == roots
    assert {r["parent_run_id"] for r in records if r["parent_run_id"] is not None} == roots
    assert len({r["attempt_id"] for r in records}) == 8


@pytest.mark.asyncio
async def test_shutdown_drains_before_closing_client(tmp_path):
    """Runtime shutdown contains active roots and awaits model cancellation/cleanup first."""
    from agent.response.guard import MemoryStore
    from agent.runtime import Runtime
    from agent.schemas import Principal, RequestEnvelope

    settings = configuration()
    store, _, _ = approval(tmp_path, settings)
    sent = asyncio.Event()
    drained = asyncio.Event()

    async def receive(request):
        """Own an interrupted HTTP send until its cancellation drain is observed."""
        sent.set()
        try:
            await asyncio.Future()
        finally:
            drained.set()

    model = gateway_model(
        settings, route_policy(settings), inner=httpx2.MockTransport(receive), store=store
    )
    runtime = Runtime(settings, model=model, response_store=MemoryStore(settings))
    principal = Principal(
        issuer="synthetic", subject="synthetic", scopes=frozenset({"tickets:read"})
    )
    task = asyncio.create_task(
        runtime.run(RequestEnvelope(task="Synthetic", profile="ticket-reader"), principal)
    )
    await asyncio.wait_for(sent.wait(), 2)
    await runtime.aclose()
    assert drained.is_set() and task.done() and model._agent_gateway.client.is_closed
    result = await runtime.run(
        RequestEnvelope(task="Synthetic", profile="ticket-reader"), principal
    )
    assert result.error_code == "contained"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["storage", "exporter"])
async def test_observation_failures_never_bypass_dispatch_or_mask_refusal(
    tmp_path, monkeypatch, failure
):
    """Start persistence fails closed; an exporter failure remains degraded with safe refusal."""
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

    from agent.gateway.models import GatewayError
    from agent.response.guard import MemoryStore
    from agent.runtime import Runtime
    from agent.schemas import Principal, RequestEnvelope
    from agent.telemetry import configure_telemetry

    class FailedExporter(SpanExporter):
        def export(self, spans):
            """Simulate a destination refusal without throwing private provider text."""
            return SpanExportResult.FAILURE

    settings = configuration()
    store, _, _ = approval(tmp_path, settings)
    calls = []

    async def receive(request):
        """Return a safe synthetic refusal, never a successful model answer."""
        calls.append(request)
        return httpx2.Response(403, json={"error": {"message": "PRIVATE"}})

    telemetry = configure_telemetry(settings, exporter=FailedExporter())
    model = gateway_model(
        settings, route_policy(settings), inner=httpx2.MockTransport(receive), store=store
    )
    runtime = Runtime(
        settings, model=model, telemetry=telemetry, response_store=MemoryStore(settings)
    )
    if failure == "storage":

        def unavailable(event):
            """Simulate local persistence failure before sending model content."""
            raise GatewayError("gateway_observation_failed")

        monkeypatch.setattr(store, "record", unavailable)
    try:
        result = await runtime.run(
            RequestEnvelope(task="Synthetic result", profile="ticket-reader"),
            Principal(issuer="synthetic", subject="synthetic", scopes=frozenset({"tickets:read"})),
        )
        assert result.error_code == (
            "gateway_observation_failed" if failure == "storage" else "gateway_request_failed"
        )
        assert len(calls) == (0 if failure == "storage" else 1)
        if failure == "exporter":
            assert store.attempts()[0].telemetry_state == "degraded"
    finally:
        await runtime.aclose()
        telemetry.shutdown()


def test_injected_live_model_cannot_bypass_gateway(tmp_path):
    """Only trusted synthetic models bypass live admission; arbitrary live injection cannot."""
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

    from agent.gateway.models import GatewayError
    from agent.response.guard import MemoryStore
    from agent.runtime import Runtime

    settings = configuration()
    supplied = OpenAIChatModel("synthetic", provider=OpenAIProvider(api_key="synthetic"))
    with pytest.raises(GatewayError, match="gateway_model_denied"):
        Runtime(settings, model=supplied, response_store=MemoryStore(settings))
