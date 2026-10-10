import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic_ai import Agent
from pydantic_ai.agent import InstrumentationSettings
from pydantic_ai.capabilities import Instrumentation
from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from agent.schemas import AgentOutput


async def test_instrumentation_omits_prompts_arguments_and_results():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    def respond(messages, info):
        if not any(isinstance(p, ToolReturnPart) for m in messages for p in m.parts):
            return ModelResponse(
                parts=[ToolCallPart("lookup", {"text": "PRIVATE_ARGUMENT_SENTINEL"})]
            )
        return ModelResponse(
            parts=[ToolCallPart(info.output_tools[0].name, {"summary": "PRIVATE_OUTPUT_SENTINEL"})]
        )

    agent = Agent(
        FunctionModel(respond),
        output_type=AgentOutput,
        capabilities=[
            Instrumentation(
                settings=InstrumentationSettings(
                    tracer_provider=provider,
                    include_content=False,
                    include_binary_content=False,
                    include_model_request_parameters=False,
                )
            )
        ],
    )

    @agent.tool_plain
    def lookup(text: str) -> str:
        return "PRIVATE_TOOL_RESULT_SENTINEL"

    await agent.run("PRIVATE_PROMPT_SENTINEL")
    spans = exporter.get_finished_spans()
    assert spans
    data = "\n".join(span.to_json() for span in spans)
    assert "PRIVATE_" not in data
    # Telemetry still includes span names and usage for operational visibility.
    assert "lookup" in data
    provider.shutdown()


def test_wrapper_filters_every_mutation_and_serialized_payload(monkeypatch):
    from opentelemetry import baggage
    from opentelemetry.context import Context
    from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.trace import Link, Status, StatusCode

    from agent.telemetry import AllowlistProvider

    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", "secret=PRIVATE_RESOURCE_CANARY")
    exporter = InMemorySpanExporter()
    sdk = TracerProvider(resource=Resource({"service.name": "agent"}))
    sdk.add_span_processor(SimpleSpanProcessor(exporter))
    provider = AllowlistProvider(sdk)
    tracer = provider.get_tracer("PRIVATE_SCOPE_CANARY", attributes={"secret": "PRIVATE_CANARY"})
    ambient = baggage.set_baggage("secret", "PRIVATE_BAGGAGE_CANARY")
    with tracer.start_as_current_span(
        "PRIVATE_NAME_CANARY", context=Context(), attributes={"secret": "PRIVATE_INITIAL_CANARY"}
    ) as span:
        span.set_attribute("secret", "PRIVATE_UPDATE_CANARY")
        span.update_name("PRIVATE_UPDATED_NAME_CANARY")
        span.add_event("PRIVATE_EVENT_CANARY", {"secret": "PRIVATE_EVENT_VALUE_CANARY"})
        span.record_exception(RuntimeError("PRIVATE_EXCEPTION_CANARY"))
        span.set_status(Status(StatusCode.ERROR, "PRIVATE_STATUS_CANARY"))
        span.add_link(span.get_span_context(), {"secret": "PRIVATE_LINK_CANARY"})
        ambient = baggage.set_baggage("secret", "PRIVATE_BAGGAGE_CANARY")
        with tracer.start_as_current_span(
            "run", context=ambient, links=[Link(span.get_span_context(), {"secret": "PRIVATE"})]
        ):
            pass
    spans = exporter.get_finished_spans()
    data = "\n".join(s.to_json() for s in spans)
    assert "PRIVATE" not in data
    assert b"PRIVATE" not in encode_spans(spans).SerializeToString()
    assert spans[0].parent.span_id == spans[1].context.span_id
    assert all(s.instrumentation_scope.name == "agent" for s in spans)
    sdk.shutdown()


def test_transport_suppresses_redirect_errors_and_partial_rejection():
    import httpx
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceResponse

    from agent.telemetry import SafeOTLPSession

    response = ExportTraceServiceResponse()
    response.partial_success.rejected_spans = 1
    for status, content in [
        (302, b"PRIVATE_DIAGNOSTIC"),
        (500, b"PRIVATE_DIAGNOSTIC"),
        (200, response.SerializeToString()),
    ]:
        calls = []

        def handler(request, calls=calls, status=status, content=content):
            calls.append(request)
            return httpx.Response(
                status, content=content, headers={"location": "https://evil.invalid"}
            )

        session = SafeOTLPSession(
            "https://safe.invalid/v1/traces",
            "PRIVATE_TOKEN",
            transport=httpx.MockTransport(handler),
        )
        reply = session.post("https://safe.invalid/v1/traces", b"safe", timeout=1)
        assert not reply.ok and reply.reason == "telemetry_export_failed"
        assert len(calls) == 1
        assert "PRIVATE" not in reply.text
        session.close()


async def test_native_nested_runtime_and_lifecycle_canaries(monkeypatch):
    import socket

    from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans

    from agent.demo import model
    from agent.runtime import Runtime
    from agent.schemas import Principal, RequestEnvelope
    from agent.telemetry import configure_telemetry
    from agent.validation.scenarios import offline_settings

    def denied(*args, **kwargs):
        raise AssertionError("ambient network")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://PRIVATE.invalid")
    exporter = InMemorySpanExporter()
    telemetry = configure_telemetry(offline_settings(), exporter=exporter)
    runtime = Runtime(offline_settings(), model=model(), telemetry=telemetry)
    result = await runtime.run(
        RequestEnvelope(task="PRIVATE_PROMPT_CANARY"),
        Principal(
            issuer="PRIVATE_ISSUER", subject="PRIVATE_SUBJECT", scopes=frozenset({"tickets:read"})
        ),
    )
    assert result.status == "completed"
    assert telemetry.flush()
    spans = exporter.get_finished_spans()
    assert spans and len({s.context.trace_id for s in spans}) == 1
    assert sum(s.parent is None for s in spans) == 1
    assert sum(s.name == "agent" for s in spans) >= 2
    assert {"run", "delegation", "policy"} <= {s.name for s in spans}
    assert b"PRIVATE" not in encode_spans(spans).SerializeToString()
    assert not telemetry.delivery.received
    assert telemetry.delivery.acknowledged == telemetry.delivery.attempted
    telemetry.shutdown()


async def test_native_denial_exception_cancellation_canaries():
    import asyncio

    from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans

    from agent.runtime import Runtime
    from agent.schemas import Principal, RequestEnvelope
    from agent.telemetry import configure_telemetry
    from agent.validation.scenarios import offline_settings

    for mode in ["denial", "exception", "cancellation"]:
        exporter = InMemorySpanExporter()
        telemetry = configure_telemetry(offline_settings(), exporter=exporter)
        ready = asyncio.Event()

        async def respond(messages, info, mode=mode, ready=ready):
            if mode == "denial":
                return ModelResponse(
                    parts=[ToolCallPart("delegate_ticket", {"ticket_id": "POC-1"})]
                )
            if mode == "exception":
                raise RuntimeError("PRIVATE_UPSTREAM_EXCEPTION")
            ready.set()
            await asyncio.Future()

        runtime = Runtime(offline_settings(), model=FunctionModel(respond), telemetry=telemetry)
        task = asyncio.create_task(
            runtime.run(
                RequestEnvelope(task="PRIVATE_PROMPT"),
                Principal(issuer="PRIVATE_ISSUER", subject="PRIVATE_SUBJECT"),
            )
        )
        if mode == "cancellation":
            await ready.wait()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        else:
            result = await task
            assert result.status in {"denied", "failed"}
        spans = exporter.get_finished_spans()
        assert spans and b"PRIVATE" not in encode_spans(spans).SerializeToString()
        assert len({s.context.trace_id for s in spans}) == 1
        telemetry.shutdown()


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://unsafe.invalid",
        "https://user:secret@safe.invalid",
        "https://safe.invalid?secret",
        "https://safe.invalid#secret",
    ],
)
def test_logfire_endpoint_rejects_untrusted_forms(endpoint):
    from pydantic import ValidationError

    from agent.settings import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None, logfire_base_url=endpoint)


def test_response_action_labels_cannot_carry_private_identifiers():
    """The export boundary preserves only known action/status values."""
    from agent.telemetry import safe_attributes

    assert safe_attributes(
        {
            "response_action": "revoke_exact",
            "response_status": "uncertain",
            "incident_id": "secret-canary",
            "source": "secret-canary",
            "native_handle": "secret-canary",
        }
    ) == {"response_action": "revoke_exact", "response_status": "uncertain"}
    assert safe_attributes({"response_action": "secret-canary"}) == {}


def test_provider_telemetry_has_only_closed_codes():
    """Provider native identities, messages and destination canaries cannot enter exported spans."""
    from types import SimpleNamespace

    from agent.observability import provider_action
    from agent.telemetry import AllowlistProvider

    exporter = InMemorySpanExporter()
    sdk = TracerProvider()
    sdk.add_span_processor(SimpleSpanProcessor(exporter))
    telemetry = SimpleNamespace(provider=AllowlistProvider(sdk))
    provider_action(telemetry, "block_registration", "acknowledged", "not_run")
    provider_action(
        telemetry, "PRIVATE_NATIVE_CANARY", "PRIVATE_DESTINATION_CANARY", "PRIVATE_RESPONSE_CANARY"
    )
    spans = exporter.get_finished_spans()
    assert spans[0].attributes["provider_action"] == "block_registration"
    assert "PRIVATE" not in "\n".join(span.to_json() for span in spans)
    sdk.shutdown()
