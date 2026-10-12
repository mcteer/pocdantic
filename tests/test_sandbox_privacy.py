"""Exporter boundaries exclude private generated source, parameters, rows and output."""

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from agent.runtime import Runtime
from agent.schemas import Principal, RequestEnvelope
from agent.settings import Settings
from agent.telemetry import AllowlistProvider, Telemetry


@pytest.mark.asyncio
async def test_generated_payloads_are_not_exported():
    exporter = InMemorySpanExporter()
    sdk = TracerProvider()
    sdk.add_span_processor(SimpleSpanProcessor(exporter))

    class Reader:
        async def query(self, plan):
            return {"rows": [{"status": "PRIVATE_ROW"}], "row_count": 1, "truncated": False}

    code = (
        'canary = "PRIVATE_SOURCE"\nprint("PRIVATE_PRINT")\n'
        'r = await query_database("SELECT status FROM poc_records WHERE status = $1",'
        ' ["PRIVATE_PARAMETER"])\nr["rows"][0]["status"]'
    )

    def model(messages, info):
        if not any(isinstance(p, ToolReturnPart) for m in messages for p in m.parts):
            return ModelResponse(parts=[ToolCallPart("run_python", {"code": code})])
        return ModelResponse(
            parts=[ToolCallPart(info.output_tools[0].name, {"summary": "PRIVATE_RESULT"})]
        )

    runtime = Runtime(
        Settings(_env_file=None),
        model=FunctionModel(model),
        database_reader=Reader(),
        telemetry=Telemetry(provider=AllowlistProvider(sdk), sdk=sdk),
    )
    result = await runtime.run(
        RequestEnvelope(task="PRIVATE_PROMPT", profile="database-analyst"),
        Principal(
            issuer="https://identity.example",
            subject="fixture",
            scopes=frozenset({"database:read"}),
        ),
    )
    assert result.status == "completed", result
    raw = "\n".join(s.to_json() for s in exporter.get_finished_spans())
    assert "PRIVATE_" not in raw and '"name": "sandbox"' in raw
    sdk.shutdown()
