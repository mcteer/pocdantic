from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic_ai import Agent
from pydantic_ai.agent import InstrumentationSettings
from pydantic_ai.capabilities import Instrumentation
from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from pocdantic.schemas import AgentOutput


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
