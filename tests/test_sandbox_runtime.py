"""Model text cannot manufacture sandbox/database completion."""

import pytest
from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from agent.runtime import Runtime
from agent.schemas import Principal, RequestEnvelope
from agent.settings import Settings


@pytest.mark.asyncio
async def test_model_generated_program_and_refusal():
    class Reader:
        async def query(self, plan):
            assert plan.kind == "count"
            return {"rows": [{"count": 4}], "row_count": 1, "truncated": False}

    def model(messages, info):
        if not any(isinstance(p, ToolReturnPart) for m in messages for p in m.parts):
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "run_python",
                        {
                            "code": (
                                'r = await query_database("SELECT COUNT(*) FROM poc_records", [])\n'
                                'r["rows"][0]["count"] * 2'
                            )
                        },
                    )
                ]
            )
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, {"summary": "8"})])

    runtime = Runtime(
        Settings(_env_file=None), model=FunctionModel(model), database_reader=Reader()
    )
    result = await runtime.run(
        RequestEnvelope(task="Count and double", profile="database-analyst"),
        Principal(
            issuer="https://identity.example",
            subject="fixture",
            scopes=frozenset({"database:read"}),
        ),
    )
    assert result.status == "completed", result
    assert runtime.sandbox_runs[result.run_id].reads == 1
    assert any(e["event"] == "sandbox" for e in runtime.audit.events)


@pytest.mark.asyncio
async def test_model_refusal_does_not_claim_monty_execution():
    def refuse(messages, info):
        return ModelResponse(
            parts=[ToolCallPart(info.output_tools[0].name, {"summary": "I cannot SSH"})]
        )

    runtime = Runtime(Settings(_env_file=None), model=FunctionModel(refuse))
    result = await runtime.run(
        RequestEnvelope(task="Run SSH", profile="database-analyst"),
        Principal(
            issuer="https://identity.example",
            subject="fixture",
            scopes=frozenset({"database:read"}),
        ),
    )
    assert result.error_code == "sandbox_not_exercised"
    assert runtime.sandbox_runs[result.run_id].inspection()["engine"] == "not_exercised"
