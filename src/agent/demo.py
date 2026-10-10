from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel


def model() -> FunctionModel:
    """Deterministic tool arguments; fixtures never rely on schema random generation."""

    def respond(messages, info):
        returned = any(
            isinstance(part, ToolReturnPart) for message in messages for part in message.parts
        )
        if not returned and info.function_tools:
            names = {tool.name for tool in info.function_tools}
            tool = "delegate_ticket" if "delegate_ticket" in names else "get_jira_ticket"
            return ModelResponse(parts=[ToolCallPart(tool, {"ticket_id": "POC-1"})])
        return ModelResponse(
            parts=[
                ToolCallPart(
                    info.output_tools[0].name,
                    {"summary": "Synthetic POC-1 ticket retrieved by the restricted child."},
                )
            ]
        )

    return FunctionModel(respond)
