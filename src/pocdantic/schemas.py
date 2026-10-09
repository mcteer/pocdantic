from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue

TicketId = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9]{1,15}-[1-9][0-9]{0,8}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Principal(StrictModel):
    issuer: str
    subject: str
    scopes: frozenset[str] = frozenset()
    expires_at: int | None = None


class RequestEnvelope(StrictModel):
    task: str = Field(min_length=1, max_length=8000)
    request_id: UUID = Field(default_factory=uuid4)
    profile: str = Field(default="parent", pattern=r"^[a-z][a-z0-9-]{1,63}$")


class AgentOutput(StrictModel):
    summary: str


class AgentResponse(StrictModel):
    request_id: UUID
    run_id: UUID
    correlation_id: str
    status: Literal["completed", "denied", "failed"]
    output: AgentOutput | None = None
    error_code: str | None = None


class Ticket(StrictModel):
    ticket_id: TicketId
    title: str
    description: str
    source: Literal["synthetic", "live"] = "synthetic"


class Action(StrictModel):
    operation: str
    resource: str
    parameters: dict[str, JsonValue] = Field(default_factory=dict)


class AgentDefinition(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    instructions: str
    capabilities: tuple[str, ...]
    policy_role: Literal["parent", "ticket-reader"] = "ticket-reader"


class WriteResult(StrictModel):
    status: Literal["approval_required", "simulated"]
    approval_id: UUID
    action_digest: str
