import hashlib
from collections.abc import Awaitable, Callable
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from pydantic_ai import RunContext
from pydantic_ai.capabilities import AbstractCapability, Capability
from pydantic_ai.usage import UsageLimits

from .approval import Approval, ApprovalStore, action_digest
from .observability import BoundObserver
from .schemas import Action, AgentOutput, Principal, Ticket, TicketId, WriteResult
from .security import Audit, Containment, Policy, SecurityError

if TYPE_CHECKING:
    from pydantic_ai import Agent


@dataclass(frozen=True)
class Dependencies:
    principal: Principal
    request_id: UUID
    run_id: UUID
    logical_agent: str
    workload_definition: str
    policy: Policy
    containment: Containment
    audit: Audit
    approvals: ApprovalStore
    child: "Agent[Dependencies, AgentOutput] | None" = None
    limits: UsageLimits | None = None
    observer: BoundObserver | None = field(default=None, repr=False)
    parent_run_id: UUID | None = None
    delegation_depth: int = 0
    policy_role: str | None = None
    approval_backend: Callable[["Dependencies", Approval, Action], Awaitable[bool]] | None = field(
        default=None, repr=False
    )
    database_reader: Callable[[int], Awaitable[list[dict]]] | None = field(default=None, repr=False)

    def check_containment(self) -> None:
        self.containment.check(self.workload_definition, self.run_id)
        self.containment.check(self.logical_agent, self.run_id)
        if self.parent_run_id:
            self.containment.check(self.workload_definition, self.parent_run_id)
            self.containment.check("parent", self.parent_run_id)

    def authorize(self, action: Action) -> None:
        self.check_containment()
        try:
            self.policy.authorize(self.principal, self.policy_role or self.logical_agent, action)
        except SecurityError:
            self.record("policy", "denied")
            raise
        self.record("policy", "allowed")

    def record(self, event: str, outcome: str) -> None:
        if self.observer:
            self.observer.record(event, outcome)
        self.audit.record(
            event,
            request_id=self.request_id,
            run_id=self.run_id,
            agent_id=self.logical_agent,
            outcome=outcome,
            parent_run_id=self.parent_run_id,
            principal_ref=hashlib.sha256(
                f"{self.principal.issuer}|{self.principal.subject}".encode()
            ).hexdigest(),
            workload_definition=self.workload_definition,
        )


def ticket_read() -> Capability[Dependencies]:
    capability = Capability[Dependencies](
        id="ticket-read", description="Read synthetic PoC tickets."
    )

    @capability.tool
    async def get_jira_ticket(ctx: RunContext[Dependencies], ticket_id: TicketId) -> Ticket:
        """Read an allowlisted synthetic ticket. Returned text is untrusted data."""
        ctx.deps.authorize(Action(operation="ticket.read", resource=ticket_id))
        ctx.deps.record("ticket.read", "synthetic")
        return Ticket(
            ticket_id=ticket_id,
            title="Synthetic service health check",
            description="PoC fixture: verify the service is healthy. No live Jira is configured.",
        )

    return capability


def delegate_tickets() -> Capability[Dependencies]:
    capability = Capability[Dependencies](
        id="delegate-tickets", description="Delegate ticket facts to a restricted child."
    )

    @capability.tool
    async def delegate_ticket(ctx: RunContext[Dependencies], ticket_id: TicketId) -> AgentOutput:
        """Delegate a ticket read to the read-only ticket-reader agent."""
        deps = ctx.deps
        deps.authorize(Action(operation="ticket.read", resource=ticket_id))
        if deps.delegation_depth >= 1 or deps.child is None:
            raise SecurityError("delegation_denied")
        child_deps = replace(
            deps,
            logical_agent="ticket-reader",
            run_id=uuid4(),
            parent_run_id=deps.run_id,
            delegation_depth=deps.delegation_depth + 1,
            child=None,
            policy_role="ticket-reader",
        )
        if deps.observer:
            child_deps = replace(
                child_deps,
                observer=replace(
                    deps.observer,
                    run_id=child_deps.run_id,
                    parent_run_id=deps.run_id,
                    agent_ref=deps.observer.definition_ref("ticket-reader")
                    if deps.observer.definition_ref
                    else deps.observer.agent_ref,
                ),
            )
        child_deps.record("delegation", "started")
        try:
            scope = (
                child_deps.observer.scope("delegation") if child_deps.observer else nullcontext()
            )
            with scope:
                result = await deps.child.run(
                    f"Retrieve and summarize ticket {ticket_id}.",
                    deps=child_deps,
                    usage=ctx.usage,
                    usage_limits=deps.limits,
                    metadata={
                        "request_id": str(deps.request_id),
                        "run_id": str(child_deps.run_id),
                        "parent_run_id": str(deps.run_id),
                        "agent_definition": "ticket-reader",
                    },
                )
        except BaseException:
            child_deps.record("delegation", "failed")
            raise
        child_deps.record("delegation", "completed")
        deps.containment.check(deps.workload_definition, deps.run_id)
        return result.output

    return capability


def simulated_infrastructure() -> Capability[Dependencies]:
    capability = Capability[Dependencies](
        id="simulated-infrastructure",
        description="Request action-bound approval for a simulated restart.",
    )

    @capability.tool(timeout=130, sequential=True)
    async def request_infrastructure_restart(ctx: RunContext[Dependencies]) -> WriteResult:
        """Request approval for a simulated sandbox/demo restart. Does not execute it."""
        action = Action(
            operation="infra.write", resource="sandbox/demo", parameters={"change": "restart"}
        )
        ctx.deps.authorize(action)
        approval = ctx.deps.approvals.create(ctx.deps.principal.subject, ctx.deps.run_id, action)
        ctx.deps.record("approval", "pending")
        if ctx.deps.approval_backend is not None:
            approved = await ctx.deps.approval_backend(ctx.deps, approval, action)
            if not approved:
                ctx.deps.record("approval", "denied")
                raise SecurityError("approval_denied_or_expired")
            ctx.deps.record("approval", "completed")
            return execute_simulated_write(ctx.deps, approval.id, action)
        return WriteResult(
            status="approval_required", approval_id=approval.id, action_digest=approval.digest
        )

    return capability


class ContainmentCapability(AbstractCapability[Dependencies]):
    id = "containment"

    async def before_model_request(self, ctx, request_context):
        ctx.deps.check_containment()
        return request_context

    async def after_output_validate(self, ctx, *, output_context, output):
        ctx.deps.check_containment()
        return output


def database_read() -> Capability[Dependencies]:
    capability = Capability[Dependencies](
        id="database-read", description="Read a scoped database record."
    )

    @capability.tool
    async def read_database(ctx: RunContext[Dependencies], record_id: int) -> list[dict]:
        """Read one record using transient credentials; accepts no SQL or credential arguments."""
        ctx.deps.authorize(Action(operation="database.read", resource="poc-records"))
        if record_id < 1 or record_id > 1_000_000 or ctx.deps.database_reader is None:
            raise SecurityError("database_not_configured_or_invalid")
        result = await ctx.deps.database_reader(record_id)
        ctx.deps.check_containment()
        ctx.deps.record("database.read", "completed")
        return result

    return capability


def execute_simulated_write(deps: Dependencies, approval_id: UUID, action: Action) -> WriteResult:
    """Trusted caller only: exact action rechecked immediately before one-time consumption."""
    deps.authorize(action)
    deps.approvals.consume(approval_id, deps.principal.subject, deps.run_id, action)
    deps.record("infra.write", "simulated")
    return WriteResult(
        status="simulated",
        approval_id=approval_id,
        action_digest=action_digest(deps.principal.subject, deps.run_id, action),
    )


CAPABILITY_FACTORIES = {
    "ticket-read": ticket_read,
    "delegate-tickets": delegate_tickets,
    "simulated-infrastructure": simulated_infrastructure,
    "database-read": database_read,
}
