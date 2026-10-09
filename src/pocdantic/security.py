import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from .schemas import Action, Principal


class SecurityError(Exception):
    """A safe, stable error code; never include upstream response text."""


@dataclass
class Containment:
    """Process-local controls. External tokens/leases require separate remediation."""

    blocked_runs: set[UUID] = field(default_factory=set)
    blocked_definitions: set[str] = field(default_factory=set)

    def check(self, definition: str, run_id: UUID) -> None:
        if run_id in self.blocked_runs or definition in self.blocked_definitions:
            raise SecurityError("contained")

    def block_run(self, run_id: UUID) -> None:
        self.blocked_runs.add(run_id)

    def block_definition(self, definition: str) -> None:
        self.blocked_definitions.add(definition)


@dataclass(frozen=True)
class Policy:
    ticket_projects: frozenset[str] = frozenset({"POC"})
    write_resources: frozenset[str] = frozenset({"sandbox/demo"})
    database_resources: frozenset[str] = frozenset({"poc-records"})

    def authorize(self, principal: Principal, agent: str, action: Action) -> None:
        if principal.expires_at is not None and principal.expires_at <= time.time():
            raise SecurityError("identity_expired")
        allowed = False
        if action.operation == "ticket.read":
            project = action.resource.split("-", 1)[0]
            allowed = (
                agent in {"parent", "ticket-reader"}
                and "tickets:read" in principal.scopes
                and project in self.ticket_projects
                and re.fullmatch(r"[A-Z][A-Z0-9]{1,15}-[1-9][0-9]{0,8}", action.resource)
            )
        elif action.operation == "infra.write":
            allowed = (
                agent == "parent"
                and "infra:write" in principal.scopes
                and action.resource in self.write_resources
                and action.parameters == {"change": "restart"}
            )
        elif action.operation == "database.read":
            allowed = (
                agent == "parent"
                and "database:read" in principal.scopes
                and action.resource in self.database_resources
            )
        if not allowed:
            raise SecurityError("policy_denied")


@dataclass
class Audit:
    """Metadata-only audit. Private payloads and upstream error text have no field here."""

    events: list[dict] = field(default_factory=list)

    def record(
        self,
        event: str,
        *,
        request_id: UUID,
        run_id: UUID,
        agent_id: str,
        outcome: str,
        parent_run_id: UUID | None = None,
        principal_ref: str | None = None,
        workload_definition: str | None = None,
    ) -> None:
        self.events.append(
            {
                "event": event,
                "timestamp": datetime.now(UTC).isoformat(),
                "request_id": str(request_id),
                "run_id": str(run_id),
                "agent_id": agent_id,
                "principal_ref": principal_ref,
                "workload_definition": workload_definition,
                "outcome": outcome,
                "parent_run_id": str(parent_run_id) if parent_run_id else None,
            }
        )
        del self.events[:-1000]
