"""Fixed synthetic permissions and counters shared by regression assertions."""

import os
from dataclasses import dataclass

from agent.security import Policy

PROFILES = {
    "baseline": Policy(ticket_projects=frozenset({"POC", "ALT"})),
    "restricted": Policy(ticket_projects=frozenset({"POC"})),
}


def selected_policy():
    """Return the compiled policy selected by the isolated child, defaulting to baseline."""
    return PROFILES[os.environ.get("SECURITY_REGRESSION_PROFILE", "baseline")]


@dataclass
class Effects:
    """Count synthetic dispatch, issuance and completion without storing payloads."""

    attempted: int = 0
    issued: int = 0
    completed: int = 0
    forbidden: int = 0


def dependencies(principal=None):
    """Build trusted synthetic tool dependencies with no provider or model-owned authority."""
    from uuid import uuid4

    from agent.approval import ApprovalStore
    from agent.capabilities import Dependencies
    from agent.schemas import Principal
    from agent.security import Audit, Containment

    return Dependencies(
        principal=principal
        or Principal(
            issuer="https://fixture.example",
            subject="verified",
            scopes=frozenset({"tickets:read", "infra:write"}),
        ),
        request_id=uuid4(),
        run_id=uuid4(),
        logical_agent="parent",
        workload_definition="fixture",
        policy=selected_policy(),
        containment=Containment(),
        audit=Audit(),
        approvals=ApprovalStore(),
    )
