"""Exercise invalid approvals at the actual trusted execution boundary."""

import pytest
from security_regression_support import dependencies

from agent.capabilities import execute_simulated_write
from agent.schemas import Action
from agent.security import SecurityError


@pytest.mark.parametrize(
    "state",
    ["denied", "pending", "timeout", "expired", "replayed", "operation", "resource", "parameters"],
)
def test_approval_states_prevent_privileged_effects(state):
    """Only one timely exact approval produces an effect; invalid variants produce none."""
    deps = dependencies()
    action = Action(
        operation="infra.write", resource="sandbox/demo", parameters={"change": "restart"}
    )
    item = deps.approvals.create(deps.principal.subject, deps.run_id, action)
    if state not in {"pending", "timeout"}:
        deps.approvals.record_decision(
            item.id,
            approved=state != "denied",
            approver=deps.principal.subject,
            source_event="fixture-event",
        )
    if state == "timeout":
        deps.approvals.invalidate(item.id, "unconfirmed")
    if state == "expired":
        item.expires_at = 0
    if state == "replayed":
        assert execute_simulated_write(deps, item.id, action).status == "simulated"
    if state == "operation":
        action = action.model_copy(update={"operation": "database.read"})
    if state == "resource":
        action = action.model_copy(update={"resource": "sandbox/other"})
    if state == "parameters":
        action = action.model_copy(update={"parameters": {"change": "destroy"}})
    before = sum(e["event"] == "infra.write" for e in deps.audit.events)
    with pytest.raises(SecurityError):
        execute_simulated_write(deps, item.id, action)
    assert sum(e["event"] == "infra.write" for e in deps.audit.events) == before
    # Simulated execution issues no native credentials; exact healthy control is independent.
    assert deps.database_reader is None
    valid = dependencies()
    exact = Action(
        operation="infra.write", resource="sandbox/demo", parameters={"change": "restart"}
    )
    approved = valid.approvals.create(valid.principal.subject, valid.run_id, exact)
    valid.approvals.record_decision(
        approved.id, approved=True, approver=valid.principal.subject, source_event="control"
    )
    assert execute_simulated_write(valid, approved.id, exact).status == "simulated"
    assert sum(e["event"] == "infra.write" for e in valid.audit.events) == 1
