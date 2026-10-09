from uuid import uuid4

import pytest
from pydantic import ValidationError

from pocdantic.approval import ApprovalStore
from pocdantic.schemas import Action, Principal
from pocdantic.security import Containment, Policy, SecurityError


def principal():
    return Principal(
        issuer="https://issuer.example",
        subject="user",
        scopes=frozenset({"tickets:read", "infra:write"}),
    )


def test_child_cannot_write_even_with_privileged_user():
    with pytest.raises(SecurityError):
        Policy().authorize(
            principal(), "ticket-reader", Action(operation="infra.write", resource="sandbox/demo")
        )


def test_denies_unknown_resources():
    with pytest.raises(SecurityError):
        Policy().authorize(
            principal(), "ticket-reader", Action(operation="ticket.read", resource="OTHER-1")
        )


def test_principal_is_immutable():
    p = principal()
    with pytest.raises(ValidationError):
        p.subject = "forged"


def test_containment_scopes():
    state = Containment()
    one, two = uuid4(), uuid4()
    state.block_run(one)
    with pytest.raises(SecurityError):
        state.check("parent", one)
    state.check("parent", two)
    state.block_definition("parent")
    with pytest.raises(SecurityError):
        state.check("parent", two)


def test_approval_mutation_replay_expiry_and_wrong_user():
    store = ApprovalStore()
    run = uuid4()
    action = Action(
        operation="infra.write", resource="sandbox/demo", parameters={"change": "restart"}
    )
    approval = store.create("user", run, action, ttl=30)
    with pytest.raises(SecurityError):
        store.consume(approval.id, "user", run, action)
    store.record_decision(approval.id, approved=True, approver="user", source_event="trusted-event")
    for user, target in [
        ("other", action),
        ("user", action.model_copy(update={"resource": "sandbox/other"})),
    ]:
        with pytest.raises(SecurityError):
            store.consume(approval.id, user, run, target)
    store.consume(approval.id, "user", run, action)
    with pytest.raises(SecurityError):
        store.consume(approval.id, "user", run, action)
    expired = store.create("user", run, action, ttl=-1)
    store.record_decision(expired.id, approved=True, approver="user", source_event="trusted-event")
    with pytest.raises(SecurityError):
        store.consume(expired.id, "user", run, action)


def test_request_cannot_supply_authority():
    from pocdantic.schemas import RequestEnvelope

    with pytest.raises(ValidationError):
        RequestEnvelope.model_validate(
            {"task": "read", "user_id": "admin", "scopes": ["infra:write"]}
        )


def test_approval_consumption_is_atomic():
    from concurrent.futures import ThreadPoolExecutor

    store = ApprovalStore()
    run = uuid4()
    action = Action(
        operation="infra.write", resource="sandbox/demo", parameters={"change": "restart"}
    )
    approval = store.create("user", run, action)
    store.record_decision(approval.id, approved=True, approver="user", source_event="event")

    def consume(_):
        try:
            store.consume(approval.id, "user", run, action)
            return True
        except SecurityError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(consume, range(8)))
    assert outcomes.count(True) == 1


def test_expired_identity_cannot_execute_tools():
    p = principal().model_copy(update={"expires_at": 1})
    with pytest.raises(SecurityError, match="identity_expired"):
        Policy().authorize(p, "ticket-reader", Action(operation="ticket.read", resource="POC-1"))
