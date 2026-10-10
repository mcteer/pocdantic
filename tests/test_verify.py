import json
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr

from agent.approval import ApprovalStore
from agent.schemas import Action
from agent.security import SecurityError
from agent.verify import VerifyClient


def action():
    return Action(
        operation="infra.write", resource="sandbox/demo", parameters={"change": "restart"}
    )


@pytest.mark.parametrize("as_string", [True, False])
async def test_exact_bound_push_result_consumed_once(as_string):
    store = ApprovalStore()
    run_id = uuid4()
    approval = store.create("user", run_id, action())
    binding = {
        "additionalData": [
            {"name": "approval_id", "value": str(approval.id)},
            {"name": "action_digest", "value": approval.digest},
        ]
    }
    payload = {
        "id": "transaction",
        "state": "SUCCESS",
        "transactionData": json.dumps(binding) if as_string else binding,
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
    ) as http:
        client = VerifyClient("https://verify.example", SecretStr("private-token"), http)
        assert await client.wait_for_decision("device", "transaction", approval, store)
    store.consume(approval.id, "user", run_id, action())
    with pytest.raises(SecurityError):
        store.consume(approval.id, "user", run_id, action())


@pytest.mark.parametrize(
    "mutation", [{"id": "other-transaction"}, {"transactionData": {}}, {"state": "UNKNOWN"}]
)
async def test_mismatched_push_result_denied(mutation):
    store = ApprovalStore()
    approval = store.create("user", uuid4(), action())
    payload = {
        "id": "transaction",
        "state": "SUCCESS",
        "transactionData": {
            "additionalData": [
                {"name": "approval_id", "value": str(approval.id)},
                {"name": "action_digest", "value": approval.digest},
            ]
        },
    } | mutation
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
    ) as http:
        client = VerifyClient("https://verify.example", SecretStr("private-token"), http)
        with pytest.raises(SecurityError):
            await client.wait_for_decision("device", "transaction", approval, store)
    assert approval.state == "pending"


@pytest.mark.parametrize("state", ["DENIED", "VERIFY_DENIED", "USER_DENIED"])
async def test_denied_push_never_becomes_approved(state):
    store = ApprovalStore()
    approval = store.create("user", uuid4(), action())
    payload = {
        "id": "transaction",
        "state": state,
        "transactionData": {
            "additionalData": [
                {"name": "approval_id", "value": str(approval.id)},
                {"name": "action_digest", "value": approval.digest},
            ]
        },
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
    ) as http:
        assert not await VerifyClient(
            "https://verify.example", SecretStr("private-token"), http
        ).wait_for_decision("device", "transaction", approval, store)
    assert approval.state == "denied"


async def test_failed_pre_request_binding_prohibits_push():
    from types import SimpleNamespace

    calls = []
    observer = SimpleNamespace(validation_id=uuid4(), observation_id=uuid4(), failed=False)

    def begin(**kwargs):
        assert kwargs["approval_ref"] == approval.id
        assert kwargs["action_digest"] == approval.digest
        observer.failed = True
        return None

    observer.begin_operation = begin
    approval = ApprovalStore().create("user", uuid4(), action())
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r))) as http:
        client = VerifyClient(
            "https://verify.example", SecretStr("private-token"), http, operation_observer=observer
        )
        with pytest.raises(SecurityError, match="storage_error"):
            await client.initiate("device", "factor", approval, action())
    assert calls == []


async def test_capture_failure_leaves_approval_pending():
    from types import SimpleNamespace

    store = ApprovalStore()
    approval = store.create("user", uuid4(), action())
    payload = {
        "id": "transaction",
        "state": "SUCCESS",
        "transactionData": {
            "additionalData": [
                {"name": "approval_id", "value": str(approval.id)},
                {"name": "action_digest", "value": approval.digest},
            ]
        },
    }
    observer = SimpleNamespace(validation_id=uuid4(), observation_id=uuid4(), failed=False)
    observer.begin_operation = lambda **kwargs: object()
    observer.finish_operation = lambda *args, **kwargs: None

    def capture(*args):
        raise OSError("private storage error")

    observer.sink = SimpleNamespace(transaction=capture)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
    ) as http:
        client = VerifyClient(
            "https://verify.example", SecretStr("private-token"), http, operation_observer=observer
        )
        with pytest.raises(SecurityError, match="storage_error"):
            await client.wait_for_decision("device", "transaction", approval, store)
    assert approval.state == "pending"
