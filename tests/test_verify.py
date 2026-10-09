import json
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr

from pocdantic.approval import ApprovalStore
from pocdantic.schemas import Action
from pocdantic.security import SecurityError
from pocdantic.verify import VerifyClient


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


async def test_denied_push_never_becomes_approved():
    store = ApprovalStore()
    approval = store.create("user", uuid4(), action())
    payload = {
        "id": "transaction",
        "state": "DENIED",
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
