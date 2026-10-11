"""Exact registry creation forbids updates, implicit defaults and unauthorized absence."""

import asyncio

import httpx
import pytest
from governance_support import binding

from agent.governance.models import GovernanceError


def test_payload_is_create_only():
    from agent.governance.registry import payload

    value = payload(binding())
    assert "id" not in value
    assert value["no_default_ceiling_policy"] is True
    assert value["optional_authorization_details"] is False
    assert "root" not in value["ceiling_policies"]


def test_unauthorized_is_not_absent():
    from agent.governance.registry import Registry

    async def check():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(403, json={"errors": ["private"]})
            )
        ) as http:
            with pytest.raises(GovernanceError, match="provider_denied"):
                await Registry(http, "secret").absence(binding())

    asyncio.run(check())


def test_foreign_readback_is_conflict():
    from agent.governance.registry import Registry

    async def check():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200, json={"data": {"id": "foreign", "entity_id": "other"}}
                )
            )
        ) as http:
            with pytest.raises(GovernanceError, match="registry_conflict"):
                await Registry(http, "secret").create(binding())

    asyncio.run(check())


def test_minimal_create_ack_is_persisted_before_exact_readback():
    """Documented POST response lacks full fields; all three GETs must still match."""
    import json

    from agent.governance.registry import Registry, payload

    b = binding()
    events = []

    def transport(request):
        """A fixed fake endpoint admits no update/delete and verifies the exact body."""
        events.append(request.method)
        if request.method == "POST":
            assert json.loads(request.content) == payload(b)
            return httpx.Response(
                200, json={"data": {"id": "fixture", "display_name": b.registry_name}}
            )
        assert events.count("ACK") == 1
        return httpx.Response(200, json={"data": payload(b) | {"id": "fixture"}})

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as http:
            adapter = Registry(http, "private-fixture")
            adapter.acknowledge = lambda *_: events.append("ACK")
            result = await adapter.create(b)
            assert result["registration_id"] == "fixture"

    asyncio.run(exercise())
    assert events == ["POST", "ACK", "GET", "GET", "GET"]


def test_matching_foreign_presence_does_not_establish_creation_ownership():
    from agent.governance.registry import Registry, payload

    b = binding()

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"data": payload(b) | {"id": "foreign"}})
            )
        ) as http:
            result = await Registry(http, "fixture").reconcile(b)
            assert result["present"] is True
            assert result["owned"] is False

    asyncio.run(exercise())
