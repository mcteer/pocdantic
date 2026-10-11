"""Independent synthetic ACL intersection exercises real Vault adapter response handling."""

import json

import httpx
import pytest
from pydantic import SecretStr
from security_regression_support import selected_policy

from agent.schemas import Action, Principal
from agent.security import SecurityError
from agent.vault import VaultClient


@pytest.mark.parametrize("pairing", ["high-human", "high-agent"])
@pytest.mark.parametrize("mutation", ["healthy", "path", "capability", "parameters"])
async def test_both_privilege_pairings(pairing, mutation):
    "An independent ACL∩ceiling∩RAR fixture denies every broadened request under either pairing."
    exact = ("database/creds/poc-readonly", "read", ())
    broadened = {
        "path": ("database/creds/admin", "read", ()),
        "capability": (exact[0], "update", ()),
        "parameters": (exact[0], "read", ("admin",)),
    }
    requested = exact if mutation == "healthy" else broadened[mutation]
    universe = {exact, *broadened.values()}
    human = universe if pairing == "high-human" else {exact}
    ceiling = {exact} if pairing == "high-human" else universe
    rar = universe
    allowed = requested in human.intersection(ceiling).intersection(rar)
    issued = []

    def provider(request):
        "Apply independently computed fixture authority, then return a genuine adapter response."
        actual = (
            request.url.path.removeprefix("/v1/"),
            "read" if request.method == "GET" else "update",
            tuple(sorted(json.loads(request.content or b"{}").keys())),
        )
        assert actual == requested
        if actual not in human.intersection(ceiling).intersection(rar):
            return httpx.Response(403, json={"errors": ["private fixture denial"]})
        issued.append(1)
        return httpx.Response(
            200,
            json={
                "lease_id": "database/creds/poc-readonly/fixture",
                "lease_duration": 60,
                "data": {"username": "fixture", "password": "private"},
            },
        )

    async def cleanup(_):
        """Accept exact synthetic lease cleanup without an external provider."""
        return None

    async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as http:
        vault = VaultClient("https://vault.example", "", http)
        if allowed:
            async with vault.credentials(
                SecretStr("fixture-token"), "database/creds/poc-readonly", revoke=cleanup
            ) as lease:
                assert lease.lease_duration == 60
        else:
            with pytest.raises(SecurityError):
                await vault.request(
                    "GET" if requested[1] == "read" else "PUT",
                    requested[0],
                    SecretStr("fixture-token"),
                    body={key: True for key in requested[2]} if requested[2] else None,
                )
    assert len(issued) == (1 if mutation == "healthy" else 0)
    user = Principal(issuer="fixture", subject="user", scopes=frozenset({"tickets:read"}))
    selected_policy().authorize(
        user, "ticket-reader", Action(operation="ticket.read", resource="POC-1")
    )
