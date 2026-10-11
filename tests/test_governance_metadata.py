"""Readiness verifies exact supported metadata, independent entitlement and KV-v2."""

import asyncio
from datetime import timedelta

import httpx
import pytest
from governance_support import binding

from agent.governance.config import binding_digest, readiness
from agent.governance.models import now
from agent.governance.registry import Registry


@pytest.mark.parametrize(
    "drift",
    [None, "audience", "mount", "policy", "entitlement", "role", "user-claim", "actor-claim"],
)
def test_metadata_readiness_blocks_any_pinned_prerequisite_drift(drift):
    """No credential or registry mutation is attempted during prerequisite checks."""
    b = binding()
    role, config, policy = (
        {"ttl": "300"},
        {"trust_domain": "test.example"},
        {"policy": "fixture-policy"},
    )
    receipt = {
        "schema_version": 1,
        "origin": b.vault_origin,
        "namespace": b.namespace,
        "version": "2.1.0+ent",
        "registry": True,
        "spiffe": True,
        "artifact_digest": "0" * 64,
        "reviewed_by": "fixture",
        "reviewed_at": now(),
        "expires_at": now() + timedelta(seconds=300),
    }
    receipt["digest"] = binding_digest(receipt)
    b = b.model_copy(
        update={
            "entitlement_digest": receipt["digest"],
            "policies": {p: binding_digest(policy) for p in b.policies},
            "trust": b.trust.model_copy(
                update={
                    "role_digest": binding_digest(role),
                    "config_digest": binding_digest(config),
                }
            ),
        }
    )
    calls = []

    def transport(request):
        calls.append((request.method, request.url.path))
        assert "mintjwt" not in request.url.path and "register" != request.url.path.split("/")[-1]
        target = request.url.path
        if target.endswith("sys/health"):
            data = {"version": "2.1.0+ent", "sealed": False}
        elif "identity/entity/id/" in target:
            data = {
                "id": b.entity_id,
                "disabled": False,
                "aliases": [
                    {"id": b.alias_id, "issuer": b.actor_issuer, "external_id": b.actor_subject}
                ],
            }
        elif "oauth-resource-server/" in target:
            data = {
                "enabled": True,
                "user_claim": "email" if drift == "user-claim" else "sub",
                "actor_claim": "actor.sub" if drift == "actor-claim" else "act.sub",
                "issuer_id": b.actor_issuer,
                "audiences": ["wrong" if drift == "audience" else "vault"],
            }
        elif target.endswith("spiffe/config"):
            data = config
        elif "spiffe/role/" in target:
            data = {"ttl": "301"} if drift == "role" else role
        elif "sys/mounts/" in target:
            data = {"type": "kv", "options": {"version": "1" if drift == "mount" else "2"}}
        elif "sys/policies/acl/" in target:
            data = {"policy": "changed"} if drift == "policy" else policy
        elif "agent-registry/registration/" in target:
            return httpx.Response(404, json={"errors": []})
        elif "sys/capabilities-self" in target:
            data = {"capabilities": ["update"]}
        else:
            pytest.fail("unexpected metadata target")
        return httpx.Response(200, json={"data": data})

    if drift == "entitlement":
        receipt["registry"] = False

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as http:
            return await readiness(
                b, Registry(http, "private-fixture", audience="vault", entitlement=receipt)
            )

    result = asyncio.run(exercise())
    assert result.ready is (drift is None)
    assert all(
        method == "GET" or target.endswith("sys/capabilities-self") for method, target in calls
    )
