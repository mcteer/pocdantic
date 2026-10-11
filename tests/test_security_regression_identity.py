"""Signed authority mutation and repeated trusted-runtime identity drills."""

import hashlib
from uuid import uuid4

import jwt
import pytest
from pydantic import SecretStr
from security_regression_support import selected_policy
from test_broker import chain as chain
from test_identity import signed_identity as signed_identity
from test_identity import verifier_for

from agent.demo import model
from agent.runtime import Runtime
from agent.schemas import RequestEnvelope
from agent.security import SecurityError
from agent.settings import Settings


@pytest.mark.parametrize(
    "stage,change",
    [
        ("user_change", {"aud": "foreign"}),
        ("user_change", {"iss": "https://foreign.example"}),
        ("user_change", {"exp": 1}),
        ("user_change", {"grant_type": "client_credentials"}),
        ("actor_change", {"sub": "human"}),
        ("actor_change", {"exp": 1}),
        ("actor_change", {"aud": "foreign"}),
        ("actor_change", {"grant_type": "authorization_code"}),
        ("change", {"act": {"sub": "foreign"}}),
        ("change", {"authorization_details": [{"path": "*"}]}),
        ("change", {"exp": 1}),
        ("change", {"aud": "foreign"}),
    ],
)
async def test_signed_authority_mutations(chain, stage, change):
    "Actual signed broker chain rejects mutation before credential issuance; valid control works."
    state, factory = chain
    state[stage] = change
    with pytest.raises(SecurityError):
        await factory()(1)
    assert state["vault"] == []
    if stage != "change":
        assert state["exchanges"] == []
    state[stage] = {}
    assert await factory()(1) == [{"id": 1, "status": "healthy"}]
    assert [r.method for r in state["vault"]] == ["GET", "PUT"]


async def test_hundred_runs_keep_identity_and_reject_remapping(signed_identity, tmp_path):
    "Verify 100 fresh signed tokens and execute real runs; foreign subjects cannot reuse binding."
    key, jwk, claims = signed_identity
    verifier, http = await verifier_for(jwk)
    definition = uuid4()
    from response_support import enrolled

    settings = Settings(_env_file=None, oauth_issuer=claims["iss"])
    store = enrolled(settings, tmp_path)
    runtime = Runtime(
        settings, model=model(), definition_ref=lambda _: definition, response_store=store
    )
    runtime.policy = selected_policy()
    requests, roots, credentials = set(), set(), set()
    mapping = {(claims["iss"], claims["sub"]): definition}
    async with http:
        for _ in range(100):
            token = jwt.encode(
                claims | {"jti": str(uuid4())},
                key,
                algorithm="RS256",
                headers={"kid": "test-key", "typ": "at+jwt"},
            )
            principal = await verifier.verify(SecretStr(token))
            assert mapping[(principal.issuer, principal.subject)] == definition
            request = RequestEnvelope(task="Read POC-1")
            result = await runtime.run(request, principal)
            assert result.status == "completed"
            requests.add(result.request_id)
            roots.add(result.run_id)
            credentials.add(hashlib.sha256(token.encode()).hexdigest())
        # A verified foreign principal still cannot replace the existing trusted binding.
        from agent.response.models import ResponseError

        binding, owner = store.register(uuid4(), uuid4(), principal)
        store.bind_actor(binding, principal.issuer, "approved-workload")
        foreign = await verifier.verify(
            SecretStr(
                jwt.encode(
                    claims | {"sub": "second-workload", "jti": str(uuid4())},
                    key,
                    algorithm="RS256",
                    headers={"kid": "test-key", "typ": "at+jwt"},
                )
            )
        )
        forged = binding.model_copy(update={"subject": foreign.subject})
        with pytest.raises(ResponseError):
            store.check(forged)
        with pytest.raises(ResponseError, match="mapping_missing"):
            store.bind_actor(binding, foreign.issuer, foreign.subject)
        assert (foreign.issuer, foreign.subject) not in mapping
        store.finish(binding)
        import os

        os.close(owner)
    assert len(requests) == len(roots) == len(credentials) == 100
    assert len(mapping) == 1
