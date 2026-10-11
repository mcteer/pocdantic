"""Native identity operations use the candidate, preserve uncertainty and discard tokens."""

import asyncio

import httpx
import pytest
from governance_support import binding, installed, source

from agent.governance.models import GovernanceError, now


def test_unregistered_case_never_bootstraps_or_mints(tmp_path):
    from agent.governance.identity import prove

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture")
    with pytest.raises(GovernanceError, match="review_stale"):
        asyncio.run(prove(s, c, binding(), None, None, "vault", None, None, lambda: None))
    assert not s.read().credentials


def test_unacknowledged_mint_is_not_a_relying_proof(tmp_path, monkeypatch):
    from pydantic import SecretStr

    from agent.governance import identity

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture").model_copy(
        update={
            "binding": binding(),
            "state": "registered",
            "registration_digest": "0" * 64,
            "registered_at": now(),
            "registration_id": "registered",
        }
    )
    s.change(lambda j: j.model_copy(update={"candidates": (c,)}))

    async def bootstrap(*_args):
        return SecretStr("synthetic-candidate")

    monkeypatch.setattr(identity, "acquire", bootstrap)

    def handler(request):
        assert request.headers["X-Vault-Token"] == "synthetic-candidate"
        raise httpx.ReadTimeout("synthetic upstream")

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ) as http:
            with pytest.raises(GovernanceError):
                await identity.prove(s, c, c.binding, None, None, "vault", http, None, lambda: None)

    asyncio.run(run())
    assert s.read().credentials[-1].state == "uncertain"
    assert not s.read().verifications


def test_native_token_field_is_delivered_privately_and_verified(tmp_path, monkeypatch):
    """Mint success needs independently fetched public keys and a retained matching proof."""
    import json
    from contextlib import asynccontextmanager

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from pydantic import SecretStr

    from agent.governance import identity
    from agent.governance.models import now
    from agent.governance.relying import create_app
    from agent.governance.verifier import Verifier

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture").model_copy(
        update={
            "binding": binding(),
            "state": "registered",
            "registration_digest": "0" * 64,
            "registered_at": now(),
            "registration_id": "registered",
        }
    )
    s.change(lambda j: j.model_copy(update={"candidates": (c,)}))
    trust = c.binding.trust
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {
        "kid": "native-fixture",
        "use": "sig",
        "alg": "RS256",
    }
    t = int(now().timestamp())
    token = jwt.encode(
        {
            "iss": trust.issuer,
            "sub": trust.subject,
            "aud": [trust.audience],
            "iat": t,
            "exp": t + 60,
            "vault": {"entity": {"id": trust.entity_id}},
        },
        key,
        algorithm="RS256",
        headers={"kid": "native-fixture"},
    )

    async def bootstrap(*_args):
        return SecretStr("synthetic-candidate")

    monkeypatch.setattr(identity, "acquire", bootstrap)
    fetched = []

    def public_handler(request):
        fetched.append(str(request.url))
        if str(request.url) == trust.discovery_url:
            return httpx.Response(200, json={"issuer": trust.issuer, "jwks_uri": trust.jwks_url})
        return httpx.Response(200, json={"keys": [public]})

    @asynccontextmanager
    async def verifier_factory(profile):
        async with httpx.AsyncClient(transport=httpx.MockTransport(public_handler)) as http:
            yield Verifier(profile, http)

    app = create_app(s, lambda: None, verifier_factory)

    async def run():
        async with (
            httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda req: httpx.Response(200, json={"data": {"token": token}})
                )
            ) as http,
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as relying,
        ):
            result = await identity.prove(
                s, c, c.binding, None, None, "vault", http, relying, lambda: None
            )
            assert result["result"] == "pass"
            assert token not in str(result)

    asyncio.run(run())
    assert fetched == [trust.discovery_url, trust.jwks_url]
    assert s.read().credentials[-1].state == "confirmed"
    assert len(s.read().verifications) == 1
    assert token not in (s.root / "state.json").read_text()


def test_mint_success_without_independent_relying_result_remains_uncertain(tmp_path, monkeypatch):
    """A native-looking issuance response cannot stand in for a proof."""
    from pydantic import SecretStr

    from agent.governance import identity

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture").model_copy(
        update={
            "binding": binding(),
            "state": "registered",
            "registration_id": "fixture",
            "registration_digest": "0" * 64,
            "registered_at": now(),
        }
    )
    s.change(lambda j: j.model_copy(update={"candidates": (c,)}))

    async def bootstrap(*_args):
        return SecretStr("candidate")

    monkeypatch.setattr(identity, "acquire", bootstrap)

    async def exercise():
        async with (
            httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda _: httpx.Response(
                        200, json={"data": {"token": "unverified-token-canary"}}
                    )
                )
            ) as issuer,
            httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda _: httpx.Response(503, json={"schema_version": 1})
                )
            ) as relying,
        ):
            with pytest.raises(GovernanceError, match="issuance_unresolved"):
                await identity.prove(
                    s, c, c.binding, None, None, "vault", issuer, relying, lambda: None
                )

    asyncio.run(exercise())
    assert not s.read().verifications
    assert s.read().credentials[-1].safe_after is None
    assert "unverified-token-canary" not in (s.root / "state.json").read_text()
