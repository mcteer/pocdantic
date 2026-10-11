"""Vault SVID verification never accepts decoded claims or token-selected key locations."""

import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from governance_support import binding

from agent.governance.models import GovernanceError, now


@pytest.fixture
def issuer():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {
        "kid": "test",
        "use": "sig",
        "alg": "RS256",
        "key_ops": ["verify"],
    }
    t = int(now().timestamp())
    trust = binding().trust
    claims = {
        "iss": trust.issuer,
        "sub": trust.subject,
        "aud": trust.audience,
        "iat": t,
        "exp": t + 60,
        "vault": {"entity": {"id": trust.entity_id}},
    }
    return key, public, trust, claims


def test_exact_signed_svid_and_negative_claims(issuer):
    from agent.governance.verifier import verify

    key, public, trust, claims = issuer

    def token(c=claims, headers=None):
        return jwt.encode(c, key, algorithm="RS256", headers={"kid": "test"} | (headers or {}))

    assert verify(token(), trust, {"keys": [public]})["vault"]["entity"]["id"] == trust.entity_id
    for change in (
        {"sub": "spiffe://test.example/other"},
        {"vault": {"entity": {"id": "other"}}},
        {"aud": [trust.audience, "other"]},
        {"exp": claims["iat"] + 301},
        {"iat": True},
        {"nbf": True},
        {"iss": "https://other.example"},
    ):
        with pytest.raises(GovernanceError):
            verify(token(claims | change), trust, {"keys": [public]})
    for header in ({"jku": "https://attacker.example/keys"}, {"typ": "at+jwt"}, {"kid": "unknown"}):
        with pytest.raises(GovernanceError):
            verify(token(headers=header), trust, {"keys": [public]})


def test_ambiguous_private_and_weak_keys_fail(issuer):
    from agent.governance.verifier import verify

    key, public, trust, claims = issuer
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test"})
    for keys in (
        [public, public],
        [public | {"d": "private"}],
        [public | {"use": "enc"}],
        [public | {"key_ops": ["sign"]}],
        [],
        [public | {"alg": "RS512"}],
    ):
        with pytest.raises(GovernanceError):
            verify(token, trust, {"keys": keys})


def test_duplicate_signed_members_are_rejected(issuer):
    import base64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    from agent.governance.verifier import verify

    key, public, trust, claims = issuer

    def b64(raw):
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    h = b64(b'{"alg":"RS256","kid":"test","typ":"JWT"}')
    content = json.dumps(claims)[:-1] + ',"sub":' + json.dumps(trust.subject) + "}"
    p = b64(content.encode())
    signed = (h + "." + p).encode()
    signature = b64(key.sign(signed, padding.PKCS1v15(), hashes.SHA256()))
    with pytest.raises(GovernanceError):
        verify(h + "." + p + "." + signature, trust, {"keys": [public]})


def test_unknown_key_refresh_is_throttled_and_empty_refresh_denies(issuer):
    import asyncio

    import httpx

    from agent.governance.verifier import Verifier

    key, public, trust, claims = issuer
    fetched = 0
    clock = [0.0]
    empty = [False]

    def handler(req):
        nonlocal fetched
        if str(req.url) == trust.discovery_url:
            return httpx.Response(200, json={"issuer": trust.issuer, "jwks_uri": trust.jwks_url})
        fetched += 1
        return httpx.Response(200, json={"keys": [] if empty[0] else [public]})

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), trust_env=False
        ) as http:
            verifier = Verifier(trust, http, clock=lambda: clock[0])
            good = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test"})
            unknown = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "other"})
            await verifier.check(good)
            for _ in range(3):
                with pytest.raises(GovernanceError):
                    await verifier.check(unknown)
            assert fetched == 2
            empty[0] = True
            clock[0] = 61
            with pytest.raises(GovernanceError):
                await verifier.check(good)
            assert verifier.jwks == {"keys": []}

    asyncio.run(run())


@pytest.mark.parametrize(
    "algorithm,curve", [("ES256", "SECP256R1"), ("ES384", "SECP384R1"), ("ES512", "SECP521R1")]
)
def test_ec_curve_is_exactly_bound_to_algorithm(algorithm, curve):
    """Accept supported EC profiles and reject a key's mismatched algorithm declaration."""
    from cryptography.hazmat.primitives.asymmetric import ec

    from agent.governance.verifier import verify

    key = ec.generate_private_key(getattr(ec, curve)())
    trust = binding().trust.model_copy(update={"algorithm": algorithm})
    public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key())) | {
        "kid": "ec",
        "use": "sig",
        "alg": algorithm,
    }
    t = int(now().timestamp())
    claims = {
        "iss": trust.issuer,
        "sub": trust.subject,
        "aud": trust.audience,
        "iat": t,
        "exp": t + 60,
        "vault": {"entity": {"id": trust.entity_id}},
    }
    raw = jwt.encode(claims, key, algorithm=algorithm, headers={"kid": "ec"})
    verify(raw, trust, {"keys": [public]})
    with pytest.raises(GovernanceError):
        verify(raw, trust, {"keys": [public | {"alg": "RS256"}]})


def test_actual_weak_rsa_is_rejected(issuer):
    from agent.governance.verifier import verify

    _key, _public, trust, claims = issuer
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {
        "kid": "weak",
        "use": "sig",
    }
    with pytest.warns(Warning, match="1024 bits"):
        raw = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "weak"})
    with pytest.raises(GovernanceError, match="trust_unavailable"):
        verify(raw, trust, {"keys": [public]})


def test_concurrent_refresh_installs_one_snapshot_and_expired_failure_clears_it(issuer):
    """Parallel proofs cannot mix generations or reuse an expired failed key snapshot."""
    import asyncio

    import httpx

    from agent.governance.verifier import Verifier

    key, public, trust, claims = issuer
    count = 0
    clock = [0.0]
    failed = [False]

    async def transport(request):
        nonlocal count
        count += 1
        await asyncio.sleep(0)
        if failed[0]:
            return httpx.Response(503, json={})
        if str(request.url) == trust.discovery_url:
            return httpx.Response(200, json={"issuer": trust.issuer, "jwks_uri": trust.jwks_url})
        return httpx.Response(200, json={"keys": [public]})

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as http:
            verifier = Verifier(trust, http, clock=lambda: clock[0])
            raw = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test"})
            await asyncio.gather(*(verifier.check(raw) for _ in range(8)))
            assert count == 2
            clock[0], failed[0] = 61, True
            with pytest.raises(GovernanceError, match="trust_unavailable"):
                await verifier.check(raw)
            assert verifier.jwks is None

    asyncio.run(exercise())
