import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr

from pocdantic.oauth import JWTVerifier, OAuthClient, OAuthConfig
from pocdantic.security import SecurityError


@pytest.fixture
def signed_identity():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk["kid"] = "test-key"
    claims = {
        "iss": "https://issuer.example",
        "sub": "verified-user",
        "aud": "poc-api",
        "iat": int(time.time()),
        "exp": int(time.time()) + 60,
        "scope": "tickets:read",
    }
    return private, jwk, claims


async def verifier_for(jwk):
    def handler(request):
        if request.url.path.endswith("discovery"):
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example",
                    "token_endpoint": "https://issuer.example/token",
                    "jwks_uri": "https://issuer.example/jwks",
                },
            )
        return httpx.Response(200, json={"keys": [jwk]})

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    oauth = OAuthClient(
        OAuthConfig(
            discovery_url="https://issuer.example/discovery",
            issuer="https://issuer.example",
            client_id="client",
            client_secret=SecretStr("private"),
        ),
        http,
    )
    return JWTVerifier(oauth, "poc-api"), http


async def test_signed_identity_and_scopes(signed_identity):
    key, jwk, claims = signed_identity
    verifier, http = await verifier_for(jwk)
    async with http:
        principal = await verifier.verify(
            SecretStr(
                jwt.encode(
                    claims, key, algorithm="RS256", headers={"kid": "test-key", "typ": "at+jwt"}
                )
            )
        )
    assert principal.subject == "verified-user" and principal.scopes == frozenset({"tickets:read"})


@pytest.mark.parametrize(
    "change", [{"aud": "other"}, {"exp": 1}, {"nbf": 9999999999}, {"iss": "https://evil.example"}]
)
async def test_wrong_identity_claims_rejected(signed_identity, change):
    key, jwk, claims = signed_identity
    verifier, http = await verifier_for(jwk)
    async with http:
        with pytest.raises(SecurityError):
            await verifier.verify(
                SecretStr(
                    jwt.encode(
                        claims | change,
                        key,
                        algorithm="RS256",
                        headers={"kid": "test-key", "typ": "at+jwt"},
                    )
                )
            )


async def test_id_token_not_accepted_as_access_token(signed_identity):
    key, jwk, claims = signed_identity
    verifier, http = await verifier_for(jwk)
    async with http:
        with pytest.raises(SecurityError, match="token_type"):
            await verifier.verify(
                SecretStr(
                    jwt.encode(
                        claims, key, algorithm="RS256", headers={"kid": "test-key", "typ": "JWT"}
                    )
                )
            )


async def test_forged_signature_rejected(signed_identity):
    _, jwk, claims = signed_identity
    forged = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier, http = await verifier_for(jwk)
    async with http:
        with pytest.raises(SecurityError):
            await verifier.verify(
                SecretStr(
                    jwt.encode(
                        claims,
                        forged,
                        algorithm="RS256",
                        headers={"kid": "test-key", "typ": "at+jwt"},
                    )
                )
            )


async def test_discovery_cannot_redirect_credentials_to_other_host():
    cfg = OAuthConfig(
        discovery_url="https://issuer.example/discovery",
        client_id="client",
        client_secret=SecretStr("private"),
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example",
                    "jwks_uri": "https://issuer.example/jwks",
                    "token_endpoint": "https://evil.example/token",
                },
            )
        )
    ) as http:
        with pytest.raises(SecurityError, match="untrusted_endpoint"):
            await OAuthClient(cfg, http).client_credentials()
