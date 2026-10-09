import asyncio
import json
import time
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr

from pocdantic.broker import DatabaseBroker
from pocdantic.security import SecurityError
from pocdantic.settings import Settings


@pytest.fixture
def chain(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {"kid": "test"}
    state = {"exchanges": [], "vault": [], "change": {}, "user_change": {}, "actor_change": {}}

    def sign(claims):
        base = {
            "iss": "https://issuer.example",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        }
        return jwt.encode(
            base | claims, key, algorithm="RS256", headers={"kid": "test", "typ": "at+jwt"}
        )

    def handler(request):
        if request.url.path == "/discovery":
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example",
                    "token_endpoint": "https://issuer.example/token",
                    "jwks_uri": "https://issuer.example/jwks",
                },
            )
        if request.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [jwk]})
        if request.url.path == "/token":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            if form["grant_type"] == "client_credentials":
                claims = {
                    "sub": "agent",
                    "aud": "agent-client",
                    "client_id": "agent-client",
                    "grant_type": "client_credentials",
                } | state["actor_change"]
            else:
                details = json.loads(form["authorization_details"])
                state["exchanges"].append(details)
                claims = {
                    "sub": "human",
                    "aud": "vault",
                    "act": {"sub": "agent", "iss": "https://issuer.example"},
                    "authorization_details": details,
                } | state["change"]
                if details[0]["path"] == "sys/leases/revoke":
                    claims |= state.get("cleanup_change", {})
            return httpx.Response(200, json={"access_token": sign(claims), "token_type": "Bearer"})
        state["vault"].append(request)
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "lease_id": "database/creds/poc-readonly/exact",
                    "lease_duration": 120,
                    "data": {"username": "leased", "password": "private"},
                },
            )
        return httpx.Response(state.get("revoke_status", 204))

    original = httpx.AsyncClient
    monkeypatch.setattr(
        "pocdantic.broker.httpx.AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )

    async def read(lease, **kwargs):
        assert kwargs["record_id"] == 1
        assert lease.username.get_secret_value() == "leased"
        if state.get("failure"):
            raise SecurityError("database_request_failed")
        if state.get("cancel"):
            raise asyncio.CancelledError
        return [{"id": 1, "status": "healthy"}]

    monkeypatch.setattr("pocdantic.broker.read_postgres", read)
    settings = Settings(
        _env_file=None,
        oauth_provider="generic",
        oauth_discovery_url="https://issuer.example/discovery",
        oauth_issuer="https://issuer.example",
        oauth_client_id="agent-client",
        oauth_client_secret=SecretStr("private"),
        oauth_audience="api",
        vault_addr="https://vault.example",
        vault_audience="vault",
        database_host="db.example",
        database_name="postgres",
    )

    def broker():
        token = sign(
            {"sub": "human", "aud": "api", "scope": "database:read"} | state["user_change"]
        )
        return DatabaseBroker(settings, SecretStr(token), "human")

    return state, broker


async def test_signed_chain_uses_distinct_exact_cleanup_grant(chain):
    state, broker = chain
    assert await broker()(1) == [{"id": 1, "status": "healthy"}]
    assert len(state["exchanges"]) == 2
    cleanup = state["exchanges"][1][0]
    assert cleanup == {
        "type": "vault:path_access",
        "path": "sys/leases/revoke",
        "capabilities": ["update"],
        "required_parameters": ["lease_id"],
        "allowed_parameters": {"lease_id": ["database/creds/poc-readonly/exact"]},
    }
    read, revoke = state["vault"]
    assert read.headers["X-Vault-Token"] != revoke.headers["X-Vault-Token"]
    assert json.loads(revoke.content) == {"lease_id": "database/creds/poc-readonly/exact"}


@pytest.mark.parametrize(
    "change",
    [
        {"sub": "other"},
        {"act": {"sub": "other"}},
        {"act": {"sub": "agent", "iss": "https://evil.example"}},
        {"act": {"sub": "agent", "act": {"sub": "nested"}}},
        {"authorization_details": [{"path": "*", "capabilities": ["read", "update"]}]},
    ],
)
async def test_expanded_or_wrong_delegation_never_reaches_vault(chain, change):
    state, broker = chain
    state["change"] = change
    with pytest.raises(SecurityError, match="delegation_claims_invalid"):
        await broker()(1)
    assert not state["vault"]


@pytest.mark.parametrize(
    "change",
    [
        {"scope": "tickets:read"},
        {"sub": "other"},
        {"grant_type": "client_credentials"},
        {"aud": "other"},
    ],
)
async def test_invalid_user_rejected_before_exchange(chain, change):
    state, broker = chain
    state["user_change"] = change
    with pytest.raises(SecurityError):
        await broker()(1)
    assert not state["exchanges"] and not state["vault"]


@pytest.mark.parametrize("change", [{"sub": "human"}, {"client_id": "other"}, {"aud": "other"}])
async def test_invalid_actor_rejected_before_exchange(chain, change):
    state, broker = chain
    state["actor_change"] = change
    with pytest.raises(SecurityError):
        await broker()(1)
    assert not state["exchanges"] and not state["vault"]


@pytest.mark.parametrize("failure", ["failure", "cancel"])
async def test_failure_and_cancellation_revoke_lease(chain, failure):
    state, broker = chain
    state[failure] = True
    with pytest.raises(asyncio.CancelledError if failure == "cancel" else SecurityError):
        await broker()(1)
    assert len(state["exchanges"]) == 2
    assert state["vault"][-1].method == "PUT"


@pytest.mark.parametrize("failure", ["claims", "vault"])
async def test_cleanup_authorization_failure_cannot_report_success(chain, failure):
    state, broker = chain
    if failure == "claims":
        state["cleanup_change"] = {"authorization_details": []}
    else:
        state["revoke_status"] = 403
    with pytest.raises(SecurityError):
        await broker()(1)
    assert len(state["exchanges"]) == 2
