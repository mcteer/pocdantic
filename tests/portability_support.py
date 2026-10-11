"""Independent synthetic provider contracts; no ambient credentials or live networking."""

import json
import time
from uuid import uuid4

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr

from agent.broker import DatabaseBroker
from agent.recovery.store import RecoveryStore
from agent.response.guard import MemoryStore, RootGuard
from agent.schemas import Principal
from agent.settings import Settings


def deployment(tmp_path, provider="generic"):
    """Build real signature verification with controlled HTTP and isolated durable storage."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {"kid": "fixture"}
    issuer = f"https://{provider}.example" + (
        "/v1.0/endpoint/default" if provider == "verify" else ""
    )
    discovery_path = "/.well-known/openid-configuration" if provider == "verify" else "/discovery"
    namespace = "department" if provider == "verify" else "team"
    mount = "department-db" if provider == "verify" else "team-db"
    role = "colleague" if provider == "verify" else "reader"
    credential_path = f"{mount}/creds/{role}"
    settings = Settings(
        _env_file=None,
        database_auth_mode="user-jwt",
        oauth_provider=provider,
        oauth_discovery_url=issuer + discovery_path,
        oauth_issuer=issuer,
        oauth_audience="records",
        vault_addr="https://vault.example",
        vault_namespace=namespace,
        vault_jwt_auth_role="human",
        vault_database_mount=mount,
        vault_database_role=role,
        database_host="db.example",
        database_name="records",
    )
    store = RecoveryStore(settings, project=tmp_path)
    store.initialize()
    from tests.response_support import enrolled

    enrolled(settings, tmp_path, recovery=store)
    state = {
        "calls": [],
        "login": {},
        "lookup": {},
        "lease_status": 200,
        "revoke_status": 204,
        "token_status": 204,
    }

    def sign(changes=None):
        """Sign bounded user claims; changes simulate an independently rejected identity."""
        now = int(time.time())
        claims = {
            "iss": issuer,
            "sub": "colleague",
            "aud": "records",
            "iat": now,
            "exp": now + 300,
            "scope": "database:read",
        } | (changes or {})
        return SecretStr(
            jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture", "typ": "at+jwt"})
        )

    def handler(request):
        """Serve the selected product contract and record effects without provider mutations."""
        state["calls"].append((request.method, request.url.path))
        path = request.url.path
        if str(request.url) == issuer + discovery_path:
            return httpx.Response(
                200,
                json={
                    "issuer": issuer,
                    "token_endpoint": issuer + "/token",
                    "jwks_uri": issuer + "/jwks",
                },
            )
        if str(request.url) == issuer + "/jwks":
            return httpx.Response(200, json={"keys": [jwk]})
        assert request.headers.get("X-Vault-Namespace") == namespace
        if path == "/v1/auth/jwt/login":
            return httpx.Response(
                200,
                json={
                    "request_id": "login-fixture",
                    "auth": {
                        "client_token": "synthetic-native-token",
                        "accessor": "synthetic-accessor",
                        "renewable": True,
                    }
                    | state["login"],
                },
            )
        if path == "/v1/auth/token/lookup-self":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "type": "service",
                        "ttl": 240,
                        "explicit_max_ttl": 240,
                        "policies": ["poc-read"],
                        "renewable": True,
                    }
                    | state["lookup"]
                },
            )
        if path == "/v1/" + credential_path:
            return httpx.Response(
                state["lease_status"],
                json={
                    "lease_id": credential_path + "/fixture",
                    "lease_duration": 120,
                    "data": {"username": "synthetic-user", "password": "synthetic-password"},
                },
            )
        if path == "/v1/sys/leases/revoke":
            assert json.loads(request.content) == {
                "lease_id": credential_path + "/fixture",
                "sync": True,
            }
            return httpx.Response(state["revoke_status"])
        if path == "/v1/auth/token/revoke-self":
            return httpx.Response(state["token_status"])
        raise AssertionError("Unexpected endpoint")

    control = MemoryStore(settings)
    binding, _ = control.register(uuid4(), uuid4(), Principal(issuer=issuer, subject="colleague"))
    guard = RootGuard(control, binding)
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    def broker(changes=None):
        """Construct one human-bound adapter without agent/API credentials."""
        return DatabaseBroker(
            settings, sign(changes), "colleague", recovery_store=store, run_guard=guard, http=http
        )

    return settings, store, state, broker, http
