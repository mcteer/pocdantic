"""Synthetic signed identity fixtures; never load local/customer credentials."""

import json
import time
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr

from agent.settings import Settings


@pytest.fixture
def workspace_settings():
    return Settings(
        _env_file=None,
        model="test",
        oauth_provider="generic",
        oauth_discovery_url="https://id.example/discovery",
        oauth_issuer="https://id.example",
        oauth_audience="resource",
        oauth_client_id="actor",
        oauth_client_secret=SecretStr("actor-secret"),
        login_client_id="login",
        login_client_secret=SecretStr("login-secret"),
        login_scopes="openid offline_access database:read infra:write tickets:read",
        timeout_seconds=1,
    )


@pytest.fixture
def identity_provider():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True) | {"kid": "key"}

    class Provider:
        nonce = "test-nonce"
        ttl = 3600
        subject = "user"
        refresh_subject = None
        scopes = "database:read infra:write tickets:read"
        refresh_error = False
        calls = []
        codes = {}
        vault_calls = []
        leases = 0

        def access(self, **changes):
            claims = {
                "iss": "https://id.example",
                "sub": self.subject,
                "aud": "resource",
                "exp": int(time.time()) + self.ttl,
                "iat": int(time.time()),
                "scope": self.scopes,
            } | changes
            return jwt.encode(
                claims, key, algorithm="RS256", headers={"typ": "at+jwt", "kid": "key"}
            )

        def identity(self, **changes):
            return jwt.encode(
                {
                    "iss": "https://id.example",
                    "sub": self.subject,
                    "aud": "login",
                    "exp": int(time.time()) + 3600,
                    "iat": int(time.time()),
                    "nonce": self.nonce,
                }
                | changes,
                key,
                algorithm="RS256",
                headers={"kid": "key"},
            )

        def handle(self, request):
            if request.url.path == "/discovery":
                return httpx.Response(
                    200,
                    json={
                        "issuer": "https://id.example",
                        "authorization_endpoint": "https://id.example/authorize",
                        "token_endpoint": "https://id.example/token",
                        "jwks_uri": "https://id.example/jwks",
                    },
                )
            if request.url.path == "/jwks":
                return httpx.Response(200, json={"keys": [jwk]})
            if request.url.path == "/token":
                values = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
                self.calls.append(values["grant_type"])
                if values["grant_type"] == "client_credentials":
                    return httpx.Response(
                        200,
                        json={
                            "access_token": self.access(
                                sub="actor",
                                aud="actor",
                                client_id="actor",
                                grant_type="client_credentials",
                            ),
                            "token_type": "Bearer",
                        },
                    )
                if values["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange":
                    details = json.loads(values["authorization_details"])
                    return httpx.Response(
                        200,
                        json={
                            "access_token": self.access(
                                aud="vault",
                                act={"sub": "actor", "iss": "https://id.example"},
                                authorization_details=details,
                            ),
                            "token_type": "Bearer",
                        },
                    )
                if values["grant_type"] == "refresh_token":
                    if self.refresh_error:
                        return httpx.Response(
                            400,
                            json={
                                "error": "invalid_grant",
                                "error_description": "PRIVATE UPSTREAM SENTINEL",
                            },
                        )
                    return httpx.Response(
                        200,
                        json={
                            "access_token": self.access(sub=self.refresh_subject or self.subject),
                            "token_type": "Bearer",
                            "refresh_token": "rotated-refresh",
                        },
                    )
                self.nonce = self.codes.get(values.get("code"), self.nonce)
                return httpx.Response(
                    200,
                    json={
                        "access_token": self.access(),
                        "id_token": self.identity(),
                        "refresh_token": "initial-refresh",
                        "token_type": "Bearer",
                    },
                )
            if request.url.host == "vault.example":
                self.vault_calls.append(request)
                if request.method == "GET":
                    self.leases += 1
                    return httpx.Response(
                        200,
                        json={
                            "lease_id": f"database/creds/poc-readonly/lease{self.leases}",
                            "lease_duration": 120,
                            "data": {"username": "fixture-user", "password": "fixture-password"},
                        },
                    )
                return httpx.Response(204)
            raise AssertionError("Unexpected external request: " + request.url.path)

    return Provider()
