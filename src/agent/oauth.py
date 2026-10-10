import json
from typing import Literal
from urllib.parse import urlparse

import httpx
import jwt
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from .schemas import Principal
from .security import SecurityError


class OAuthConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    discovery_url: str | None = None
    token_endpoint: str | None = None
    issuer: str | None = None
    client_id: str = Field(repr=False)
    client_secret: SecretStr = Field(repr=False)
    auth_method: Literal["client_secret_basic", "client_secret_post"] = "client_secret_post"
    trusted_hosts: frozenset[str] = frozenset()

    @field_validator("discovery_url", "token_endpoint", "issuer")
    @classmethod
    def secure_url(cls, value):
        if value is not None:
            parsed = urlparse(value)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.fragment
            ):
                raise ValueError("HTTPS endpoint required")
        return value


class TokenResponse(BaseModel):
    access_token: SecretStr = Field(repr=False, min_length=1, max_length=65536)
    refresh_token: SecretStr | None = Field(
        default=None, repr=False, min_length=1, max_length=65536
    )
    id_token: SecretStr | None = Field(default=None, repr=False, min_length=1, max_length=65536)
    token_type: str
    expires_in: int | None = Field(default=None, ge=0)
    issued_token_type: str | None = None


class OAuthClient:
    def __init__(self, config: OAuthConfig, http: httpx.AsyncClient):
        self.config, self.http = config, http
        self._metadata: dict | None = None

    def validate_endpoint(self, endpoint: str) -> str:
        parsed = urlparse(endpoint)
        roots = [self.config.discovery_url, self.config.token_endpoint, self.config.issuer]
        hosts = self.config.trusted_hosts | frozenset(urlparse(x).hostname for x in roots if x)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in hosts
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise SecurityError("oauth_untrusted_endpoint")
        return endpoint

    async def metadata(self) -> dict:
        if self._metadata is None:
            if not self.config.discovery_url:
                raise SecurityError("oauth_discovery_missing")
            try:
                response = await self.http.get(self.validate_endpoint(self.config.discovery_url))
                response.raise_for_status()
                data = response.json()
                if self.config.issuer and data.get("issuer") != self.config.issuer:
                    raise SecurityError("oauth_issuer_mismatch")
                for name in ("issuer", "token_endpoint", "jwks_uri"):
                    self.validate_endpoint(data[name])
                self._metadata = data
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                raise SecurityError("oauth_discovery_failed") from None
        return self._metadata

    async def _token(self, data: dict[str, str]) -> TokenResponse:
        endpoint = self.config.token_endpoint or (await self.metadata())["token_endpoint"]
        auth = None
        data = dict(data)
        if self.config.auth_method == "client_secret_basic":
            auth = httpx.BasicAuth(
                self.config.client_id, self.config.client_secret.get_secret_value()
            )
        else:
            data.update(
                client_id=self.config.client_id,
                client_secret=self.config.client_secret.get_secret_value(),
            )
        try:
            response = await self.http.post(self.validate_endpoint(endpoint), data=data, auth=auth)
            if response.is_error:
                raise SecurityError(f"oauth_http_{response.status_code}")
            if len(response.content) > 262144:
                raise SecurityError("oauth_response_size")
            token = TokenResponse.model_validate(response.json())
            if token.token_type.lower() != "bearer" or token.issued_token_type not in {
                None,
                "urn:ietf:params:oauth:token-type:access_token",
            }:
                raise SecurityError("oauth_token_type")
            return token
        except (httpx.HTTPError, ValueError, TypeError):
            raise SecurityError("oauth_request_failed") from None

    async def client_credentials(self, scopes: tuple[str, ...] = ()) -> TokenResponse:
        data = {"grant_type": "client_credentials"}
        if scopes:
            data["scope"] = " ".join(scopes)
        return await self._token(data)

    async def authorization_code(
        self, code: str, verifier: str, redirect_uri: str
    ) -> TokenResponse:
        return await self._token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": redirect_uri,
            }
        )

    async def refresh(self, token: SecretStr) -> TokenResponse:
        return await self._token(
            {"grant_type": "refresh_token", "refresh_token": token.get_secret_value()}
        )

    async def exchange_details(
        self, subject: SecretStr, actor: SecretStr, details: list[dict], audience: str
    ) -> TokenResponse:
        return await self._token(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject.get_secret_value(),
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "actor_token": actor.get_secret_value(),
                "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": audience,
                "authorization_details": json.dumps(details),
            }
        )

    async def exchange(
        self, subject: SecretStr, actor: SecretStr, path: str, audience: str
    ) -> TokenResponse:
        from .vault import validate_path

        validate_path(path)
        return await self.exchange_details(
            subject,
            actor,
            [{"type": "vault:path_access", "path": path, "capabilities": ["read"]}],
            audience,
        )


class JWTVerifier:
    def __init__(self, oauth: OAuthClient, audience: str, *, token_typ: str = "at+jwt"):
        if not audience:
            raise SecurityError("oauth_audience_missing")
        self.oauth, self.audience, self.token_typ = oauth, audience, token_typ

    async def verify_claims(self, token: SecretStr) -> dict:
        try:
            metadata = await self.oauth.metadata()
            response = await self.oauth.http.get(self.oauth.validate_endpoint(metadata["jwks_uri"]))
            response.raise_for_status()
            keys = jwt.PyJWKSet.from_dict(response.json())
            raw = token.get_secret_value()
            header = jwt.get_unverified_header(raw)
            if header.get("typ") != self.token_typ or header.get("alg") not in {"RS256", "ES256"}:
                raise SecurityError("identity_token_type")
            key = keys[header["kid"]]
            claims = jwt.decode(
                raw,
                key=key.key,
                algorithms=[header["alg"]],
                audience=self.audience,
                issuer=metadata["issuer"],
                options={"require": ["iss", "sub", "aud", "exp", "iat"]},
            )
            if not isinstance(claims["sub"], str) or not claims["sub"]:
                raise SecurityError("identity_subject")
            return claims
        except SecurityError:
            raise
        except jwt.ExpiredSignatureError:
            raise SecurityError("identity_expired") from None
        except (jwt.PyJWTError, httpx.HTTPError, ValueError, KeyError, TypeError):
            raise SecurityError("identity_invalid") from None

    async def verify(self, token: SecretStr) -> Principal:
        claims = await self.verify_claims(token)
        if claims.get("grant_type") == "client_credentials":
            raise SecurityError("identity_user_required")
        return Principal(
            issuer=claims["iss"],
            subject=claims["sub"],
            scopes=frozenset(str(claims.get("scope", "")).split()),
            expires_at=claims["exp"],
        )
