"""Code/PKCE login and separately verified resource credentials."""

import base64
import hashlib
import hmac
import re
import time
from dataclasses import dataclass, replace
from urllib.parse import urlencode

import httpx
import jwt
from pydantic import SecretStr

from agent.oauth import JWTVerifier, OAuthClient, OAuthConfig
from agent.schemas import Principal
from agent.security import SecurityError
from agent.workspace.sessions import LoginAttempt, opaque


@dataclass(frozen=True, repr=False)
class Credentials:
    access_token: SecretStr
    refresh_token: SecretStr | None
    principal: Principal
    nonce: str
    expires: float

    def with_expiry(self, expiry):
        return replace(self, expires=expiry)


class WorkspaceAuth:
    def __init__(self, settings, http, origin):
        self.settings, self.http, self.origin = settings, http, origin
        discovery = settings.oauth_discovery_url
        if not discovery and settings.verify_tenant_url:
            discovery = (
                settings.verify_tenant_url
                + "/v1.0/endpoint/default/.well-known/openid-configuration"
            )
        self.oauth = OAuthClient(
            OAuthConfig(
                discovery_url=discovery,
                issuer=settings.oauth_issuer,
                token_endpoint=settings.oauth_token_endpoint,
                client_id=settings.login_client_id,
                client_secret=settings.login_client_secret,
                auth_method=settings.oauth_auth_method,
            ),
            http,
        )
        self.verifier = JWTVerifier(
            self.oauth, settings.oauth_audience, token_typ=settings.oauth_access_token_typ
        )

    async def start(self, browser):
        async with browser.lock:
            metadata = await self.oauth.metadata()
            endpoint = self.oauth.validate_endpoint(metadata["authorization_endpoint"])
            attempt = LoginAttempt(opaque(), opaque(), opaque(), time.monotonic() + 300)
            browser.attempt = attempt
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(attempt.verifier.encode()).digest())
                .rstrip(b"=")
                .decode()
            )
            return (
                endpoint
                + "?"
                + urlencode(
                    {
                        "client_id": self.settings.login_client_id,
                        "redirect_uri": self.origin + "/auth/callback",
                        "response_type": "code",
                        "response_mode": "query",
                        "scope": self.settings.login_scopes,
                        "state": attempt.state,
                        "nonce": attempt.nonce,
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                    }
                )
            )

    def consume(self, browser, state):
        attempt = browser.attempt
        if (
            not isinstance(state, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", state)
            or not attempt
            or attempt.deadline <= time.monotonic()
            or not hmac.compare_digest(state, attempt.state)
        ):
            raise SecurityError("login_invalid")
        browser.attempt = None
        return attempt

    async def complete(self, browser, code, state):
        async with browser.lock:
            attempt = self.consume(browser, state)
            response = await self.oauth.authorization_code(
                code, attempt.verifier, self.origin + "/auth/callback"
            )
            if not response.id_token:
                raise SecurityError("login_invalid")
            principal = await self.validate_identity(
                response.id_token, response.access_token, attempt.nonce, initial=True
            )
            return self.credentials(response, principal, attempt.nonce)

    def credentials(self, response, principal, nonce, old_refresh=None):
        expiry = principal.expires_at
        if response.expires_in is not None:
            expiry = min(expiry, time.time() + response.expires_in)
        return Credentials(
            response.access_token,
            response.refresh_token or old_refresh,
            principal.model_copy(update={"expires_at": int(expiry)}),
            nonce,
            expiry,
        )

    async def validate_identity(self, token, access, nonce, *, initial):
        try:
            metadata = await self.oauth.metadata()
            response = await self.http.get(self.oauth.validate_endpoint(metadata["jwks_uri"]))
            response.raise_for_status()
            if len(response.content) > 262144:
                raise SecurityError("login_invalid")
            keys = jwt.PyJWKSet.from_dict(response.json())
            raw = token.get_secret_value()
            header = jwt.get_unverified_header(raw)
            alg = header.get("alg")
            if alg not in {"RS256", "ES256"}:
                raise SecurityError("login_invalid")
            claims = jwt.decode(
                raw,
                keys[header["kid"]].key,
                algorithms=[alg],
                issuer=metadata["issuer"],
                audience=self.settings.login_client_id,
                options={"require": ["iss", "sub", "aud", "iat", "exp"]},
            )
            audience = claims["aud"]
            if audience not in (self.settings.login_client_id, [self.settings.login_client_id]):
                raise SecurityError("login_invalid")
            if (
                claims.get("azp", self.settings.login_client_id) != self.settings.login_client_id
                or not isinstance(claims["sub"], str)
                or not claims["sub"]
                or (initial and "nonce" not in claims)
                or ("nonce" in claims and claims["nonce"] != nonce)
            ):
                raise SecurityError("login_invalid")
            if "at_hash" in claims:
                expected = (
                    base64.urlsafe_b64encode(
                        hashlib.sha256(access.get_secret_value().encode()).digest()[:16]
                    )
                    .rstrip(b"=")
                    .decode()
                )
                if not isinstance(claims["at_hash"], str) or not hmac.compare_digest(
                    expected, claims["at_hash"]
                ):
                    raise SecurityError("login_invalid")
            principal = await self.verifier.verify(access)
            if (principal.issuer, principal.subject) != (claims["iss"], claims["sub"]):
                raise SecurityError("login_invalid")
            return principal
        except SecurityError:
            raise
        except (jwt.PyJWTError, httpx.HTTPError, ValueError, KeyError, TypeError):
            raise SecurityError("login_invalid") from None

    async def admit(self, session):
        async with session.lock:
            if session.state != "active":
                raise SecurityError("sign_in_required")
            old = session.credentials
            needed = self.settings.timeout_seconds + 45
            try:
                if old.expires - time.time() < needed:
                    if not old.refresh_token:
                        raise SecurityError("sign_in_required")
                    response = await self.oauth.refresh(old.refresh_token)
                    principal = (
                        await self.validate_identity(
                            response.id_token, response.access_token, old.nonce, initial=False
                        )
                        if response.id_token
                        else await self.verifier.verify(response.access_token)
                    )
                    if (principal.issuer, principal.subject) != (
                        old.principal.issuer,
                        old.principal.subject,
                    ):
                        raise SecurityError("sign_in_required")
                    credentials = self.credentials(
                        response, principal, old.nonce, old.refresh_token
                    )
                else:
                    principal = await self.verifier.verify(old.access_token)
                    if (principal.issuer, principal.subject) != (
                        old.principal.issuer,
                        old.principal.subject,
                    ):
                        raise SecurityError("sign_in_required")
                    credentials = replace(old, principal=principal)
                if session.state != "active":
                    raise SecurityError("sign_in_required")
                session.credentials = credentials
            except (SecurityError, httpx.HTTPError, ValueError, TypeError):
                if session.state == "active":
                    session.state = "reauth_required"
                    session.credentials = replace(old, refresh_token=None)
                raise SecurityError("sign_in_required") from None
            if credentials.expires - time.time() < needed:
                raise SecurityError("token_lifetime_short")
            return credentials
