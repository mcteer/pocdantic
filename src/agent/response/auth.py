"""Authenticate only enrolled automation JWTs for the separate response audience."""

import time

from agent.oauth import JWTVerifier, OAuthClient
from agent.probe import oauth_config

from .models import ResponseError


class SourceAuthenticator:
    """Use existing pinned verification without accepting task cookies or task audiences."""

    def __init__(self, settings, policy, http):
        """Bind one captured policy and bounded HTTP client for key verification."""
        self.policy = policy
        self.verifier = (
            JWTVerifier(
                OAuthClient(oauth_config(settings), http),
                policy.audience,
                token_typ=settings.oauth_access_token_typ,
                leeway=30,
            )
            if policy.intake_mode == "relay"
            else None
        )

    async def verify(self, token):
        """Return the exact allowlisted source after signature, purpose, time and scope checks."""
        try:
            if self.verifier is None or len(token.get_secret_value()) > 65536:
                raise ResponseError("source_invalid")
            claims = await self.verifier.verify_claims(token)
            current = time.time()
            iat, exp = claims["iat"], claims["exp"]
            if (
                type(iat) not in (int, float)
                or type(exp) not in (int, float)
                or iat > current + 30
                or current - iat > 300
                or exp <= current
                or exp - current > 300
                or exp - iat > 300
                or exp <= iat
                or "response:submit" not in str(claims.get("scope", "")).split()
            ):
                raise ResponseError("source_invalid")
            source = next(
                (
                    s
                    for s in self.policy.sources
                    if (s.issuer, s.subject) == (claims["iss"], claims["sub"])
                ),
                None,
            )
            if source is None:
                raise ResponseError("source_invalid")
            return source
        except Exception:
            raise ResponseError("source_invalid") from None


class NativeAuthenticator:
    """Verify one separately enrolled relay profile using existing pinned JWT rules."""

    def __init__(self, settings, profile, http):
        """Capture the exact profile; no body-supplied identity or audience is accepted."""
        from types import SimpleNamespace

        self.profile = profile
        self.auth = SourceAuthenticator(
            settings,
            SimpleNamespace(audience=profile.audience, intake_mode="relay", sources=(profile,)),
            http,
        )

    async def verify(self, token):
        """Require signed freshness, submit scope, issuer and exact relay subject."""
        return await self.auth.verify(token)
