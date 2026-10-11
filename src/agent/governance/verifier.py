"""Independent pinned Vault JWT-SVID verification and bounded public key caching.

No credential, claim or JOSE field selects a network location. Claim validation follows
signature verification; neither a successful mint nor decoded JWT text is relying proof.
"""

import asyncio
import base64
import hashlib
import re
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from agent.validation.store import decode_json

from .models import GovernanceError, now, require, spiffe
from .network import request

PRIVATE_PARAMETERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}


def segment(value):
    """Decode a canonical bounded JWT JSON segment, rejecting duplicate members."""
    require(bool(re.fullmatch(r"[A-Za-z0-9_-]+", value)), "identity_rejected")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))
        require(base64.urlsafe_b64encode(raw).decode().rstrip("=") == value, "identity_rejected")
        data = decode_json(raw)
        require(isinstance(data, dict), "identity_rejected")
        return data
    except Exception:
        raise GovernanceError("identity_rejected") from None


def keys(jwks, trust):
    """Validate the whole pinned public key set before choosing any signing key."""
    require(
        isinstance(jwks, dict)
        and set(jwks) == {"keys"}
        and isinstance(jwks["keys"], list)
        and len(jwks["keys"]) <= 16,
        "trust_unavailable",
    )
    result = {}
    for value in jwks["keys"]:
        require(
            isinstance(value, dict) and not PRIVATE_PARAMETERS & value.keys(), "trust_unavailable"
        )
        kid = value.get("kid")
        require(
            type(kid) is str and 1 <= len(kid) <= 128 and kid not in result, "trust_unavailable"
        )
        require(
            value.get("use") == "sig" and value.get("alg", trust.algorithm) == trust.algorithm,
            "trust_unavailable",
        )
        require("key_ops" not in value or value["key_ops"] == ["verify"], "trust_unavailable")
        require(not {"jku", "x5u", "jwk"} & value.keys(), "trust_unavailable")
        try:
            key = jwt.PyJWK.from_dict(value, algorithm=trust.algorithm).key
            if trust.algorithm.startswith("RS"):
                require(
                    isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048, "trust_unavailable"
                )
            else:
                curve = {"ES256": "secp256r1", "ES384": "secp384r1", "ES512": "secp521r1"}[
                    trust.algorithm
                ]
                require(
                    isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == curve,
                    "trust_unavailable",
                )
            result[kid] = key
        except GovernanceError:
            raise
        except Exception:
            raise GovernanceError("trust_unavailable") from None
    return result


def header(raw, trust):
    """Inspect only allowlisted routing fields; no decoded claim grants authority."""
    require(type(raw) is str and 0 < len(raw.encode()) <= 16384, "identity_rejected")
    parts = raw.split(".")
    require(len(parts) == 3 and all(parts), "identity_rejected")
    h = segment(parts[0])
    require(
        set(h) <= {"alg", "kid", "typ"}
        and h.get("alg") == trust.algorithm
        and h.get("typ") in (None, "JWT", "JOSE"),
        "identity_rejected",
    )
    require(type(h.get("kid")) is str and 1 <= len(h["kid"]) <= 128, "identity_rejected")
    return h


def verify(raw, trust, jwks):
    """Verify the signature then enforce exact SPIFFE/entity/audience and strict times."""
    try:
        h = header(raw, trust)
        available = keys(jwks, trust)
        require(h["kid"] in available, "identity_rejected")
        jwt.decode(
            raw,
            available[h["kid"]],
            algorithms=[trust.algorithm],
            options={
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
                "verify_sub": False,
            },
        )
        # Parse the same signed bytes with duplicate-key rejection after validating
        # their signature; PyJWT's ordinary JSON parser permits last-member wins.
        claims = segment(raw.split(".")[1])
        require(
            {"iss", "sub", "aud", "iat", "exp", "vault"} <= claims.keys(),
            "identity_rejected",
        )
        require(
            claims["iss"] == trust.issuer
            and claims["sub"] == trust.subject
            and spiffe(claims["sub"]) == trust.subject
            and isinstance(claims["vault"], dict)
            and isinstance(claims["vault"].get("entity"), dict)
            and claims["vault"]["entity"].get("id") == trust.entity_id,
            "identity_rejected",
        )
        require(claims["aud"] in (trust.audience, [trust.audience]), "identity_rejected")
        issued, expiry = claims["iat"], claims["exp"]
        current = int(now().timestamp())
        require(
            type(issued) is int
            and type(expiry) is int
            and 0 < expiry - issued <= trust.max_ttl
            and issued <= current + 30
            and expiry > current,
            "identity_rejected",
        )
        if "nbf" in claims:
            require(
                type(claims["nbf"]) is int
                and claims["nbf"] <= current + 30
                and claims["nbf"] < expiry,
                "identity_rejected",
            )
        return claims
    except GovernanceError:
        raise
    except Exception:
        raise GovernanceError("identity_rejected") from None


class Verifier:
    """One independent pinned trust cache; failed or expired refresh never reuses trust."""

    def __init__(self, trust, http, *, clock=time.monotonic):
        """Inject an independent client with redirects/environment proxies disabled."""
        require(not http.follow_redirects)
        self.trust, self.http, self.clock = trust, http, clock
        self.jwks = None
        self.fetched = float("-inf")
        self.unknown_refresh = float("-inf")
        self.refresh_lock = asyncio.Lock()

    async def refresh(self):
        """Fetch exact discovery/keys within provider bounds and atomically install valid trust."""
        try:
            headers = {"X-Vault-Namespace": self.trust.namespace} if self.trust.namespace else {}
            status, metadata, _digest = await request(
                self.http, "GET", self.trust.discovery_url, headers=headers
            )
            require(
                status == 200
                and isinstance(metadata, dict)
                and metadata.get("issuer") == self.trust.issuer
                and metadata.get("jwks_uri") == self.trust.jwks_url,
                "trust_unavailable",
            )
            status, jwks, _digest = await request(
                self.http, "GET", self.trust.jwks_url, headers=headers
            )
            require(status == 200, "trust_unavailable")
            keys(jwks, self.trust)
            self.jwks, self.fetched = jwks, self.clock()
        except Exception:
            self.jwks = None
            raise GovernanceError("trust_unavailable") from None

    async def check(self, raw):
        """Refresh stale keys and throttle unknown-key fetches; return private signed claims."""
        h = header(raw, self.trust)
        async with self.refresh_lock:
            if self.jwks is None or self.clock() - self.fetched >= 60:
                await self.refresh()
            available = keys(self.jwks, self.trust)
            if h["kid"] not in available and self.clock() - self.unknown_refresh >= 10:
                self.unknown_refresh = self.clock()
                await self.refresh()
        return verify(raw, self.trust, self.jwks)

    async def fingerprint(self, raw):
        """Verify and return only a digest suitable for safe proof correlation."""
        await self.check(raw)
        return hashlib.sha256(raw.encode()).hexdigest()
