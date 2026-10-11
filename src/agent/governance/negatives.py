"""Synthetic verifier rejection classes and actual unauthenticated mint denial.

Local mutations are labeled synthetic. Native issuer enforcement is a separate request
with its own issuance intent and a successful authenticated independent relying control.
"""

import json

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from .bootstrap import uncertain, update_intent
from .config import binding_digest
from .models import GovernanceError, now, require
from .network import request
from .verifier import verify


def local_checks(trust):
    """Check five signed synthetic negatives without exporting any test credential."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Always use a local RSA profile; this tests the strict shared predicates and
    # never substitutes its keys/issuer for the independently pinned native profile.
    profile = trust.model_copy(update={"algorithm": "RS256"})
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public.update(kid="local-negative", use="sig", alg="RS256")
    jwks = {"keys": [public]}
    current = int(now().timestamp())
    claims = {
        "iss": profile.issuer,
        "sub": profile.subject,
        "aud": profile.audience,
        "iat": current,
        "exp": current + 60,
        "vault": {"entity": {"id": profile.entity_id}},
    }
    valid = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "local-negative"})
    verify(valid, profile, jwks)
    rejected = []
    variants = {
        "signature": (
            claims,
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            profile,
        ),
        "audience": (claims | {"aud": "synthetic-other"}, key, profile),
        "expiry": (claims | {"iat": current - 120, "exp": current - 60}, key, profile),
        "trust": (
            claims,
            key,
            profile.model_copy(update={"issuer": "https://synthetic-other.example"}),
        ),
        "entity": (claims | {"vault": {"entity": {"id": "synthetic-other"}}}, key, profile),
    }
    for kind, (value, signer, selected) in variants.items():
        raw = jwt.encode(value, signer, algorithm="RS256", headers={"kid": "local-negative"})
        try:
            verify(raw, selected, jwks)
        except GovernanceError:
            rejected.append(kind)
    require(len(rejected) == 5, "proof_inconclusive")
    return {
        "outcome": "pass",
        "provenance": "synthetic",
        "classes": rejected,
        "digest": binding_digest(rejected),
    }


async def unauthenticated(store, candidate, binding, http, control, check):
    """Attempt the fixed mint without credentials only after a real healthy control.

    An unexpected token or lost reply remains possible issuance and pins the case. Only
    the actual authentication rejection is a no-issuance terminal result.
    """
    require(control.get("result") == "pass", "proof_inconclusive")
    require(
        not http.cookies
        and http.auth is None
        and "authorization" not in http.headers
        and "x-vault-token" not in http.headers,
        "invalid_input",
    )
    intent = store.intent(candidate.candidate_id, "svid")
    submitted = now()
    check()
    update_intent(store, intent, state="submitted", submitted_at=submitted)
    try:
        headers = {"X-Vault-Namespace": binding.namespace} if binding.namespace else {}
        status, value, digest = await request(
            http,
            "POST",
            binding.vault_origin
            + "/v1/"
            + binding.trust.mount
            + "/role/"
            + binding.trust.role
            + "/mintjwt",
            headers=headers,
            body={"audience": binding.trust.audience},
        )
        check()
        require(
            status in {401, 403} and isinstance(value, dict) and "data" not in value,
            "proof_inconclusive",
        )
        update_intent(store, intent, state="denied", finished_at=now(), reason="provider_denied")
        return {
            "outcome": "pass",
            "healthy": True,
            "attributed": True,
            "digest": digest,
            "intent_id": str(intent.intent_id),
        }
    except BaseException:
        uncertain(store, intent, binding, submitted_at=submitted)
        raise GovernanceError("issuance_unresolved") from None
