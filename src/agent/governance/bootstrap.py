"""Candidate-specific direct OAuth with exact RAR and durable issuance uncertainty.

Tokens remain in trusted memory. Administrative or human/OBO credentials cannot stand
in for the reviewed actor, even when the provider would accept them for the same path.
"""

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta

from agent.validation.models import canonical

from .config import binding_digest
from .models import CredentialIntent, GovernanceError, now, path, require


def details_for(target):
    """Construct the sole supported direct read grant for an approved path."""
    path(target)
    return [{"type": "vault:path_access", "path": target, "capabilities": ["read"]}]


def mint_details(binding):
    """Request update authority only for the fixed reviewed SPIFFE mint endpoint."""
    return [
        {
            "type": "vault:path_access",
            "path": binding.trust.mount + "/role/" + binding.trust.role + "/mintjwt",
            "capabilities": ["update"],
        }
    ]


def validate_claims(claims, binding, audience, details):
    """Validate already signature-verified claims; decoded JWT text grants no authority."""
    require(isinstance(claims, dict), "bootstrap_mismatch")
    require(
        claims.get("iss") == binding.actor_issuer and claims.get("sub") == binding.actor_subject,
        "bootstrap_mismatch",
    )
    require(
        claims.get("aud") in (audience, [audience]) and "act" not in claims, "bootstrap_mismatch"
    )
    require(
        canonical(claims.get("authorization_details")) == canonical(details), "bootstrap_mismatch"
    )
    current = int(now().timestamp())
    issued, expires = claims.get("iat"), claims.get("exp")
    require(type(issued) is int and type(expires) is int, "bootstrap_mismatch")
    ceiling = binding.trust.oauth_max_ttl or 86400
    require(
        issued <= current + 30 and expires > current and 0 < expires - issued <= ceiling,
        "bootstrap_mismatch",
    )
    if "nbf" in claims:
        require(type(claims["nbf"]) is int and claims["nbf"] <= current + 30, "bootstrap_mismatch")


def update_intent(store, intent, **changes):
    """Commit lifecycle fields without allowing replacement of the pinned issuance target."""
    require(
        set(changes)
        <= {
            "state",
            "submitted_at",
            "finished_at",
            "token_digest",
            "expires_at",
            "safe_after",
            "reason",
        }
    )
    updated = None

    def change(journal):
        """Update the exact retained intent while preserving its candidate and profile binding."""
        nonlocal updated
        current = next((i for i in journal.credentials if i.intent_id == intent.intent_id), None)
        require(current is not None, "storage_error")
        updated = CredentialIntent.model_validate(current.model_dump() | changes)
        return journal.model_copy(
            update={
                "credentials": tuple(
                    updated if i.intent_id == intent.intent_id else i for i in journal.credentials
                )
            }
        )

    store.change(change)
    return updated


def uncertain(store, intent, binding, *, submitted_at):
    """Keep unknown issuance pinned unless independently reviewed bounds cover completion."""
    trust = binding.trust
    ttl = trust.max_ttl if intent.kind == "svid" else trust.oauth_max_ttl
    safe_after = (
        submitted_at + timedelta(seconds=trust.server_completion_bound + ttl + 30)
        if trust.server_completion_bound and ttl
        else None
    )
    return update_intent(
        store,
        intent,
        state="uncertain",
        submitted_at=submitted_at,
        reason="issuance_unresolved",
        safe_after=safe_after,
    )


async def acquire(store, candidate, binding, oauth, verifier, audience, details, check):
    """Persist intent before a single token request and return only a verified memory token."""
    require(
        len(details) == 1
        and (
            details == mint_details(binding)
            or any(details == details_for(target) for target in binding.paths.values())
        ),
        "bootstrap_mismatch",
    )
    intent = store.intent(
        candidate.candidate_id, "actor_oauth", profile_digest=binding_digest(binding)
    )
    submitted = now()
    check()
    update_intent(store, intent, state="submitted", submitted_at=submitted)
    try:
        async with asyncio.timeout(10):
            token = await oauth.client_credentials_details(details, audience)
        check()
        async with asyncio.timeout(10):
            claims = await verifier.verify_claims(token.access_token)
        validate_claims(claims, binding, audience, details)
        check()
        expiry = datetime.fromtimestamp(claims["exp"], UTC)
        update_intent(
            store,
            intent,
            state="confirmed",
            finished_at=now(),
            expires_at=expiry,
            safe_after=expiry + timedelta(seconds=30),
            token_digest=hashlib.sha256(token.access_token.get_secret_value().encode()).hexdigest(),
        )
        return token.access_token
    except BaseException:
        # A credential may exist even when verification or the post-request hold check
        # failed. Do not mark a denied/error response as proof of non-issuance.
        uncertain(store, intent, binding, submitted_at=submitted)
        raise GovernanceError("bootstrap_mismatch") from None
