"""Fixed harmless KV reads and conservative policy-layer attribution predicates.

HTTP denial alone cannot establish Agent Registry or ceiling enforcement. Signed exact
RAR, current metadata and independent healthy/baseline reads are separate prerequisites.
"""

from agent.validation.models import canonical

from .bootstrap import details_for
from .models import require
from .network import request


def delegated(claims, binding, human_subject, details):
    """Check already verified human/actor delegation and the exact requested read grants."""
    return (
        isinstance(claims, dict)
        and claims.get("sub") == human_subject
        and claims.get("act") == {"iss": binding.actor_issuer, "sub": binding.actor_subject}
        and canonical(claims.get("authorization_details")) == canonical(details)
    )


def ceiling_denial(
    status,
    claims,
    binding,
    human_subject,
    details,
    *,
    baseline_status,
    healthy_status,
    metadata_current,
):
    """Attribute only a healthy native denial after proving human baseline and exact RAR."""
    return (
        status == 403
        and baseline_status == healthy_status == 200
        and metadata_current is True
        and details == details_for(binding.paths["obo_beyond_ceiling"])
        and delegated(claims, binding, human_subject, details)
    )


async def read(http, binding, scenario, token):
    """Read a compiled reviewed KV path and discard all fixture values at the adapter boundary."""
    require(scenario in binding.paths)
    headers = {"X-Vault-Token": token.get_secret_value()}
    if binding.namespace:
        headers["X-Vault-Namespace"] = binding.namespace
    status, _body, digest = await request(
        http, "GET", binding.vault_origin + "/v1/" + binding.paths[scenario], headers=headers
    )
    return {"status": status, "digest": digest}


def distinct_control(candidate_claims, healthy_claims, binding):
    """Require genuinely distinct signed actor identities rather than two client aliases."""
    require(
        candidate_claims.get("iss") == binding.actor_issuer
        and candidate_claims.get("sub") == binding.actor_subject
    )
    require(
        healthy_claims.get("iss") == binding.actor_issuer
        and healthy_claims.get("sub") != binding.actor_subject
    )
    require("act" not in candidate_claims and "act" not in healthy_claims)
    require(healthy_claims.get("sub") is not None)


async def acquire_obo(
    store, candidate, binding, oauth, verifier, audience, human, human_verifier, details, check
):
    """Issue one delegated token after independently verifying human and actor identities.

    The exchange has its own durable intent. Even a failed response remains possible
    issuance; a client timeout is never recorded as provider denial.
    """
    import asyncio
    import hashlib
    from datetime import UTC, datetime, timedelta

    from .bootstrap import acquire, uncertain, update_intent
    from .config import binding_digest
    from .models import GovernanceError, now

    check()
    async with asyncio.timeout(10):
        human_claims = await human_verifier.verify_claims(human)
    require(
        human_claims.get("iss") == binding.owner_issuer
        and human_claims.get("sub") == binding.owner_subject
        and "act" not in human_claims
        and human_claims.get("grant_type") != "client_credentials",
        "bootstrap_mismatch",
    )
    actor = await acquire(store, candidate, binding, oauth, verifier, audience, details, check)
    intent = store.intent(
        candidate.candidate_id, "obo_oauth", profile_digest=binding_digest(binding)
    )
    submitted = now()
    check()
    update_intent(store, intent, state="submitted", submitted_at=submitted)
    try:
        async with asyncio.timeout(10):
            issued = await oauth.exchange_details(human, actor, details, audience)
        check()
        async with asyncio.timeout(10):
            claims = await verifier.verify_claims(issued.access_token)
        require(
            claims.get("iss") == binding.actor_issuer
            and claims.get("aud") in (audience, [audience])
            and delegated(claims, binding, binding.owner_subject, details),
            "bootstrap_mismatch",
        )
        iat, exp = claims.get("iat"), claims.get("exp")
        require(
            type(iat) is int
            and type(exp) is int
            and iat <= int(now().timestamp()) + 30
            and exp > int(now().timestamp())
            and 0 < exp - iat <= (binding.trust.oauth_max_ttl or 86400),
            "bootstrap_mismatch",
        )
        if "nbf" in claims:
            require(
                type(claims["nbf"]) is int and claims["nbf"] <= int(now().timestamp()) + 30,
                "bootstrap_mismatch",
            )
        check()
        expiry = datetime.fromtimestamp(exp, UTC)
        update_intent(
            store,
            intent,
            state="confirmed",
            finished_at=now(),
            token_digest=hashlib.sha256(
                issued.access_token.get_secret_value().encode()
            ).hexdigest(),
            expires_at=expiry,
            safe_after=expiry + timedelta(seconds=30),
        )
        return issued.access_token, claims, intent
    except BaseException:
        uncertain(store, intent, binding, submitted_at=submitted)
        raise GovernanceError("bootstrap_mismatch") from None


async def prove(
    store,
    candidate,
    binding,
    *,
    oauth,
    verifier,
    healthy_oauth,
    healthy_verifier,
    healthy_binding,
    audience,
    http,
    human,
    human_verifier,
    registry,
    check,
):
    """Run four fixed permission paths with current policies and independent controls.

    All five fixture paths are compiled in the binding. OBO beyond-ceiling attribution
    additionally requires the same human's direct baseline and a distinct healthy actor.
    Returned records contain decisions/digests only, never the fixture values.
    """
    from .bootstrap import acquire
    from .config import binding_digest

    require(
        candidate.state == "registered" and candidate.binding == binding, "configuration_changed"
    )
    require(healthy_binding.actor_subject != binding.actor_subject, "bootstrap_mismatch")
    expected = await registry.metadata(binding, require_absent=False)
    require(
        candidate.readiness and binding_digest(expected) == candidate.readiness.metadata_digest,
        "configuration_changed",
    )
    results = {}
    for scenario in ("obo_allowed", "obo_beyond_ceiling", "direct_allowed", "direct_denied"):
        check()
        details = details_for(binding.paths[scenario])
        healthy = await acquire(
            store,
            candidate,
            healthy_binding,
            healthy_oauth,
            healthy_verifier,
            audience,
            details,
            check,
        )
        check()
        control = await read(http, binding, scenario, healthy)
        check()
        if scenario.startswith("obo_"):
            token, claims, intent = await acquire_obo(
                store,
                candidate,
                binding,
                oauth,
                verifier,
                audience,
                human,
                human_verifier,
                details,
                check,
            )
            baseline = await read(http, binding, scenario, human)
            check()
        else:
            token = await acquire(
                store, candidate, binding, oauth, verifier, audience, details, check
            )
            claims, baseline, intent = None, None, None
        decision = await read(http, binding, scenario, token)
        check()
        current = await registry.metadata(binding, require_absent=False)
        check()
        stable = binding_digest(current) == binding_digest(expected)
        expected_status = 403 if scenario in {"obo_beyond_ceiling", "direct_denied"} else 200
        attributed = stable and control["status"] == 200 and decision["status"] == expected_status
        if scenario == "obo_beyond_ceiling":
            attributed = ceiling_denial(
                decision["status"],
                claims,
                binding,
                binding.owner_subject,
                details,
                baseline_status=baseline["status"],
                healthy_status=control["status"],
                metadata_current=stable,
            )
        elif scenario == "obo_allowed":
            attributed = attributed and baseline["status"] == 200
        results[scenario] = {
            "status": decision["status"],
            "control_status": control["status"],
            "baseline_status": baseline["status"] if baseline else None,
            "outcome": "pass" if attributed else "inconclusive",
            "healthy": control["status"] == 200,
            "attributed": attributed,
            "digest": binding_digest([decision, control, baseline, expected]),
            "intent_id": str(intent.intent_id) if intent else None,
        }
    return results
