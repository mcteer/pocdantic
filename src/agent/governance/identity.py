"""Candidate-authenticated native mint and ephemeral delivery to an independent relying service.

The mint response stays in trusted memory and private IPC. A mint acknowledgement is
not proof: only the independently recorded verification supplies a signed expiry bound.
"""

import asyncio
import hashlib
from datetime import timedelta
from uuid import UUID

from .bootstrap import acquire, mint_details, uncertain, update_intent
from .config import binding_digest
from .models import GovernanceError, now, require
from .network import request
from .relying import challenge


async def prove(
    store, candidate, binding, oauth, oauth_verifier, audience, http, relying_http, check
):
    """Mint once after direct candidate verification; deliver privately and correlate the proof."""
    require(
        candidate.state == "registered"
        and candidate.registration_id
        and candidate.binding == binding,
        "review_stale",
    )
    current = next(
        (c for c in store.read().candidates if c.candidate_id == candidate.candidate_id), None
    )
    require(current == candidate, "configuration_changed")
    check()
    token = await acquire(
        store, candidate, binding, oauth, oauth_verifier, audience, mint_details(binding), check
    )
    check()
    intent = store.intent(candidate.candidate_id, "svid")
    submitted = now()
    update_intent(store, intent, state="submitted", submitted_at=submitted)
    try:
        check()
        require(not http.follow_redirects)
        headers = {"X-Vault-Token": token.get_secret_value()}
        if binding.namespace:
            headers["X-Vault-Namespace"] = binding.namespace
        status, value, _digest = await request(
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
        require(
            status == 200 and isinstance(value, dict) and isinstance(value.get("data"), dict),
            "identity_rejected",
        )
        raw = value["data"].get("token")
        require(type(raw) is str and 0 < len(raw.encode()) <= 16384, "identity_rejected")
        check()
        envelope = challenge(store, candidate, intent)
        async with asyncio.timeout(10):
            response = await relying_http.post(
                "http://relying/verify", json=envelope | {"token": raw}
            )
        require(response.status_code == 200 and len(response.content) <= 8192, "proof_inconclusive")
        from agent.validation.store import decode_json

        result = decode_json(response.content)
        require(
            isinstance(result, dict)
            and result.get("schema_version") == 1
            and result.get("result") == "pass"
            and result.get("candidate_id") == str(candidate.candidate_id)
            and result.get("generation") == candidate.generation,
            "proof_inconclusive",
        )
        proof_id = UUID(result["proof_id"])
        state = store.read()
        proof = next((v for v in state.verifications if v.proof_id == proof_id), None)
        digest = hashlib.sha256(raw.encode()).hexdigest()
        require(
            proof
            and proof.result == "pass"
            and proof.challenge_id == UUID(envelope["challenge_id"])
            and proof.token_digest == digest
            and proof.trust_digest == binding_digest(binding.trust)
            and proof.generation == candidate.generation
            and proof.expires_at,
            "proof_inconclusive",
        )
        check()
        update_intent(
            store,
            intent,
            state="confirmed",
            finished_at=now(),
            token_digest=digest,
            expires_at=proof.expires_at,
            safe_after=proof.expires_at + timedelta(seconds=30),
        )
        return {
            "schema_version": 1,
            "candidate_id": str(candidate.candidate_id),
            "proof_id": str(proof.proof_id),
            "result": "pass",
        }
    except BaseException:
        uncertain(store, intent, binding, submitted_at=submitted)
        raise GovernanceError("issuance_unresolved") from None
