"""Compiled native workflows, run only inside an inherited effect-owner process.

Inputs name a local case, never a provider destination. Private drafts and credentials
are reopened through verified storage; all effects recheck existing containment. This
module provisions nothing and returns only generated identifiers and closed outcomes.
"""

from uuid import UUID

import httpx
from pydantic import SecretStr

from agent.oauth import JWTVerifier, OAuthClient, OAuthConfig
from agent.validation.models import implementation_revision

from .config import CandidateDraft, Secrets, activate, binding_digest, read_private, readiness
from .enrollment import candidate, enroll
from .evidence import attach
from .models import Evidence, Facts, now, require
from .registry import Registry


def credentials(settings, client, http, check):
    """Construct a checked OAuth adapter for exactly one reviewed private client."""
    require(client is not None, "missing_authority")
    require(settings.oauth_issuer and settings.oauth_discovery_url, "missing_authority")

    class CheckedOAuth(OAuthClient):
        """Recheck holds around every metadata or credential request."""

        async def bounded_json(self, *args, **kwargs):
            """Apply deterministic containment at each independently bounded dispatch."""
            check()
            result = await super().bounded_json(*args, **kwargs)
            check()
            return result

    return CheckedOAuth(
        OAuthConfig(
            discovery_url=settings.oauth_discovery_url,
            issuer=settings.oauth_issuer,
            client_id=client.client_id.get_secret_value(),
            client_secret=client.client_secret,
        ),
        http,
    )


def record(store, item, kind, result, *, attempt_id=None, facts=None, source_digest=None):
    """Retain an unreviewed native adapter receipt; explicit operator review is still needed."""
    evidence = Evidence(
        candidate_id=item.candidate_id,
        case_id=item.case_id,
        generation=item.generation,
        environment=store.environment,
        implementation=implementation_revision(),
        binding_digest=binding_digest(item.binding),
        source_digest=source_digest or binding_digest(item.binding),
        artifact_digest=result["digest"],
        kind=kind,
        outcome=result.get("outcome", "pass"),
        provenance=result.get("provenance", "native"),
        observed_at=now(),
        clock_bound=item.binding.registry_clock_bound,
        independent=True,
        healthy=result.get("healthy", False),
        attributed=result.get("attributed", True),
        attempt_id=attempt_id,
        facts=facts,
    )
    attach(store, evidence, revision=store.read().revision)
    return evidence


async def execute(operation, payload, store, settings, check):
    """Execute one selected workflow with a fixed candidate/revision and bounded adapters."""
    state = store.read()
    require(state.revision == payload["revision"], "review_stale")
    if operation == "enroll":
        decision = next((r for r in state.reviews if r.review_id == UUID(payload["review"])), None)
        require(decision, "review_stale")
        item = candidate(state, decision.candidate_id)
    else:
        item = candidate(state, UUID(payload["candidate"]))
    draft = CandidateDraft.model_validate(
        read_private(store, f"candidate-{item.candidate_id}.draft.json")
    )
    require(draft.binding, "missing_authority")
    binding = draft.binding
    require(
        binding.actor_issuer == settings.oauth_issuer
        and binding.vault_origin == (settings.vault_addr or "").rstrip("/")
        and binding.namespace == (settings.vault_namespace or ""),
        "configuration_changed",
    )
    secrets = Secrets.model_validate(read_private(store, "secrets.json"))
    require(secrets.operator, "missing_authority")
    needed = {"observe": 2, "enroll": 1, "identity": 1, "permissions": 4, "negatives": 3}.get(
        operation, 0
    )
    require(
        sum(e.candidate_id == item.candidate_id for e in state.evidence) + needed <= 32,
        "capacity_exhausted",
    )
    check()
    async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as http:
        registry = Registry(
            http,
            secrets.operator.get_secret_value(),
            entitlement=draft.entitlement.model_dump() if draft.entitlement else None,
            audience=settings.vault_audience,
            registration_id=item.registration_id,
            check=check,
        )
        if operation == "readiness":
            snapshot = await readiness(binding, registry)
            check()
            activate(store, item.candidate_id, draft, snapshot, revision=state.revision)
            return {
                "schema_version": 1,
                "candidate_id": str(item.candidate_id),
                "ready": snapshot.ready,
                "checks": snapshot.checks,
                "reason_code": snapshot.reason,
            }
        require(item.binding == binding, "configuration_changed")
        if operation == "enroll":
            attempt = await enroll(store, decision.review_id, state.revision, registry, check)
            latest = candidate(store.read(), item.candidate_id)
            record(
                store,
                latest,
                "registration",
                {"digest": latest.registration_digest},
                attempt_id=attempt,
            )
            return {
                "schema_version": 1,
                "candidate_id": str(item.candidate_id),
                "attempt_id": str(attempt),
                "state": "registered",
            }
        if operation == "reconcile":
            result = await registry.reconcile(binding, item.registration_id)
            check()

            def retain(current):
                """Keep reconciliation fingerprints without attributing foreign creation."""
                records = tuple(
                    a.model_copy(
                        update={
                            "readback_digest": result["digest"],
                            "state": "conflict"
                            if result.get("present", bool(result.get("registration_id")))
                            else "uncertain",
                            "reason": "registry_conflict"
                            if result.get("present", bool(result.get("registration_id")))
                            else "creation_uncertain",
                        }
                    )
                    if a.candidate_id == item.candidate_id
                    and a.state in {"submitted", "uncertain", "conflict"}
                    else a
                    for a in current.registrations
                )
                return current.model_copy(update={"registrations": records})

            store.change(retain)
            return {
                "schema_version": 1,
                "candidate_id": str(item.candidate_id),
                "present": result.get("present", bool(result.get("registration_id"))),
                "owned": False,
            }
        require(secrets.candidate and secrets.healthy, "missing_authority")
        require(
            secrets.candidate.alias == binding.client
            and secrets.candidate.subject == binding.actor_subject
            and secrets.healthy.alias == binding.healthy_client
            and secrets.healthy.subject != binding.actor_subject,
            "bootstrap_mismatch",
        )
        oauth = credentials(settings, secrets.candidate, http, check)
        healthy_oauth = credentials(settings, secrets.healthy, http, check)
        audience = settings.vault_audience
        require(audience, "missing_authority")
        verifier = JWTVerifier(oauth, audience, token_typ=settings.oauth_access_token_typ)
        healthy_verifier = JWTVerifier(
            healthy_oauth, audience, token_typ=settings.oauth_access_token_typ
        )
        healthy_binding = binding.model_copy(
            update={
                "actor_subject": secrets.healthy.subject,
                "client": binding.healthy_client,
                "healthy_client": binding.client,
            }
        )
        if operation == "observe":
            from .activity import observe

            result = await observe(
                store,
                item,
                binding,
                registry=registry,
                oauth=oauth,
                verifier=verifier,
                healthy_oauth=healthy_oauth,
                healthy_verifier=healthy_verifier,
                healthy_binding=healthy_binding,
                audience=audience,
                http=http,
                check=check,
            )
            record(store, item, "registry_absence", result | {"digest": result["absence"]})
            record(
                store,
                item,
                "preregistration",
                result,
                facts=Facts(status=result["status"], control_status=result["control_status"]),
            )
            return {
                "schema_version": 1,
                "candidate_id": str(item.candidate_id),
                "result": result["outcome"],
            }
        require(item.state == "registered", "review_stale")
        if operation in {"identity", "negatives"}:
            from .identity import prove

            fingerprints = await registry.metadata(binding, require_absent=False)
            require(
                item.readiness and binding_digest(fingerprints) == item.readiness.metadata_digest,
                "configuration_changed",
            )
            transport = httpx.AsyncHTTPTransport(uds=str(store.root / "relying.sock"))
            async with httpx.AsyncClient(
                transport=transport, timeout=10, trust_env=False, follow_redirects=False
            ) as relying:
                result = await prove(
                    store, item, binding, oauth, verifier, audience, http, relying, check
                )
            proof = next(
                v for v in store.read().verifications if str(v.proof_id) == result["proof_id"]
            )
            challenge = next(
                c for c in store.read().challenges if c.challenge_id == proof.challenge_id
            )
            record(
                store,
                item,
                "identity",
                {"digest": binding_digest(proof)},
                attempt_id=challenge.intent_id,
                facts=Facts(proof_id=proof.proof_id),
            )
            if operation == "negatives":
                from .negatives import local_checks, unauthenticated

                async with httpx.AsyncClient(
                    timeout=10, trust_env=False, follow_redirects=False
                ) as anonymous:
                    native = await unauthenticated(store, item, binding, anonymous, result, check)
                record(
                    store,
                    item,
                    "unauthenticated_mint",
                    native,
                    attempt_id=UUID(native["intent_id"]),
                )
                synthetic = local_checks(binding.trust)
                record(
                    store,
                    item,
                    "verifier_negatives",
                    synthetic,
                    facts=Facts(negative_classes=tuple(synthetic["classes"])),
                )
                return {
                    "schema_version": 1,
                    "candidate_id": str(item.candidate_id),
                    "result": "pass",
                    "local_negatives": "synthetic",
                }
            return result
        if operation == "permissions":
            from .permissions import prove

            require(
                isinstance(payload.get("human"), str) and 0 < len(payload["human"]) <= 16384,
                "missing_authority",
            )
            results = await prove(
                store,
                item,
                binding,
                oauth=oauth,
                verifier=verifier,
                healthy_oauth=healthy_oauth,
                healthy_verifier=healthy_verifier,
                healthy_binding=healthy_binding,
                audience=audience,
                http=http,
                human=SecretStr(payload["human"]),
                human_verifier=verifier,
                registry=registry,
                check=check,
            )
            for kind, result in results.items():
                record(
                    store,
                    item,
                    kind,
                    result,
                    attempt_id=UUID(result["intent_id"]) if result["intent_id"] else None,
                    facts=Facts(
                        status=result["status"],
                        control_status=result["control_status"],
                        baseline_status=result["baseline_status"],
                    ),
                )
            return {
                "schema_version": 1,
                "candidate_id": str(item.candidate_id),
                "results": {k: v["outcome"] for k, v in results.items()},
            }
        require(False, "unsupported")
