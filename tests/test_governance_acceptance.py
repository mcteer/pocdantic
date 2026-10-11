"""Four-story fixture matrix exercises all seven predicates without native promotion.

Native-shaped records here simulate adapters/source receipts inside a temporary store.
They prove software predicates only; no test edits a public acceptance ledger.
"""

from datetime import timedelta
from uuid import uuid4

import pytest
from governance_support import binding, installed, source

from agent.governance.config import binding_digest
from agent.governance.models import (
    Challenge,
    CredentialIntent,
    Evidence,
    Facts,
    Observation,
    RegistrationAttempt,
    Review,
    Verification,
    now,
)
from agent.governance.report import TESTS, closeout
from agent.validation.models import implementation_revision


def matrix(tmp_path):
    """Seed independent source/enrollment/identity/policy receipts with causal ordering."""
    store = installed(tmp_path)
    profile = source().model_copy(update={"provenance": "native"})
    store.configure((profile,), 1)
    item = store.case("fixture")
    b = binding()
    t = now()
    item = item.model_copy(
        update={
            "binding": b,
            "state": "registered",
            "registration_digest": "0" * 64,
            "registration_id": "fixture",
            "registered_at": t - timedelta(seconds=10),
        }
    )
    implementation = implementation_revision()
    digest = binding_digest(b)
    decision = Review(
        candidate_id=item.candidate_id,
        candidate_revision=1,
        journal_revision=1,
        binding_digest=digest,
        metadata_digest="0" * 64,
        evidence_digest="0" * 64,
        implementation=implementation,
        operator="fixture",
        consumed=True,
    )
    registration = RegistrationAttempt(
        candidate_id=item.candidate_id,
        generation=1,
        review_id=decision.review_id,
        binding_digest=digest,
        state="confirmed",
        submitted_at=t - timedelta(seconds=20),
        finished_at=t - timedelta(seconds=10),
        registration_id="fixture",
        readback_digest="0" * 64,
        source_digest="0" * 64,
    )
    observation = Observation(
        candidate_id=item.candidate_id,
        source=profile.alias,
        source_generation=1,
        source_digest=binding_digest(profile),
        event="fixture-discovery",
        object=b.source_object,
        kind="unknown",
        occurred_at=t - timedelta(seconds=40),
        received_at=t - timedelta(seconds=35),
        selected_digest="0" * 64,
        provenance="native",
    )
    intent = CredentialIntent(
        candidate_id=item.candidate_id,
        generation=1,
        profile_digest=digest,
        kind="svid",
        state="confirmed",
        submitted_at=t - timedelta(seconds=5),
        finished_at=t - timedelta(seconds=1),
        token_digest="0" * 64,
        expires_at=t + timedelta(seconds=60),
        safe_after=t + timedelta(seconds=90),
    )
    challenge = Challenge(
        candidate_id=item.candidate_id,
        generation=1,
        intent_id=intent.intent_id,
        binding_digest=digest,
        implementation=implementation,
        nonce_digest="0" * 64,
        consumed=True,
    )
    proof = Verification(
        candidate_id=item.candidate_id,
        generation=1,
        challenge_id=challenge.challenge_id,
        token_digest="0" * 64,
        trust_digest=binding_digest(b.trust),
        result="pass",
        reason="ok",
        expires_at=intent.expires_at,
    )
    kinds = set(k for group in TESTS.values() for k in group)
    evidence = []
    for kind in sorted(kinds):
        before = kind in {"registry_absence", "discovery", "notification", "preregistration"}
        observed, received = (
            (t - timedelta(seconds=40), t - timedelta(seconds=35)) if before else (t, t)
        )
        facts = Facts(
            status=403
            if kind in {"preregistration", "obo_beyond_ceiling", "direct_denied"}
            else 200,
            control_status=200,
            baseline_status=200,
            proof_id=proof.proof_id if kind == "identity" else None,
            negative_classes=("signature", "audience", "expiry", "trust", "entity")
            if kind == "verifier_negatives"
            else (),
            vault_audit_digest="0" * 64 if kind == "audit" else None,
            source_audit_digest="0" * 64 if kind == "audit" else None,
        )
        evidence.append(
            Evidence(
                candidate_id=item.candidate_id,
                case_id=item.case_id,
                generation=1,
                environment=store.environment,
                implementation=implementation,
                binding_digest=digest,
                source_digest=binding_digest(profile),
                artifact_digest="0" * 64,
                kind=kind,
                outcome="pass",
                provenance="synthetic" if kind == "verifier_negatives" else "native",
                observed_at=observed,
                received_at=received,
                clock_bound=1,
                independent=True,
                healthy=True,
                attributed=True,
                reviewed_by="fixture",
                reviewed_at=t,
                observation_id=observation.observation_id
                if kind in {"discovery", "audit"}
                else None,
                attempt_id=intent.intent_id
                if kind == "identity"
                else registration.attempt_id
                if kind in {"registration", "audit"}
                else None,
                facts=facts,
            )
        )
    store.change(
        lambda j: j.model_copy(
            update={
                "candidates": (item,),
                "reviews": (decision,),
                "registrations": (registration,),
                "observations": (observation,),
                "credentials": (intent,),
                "challenges": (challenge,),
                "verifications": (proof,),
                "evidence": tuple(evidence),
            }
        )
    )
    return store, item


def test_every_predicate_passes_only_with_its_independent_fixture_receipts(tmp_path):
    store, item = matrix(tmp_path)
    results = closeout(store.read(), item.candidate_id)["tests"]
    assert len(results) == 7
    assert all(r["outcome"] == "pass" for r in results)


@pytest.mark.parametrize(
    "kind",
    [
        "audit",
        "identity",
        "obo_beyond_ceiling",
        "preregistration",
        "notification",
        "verifier_negatives",
    ],
)
def test_latest_contradiction_invalidates_only_dependent_proofs(tmp_path, kind):
    store, item = matrix(tmp_path)
    original = next(e for e in store.read().evidence if e.kind == kind)
    contradictory = original.model_copy(
        update={
            "evidence_id": uuid4(),
            "outcome": "fail",
            "received_at": now() + timedelta(seconds=1),
        }
    )
    store.change(lambda j: j.model_copy(update={"evidence": (*j.evidence, contradictory)}))
    results = {
        r["test_id"]: r["outcome"] for r in closeout(store.read(), item.candidate_id)["tests"]
    }
    for test_id, kinds in TESTS.items():
        if kind in kinds:
            assert results[test_id] != "pass"


def test_unavailable_audit_does_not_block_other_paths(tmp_path):
    store, item = matrix(tmp_path)
    store.change(
        lambda j: j.model_copy(
            update={"evidence": tuple(e for e in j.evidence if e.kind != "audit")}
        )
    )
    results = {r["test_id"]: r for r in closeout(store.read(), item.candidate_id)["tests"]}
    assert results["F11-T5"]["reason_code"] == "audit_unavailable"
    assert all(r["outcome"] == "pass" for k, r in results.items() if k != "F11-T5")
