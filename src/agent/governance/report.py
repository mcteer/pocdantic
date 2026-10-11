"""Credential-free owner projections and independent Function 11 native dispositions.

Each test needs its own correlated evidence. A passing issuer response cannot substitute
for a relying proof, audit correlation or an attributed policy-denial pair.
"""

from collections import Counter

from agent.validation.models import implementation_revision

from .config import binding_digest
from .evidence import before_registration
from .models import REASONS, require

TESTS = {
    "F11-T1": ("registry_absence", "discovery", "notification"),
    "F11-T2": ("preregistration", "registration", "direct_allowed"),
    "F11-T3": ("identity",),
    "F11-T4": ("obo_allowed", "obo_beyond_ceiling"),
    "F11-T5": ("audit",),
    "F11-T6": ("unauthenticated_mint", "verifier_negatives"),
    "F11-T7": ("obo_allowed", "obo_beyond_ceiling", "direct_allowed", "direct_denied"),
}
ACTIONS = {
    "native_evidence_missing": (
        "Capture and review the exact native source receipt for this case, then "
        "import it and rerun closeout."
    ),
    "audit_unavailable": (
        "Enable Vault audit logging on a supported deployment, capture the "
        "correlated native audit event, then import it and rerun closeout."
    ),
    "issuance_unresolved": (
        "Review provider issuance evidence for the retained intent; resolve it "
        "before closing the case."
    ),
    "proof_inconclusive": (
        "Rerun the failed proof with its reviewed healthy control and exact policy metadata."
    ),
    "configuration_changed": (
        "Rerun readiness for the current private candidate draft and review the changed metadata."
    ),
    "source_not_ready": (
        "Enroll the exact source schema, collector receipt and separate relay "
        "authority in config.draft.json, then configure."
    ),
    "workspace_busy": (
        "Stop the browser workspace, wait for its workers to drain, run the "
        "privileged command, then restart the workspace."
    ),
    "contained": (
        "Inspect agent respond status and complete the existing incident "
        "workflow before rerunning this command."
    ),
}


def summary(state, *, owner=None):
    """Project only generated local labels and safe counts; unbound findings are operator-only."""
    observations = Counter(o.candidate_id for o in state.observations)
    evidence_counts = Counter(e.candidate_id for e in state.evidence)
    pending_credentials = Counter(i.candidate_id for i in state.credentials if i.unresolved)
    pending_registrations = Counter(
        a.candidate_id
        for a in state.registrations
        if a.state in {"prepared", "submitted", "uncertain", "conflict"}
    )
    receipts = {}
    for evidence in state.evidence:
        receipts.setdefault(evidence.candidate_id, []).append(
            {
                "evidence_id": str(evidence.evidence_id),
                "kind": evidence.kind,
                "outcome": evidence.outcome,
                "provenance": evidence.provenance,
                "reviewed": evidence.reviewed_at is not None,
            }
        )
    candidates = []
    for candidate in state.candidates:
        if owner is not None and (
            candidate.binding is None
            or owner != (candidate.binding.owner_issuer, candidate.binding.owner_subject)
        ):
            continue
        candidates.append(
            {
                "candidate_id": str(candidate.candidate_id),
                "case_id": str(candidate.case_id),
                "alias": candidate.alias,
                "state": candidate.state,
                "revision": candidate.revision,
                "generation": candidate.generation,
                "created_at": candidate.created_at.isoformat(),
                "reason_code": candidate.reason
                if candidate.reason != "ok"
                else "creation_uncertain"
                if pending_registrations[candidate.candidate_id]
                else "issuance_unresolved"
                if pending_credentials[candidate.candidate_id]
                else "ok",
                "pending_credentials": pending_credentials[candidate.candidate_id],
                "observations": observations[candidate.candidate_id],
                "evidence": evidence_counts[candidate.candidate_id],
                **({"receipts": receipts.get(candidate.candidate_id, [])} if owner is None else {}),
            }
        )
    result = {"schema_version": 1, "revision": state.revision, "candidates": candidates}
    if owner is None:
        result["attempts"] = [
            {
                "attempt_id": str(getattr(a, "intent_id", getattr(a, "attempt_id", ""))),
                "candidate_id": str(a.candidate_id),
                "kind": getattr(a, "kind", "registration"),
                "state": a.state,
                "reason_code": a.reason,
            }
            for a in (*state.credentials, *state.registrations)
        ]
    return result


def closeout(state, candidate_id):
    """Evaluate all seven tests independently using latest current correlated evidence."""
    candidate = next((c for c in state.candidates if c.candidate_id == candidate_id), None)
    require(candidate is not None)
    implementation = implementation_revision()
    binding = binding_digest(candidate.binding)
    relevant = [
        e
        for e in state.evidence
        if e.candidate_id == candidate_id
        and e.case_id == candidate.case_id
        and e.generation == candidate.generation
        and e.environment == state.environment
        and e.implementation == implementation
        and e.binding_digest == binding
    ]
    latest = {}
    for evidence in sorted(relevant, key=lambda e: e.received_at):
        latest[evidence.kind] = evidence
    tests = []
    for test_id, kinds in TESTS.items():
        reason, outcome = "ok", "pass"
        for kind in kinds:
            evidence = latest.get(kind)
            if evidence is None:
                outcome, reason = (
                    "blocked",
                    "audit_unavailable" if kind == "audit" else "native_evidence_missing",
                )
                break
            # Tamper tests are intentionally synthetic; their real unauthenticated
            # mint/control companion is native. No other path accepts fixtures.
            native = (
                kind == "verifier_negatives" and evidence.provenance == "synthetic"
            ) or evidence.provenance == "native"
            if not native or not evidence.reviewed_by or not evidence.reviewed_at:
                outcome, reason = "blocked", "native_evidence_missing"
                break
            if evidence.outcome != "pass":
                outcome, reason = evidence.outcome, "proof_inconclusive"
                break
            if (
                not evidence.independent
                or not evidence.attributed
                or (
                    kind
                    in {
                        "preregistration",
                        "obo_allowed",
                        "obo_beyond_ceiling",
                        "direct_allowed",
                        "direct_denied",
                        "unauthenticated_mint",
                    }
                    and not evidence.healthy
                )
            ):
                outcome, reason = "inconclusive", "proof_inconclusive"
                break
        if outcome == "pass" and test_id == "F11-T1":
            registration = next(
                (
                    a
                    for a in state.registrations
                    if a.candidate_id == candidate_id and a.state == "confirmed"
                ),
                None,
            )
            if (
                "registration" not in latest
                or latest["registration"].provenance != "native"
                or registration is None
                or not registration.submitted_at
                or not all(
                    before_registration(
                        latest[k], registration.submitted_at, latest["registration"].clock_bound
                    )
                    for k in kinds
                )
            ):
                outcome, reason = "blocked", "native_evidence_missing"
        if outcome == "pass":
            outcome, reason = extra_predicate(test_id, state, candidate, latest)
        tests.append(
            {
                "test_id": test_id,
                "outcome": outcome,
                "reason_code": reason,
                "next_action": ACTIONS.get(reason, ""),
            }
        )
    return {"schema_version": 1, "candidate_id": str(candidate_id), "tests": tests}


def extra_predicate(test_id, state, candidate, latest):
    """Apply test-specific causal links instead of equating receipt presence with proof."""
    blocked = ("blocked", "native_evidence_missing")
    inconclusive = ("inconclusive", "proof_inconclusive")
    registration = next(
        (
            a
            for a in state.registrations
            if a.candidate_id == candidate.candidate_id
            and a.generation == candidate.generation
            and a.state == "confirmed"
        ),
        None,
    )
    if (
        candidate.binding is None
        or registration is None
        or registration.binding_digest != binding_digest(candidate.binding)
    ):
        return blocked
    if test_id in {"F11-T1", "F11-T2"}:
        before, after = latest.get("preregistration"), latest.get("direct_allowed")
        if (
            not registration
            or not registration.submitted_at
            or not registration.finished_at
            or not before
        ):
            return blocked
        if (
            before.outcome != "pass"
            or before.provenance != "native"
            or not before.reviewed_by
            or not before.reviewed_at
            or not before.independent
            or not before.healthy
            or not before.attributed
        ):
            return inconclusive
        if test_id == "F11-T1":
            discovery = latest["discovery"]
            observation = next(
                (o for o in state.observations if o.observation_id == discovery.observation_id),
                None,
            )
            if (
                not observation
                or observation.provenance != "native"
                or observation.kind != "unknown"
                or observation.object != candidate.binding.source_object
                or observation.source_digest != discovery.source_digest
                or not before_registration(
                    before, registration.submitted_at, latest["registration"].clock_bound
                )
            ):
                return blocked
        if (
            test_id == "F11-T2"
            and candidate.binding.paths["preregistration"]
            != candidate.binding.paths["direct_allowed"]
        ):
            return inconclusive
        if (
            not before.facts
            or before.facts.status != 403
            or before.facts.control_status != 200
            or before.received_at >= registration.submitted_at
        ):
            return inconclusive
        if test_id == "F11-T2" and (
            not after
            or after.observed_at < registration.finished_at
            or not after.facts
            or after.facts.status != 200
            or after.facts.control_status != 200
        ):
            return inconclusive
    if test_id == "F11-T3":
        evidence = latest["identity"]
        proof = next(
            (
                v
                for v in state.verifications
                if evidence.facts and v.proof_id == evidence.facts.proof_id
            ),
            None,
        )
        if (
            not proof
            or proof.result != "pass"
            or proof.candidate_id != candidate.candidate_id
            or proof.generation != candidate.generation
            or not candidate.binding
            or proof.trust_digest != binding_digest(candidate.binding.trust)
        ):
            return blocked
        challenge = next(
            (c for c in state.challenges if c.challenge_id == proof.challenge_id), None
        )
        intent = next(
            (i for i in state.credentials if challenge and i.intent_id == challenge.intent_id), None
        )
        if (
            not challenge
            or not challenge.consumed
            or challenge.implementation != implementation_revision()
            or not intent
            or intent.kind != "svid"
            or intent.state != "confirmed"
            or intent.token_digest != proof.token_digest
            or evidence.attempt_id != intent.intent_id
            or intent.expires_at != proof.expires_at
        ):
            return blocked
    if test_id in {"F11-T4", "F11-T7"}:
        for kind in TESTS[test_id]:
            facts = latest[kind].facts
            expected = 403 if kind in {"obo_beyond_ceiling", "direct_denied"} else 200
            if (
                not facts
                or facts.status != expected
                or facts.control_status != 200
                or (kind.startswith("obo_") and facts.baseline_status != 200)
            ):
                return inconclusive
    if test_id == "F11-T5":
        evidence = latest["audit"]
        if (
            not registration
            or not evidence.observation_id
            or evidence.attempt_id != registration.attempt_id
            or not evidence.facts
            or not evidence.facts.vault_audit_digest
            or not evidence.facts.source_audit_digest
        ):
            return blocked
    if test_id == "F11-T6":
        evidence = latest["verifier_negatives"]
        if not evidence.facts or set(evidence.facts.negative_classes) != {
            "signature",
            "audience",
            "expiry",
            "trust",
            "entity",
        }:
            return blocked
    return "pass", "ok"


# Every closed failure has a concrete local command or provider setup/recheck; no raw
# provider message is used as browser help or a command's error explanation.
ACTIONS.update(
    {
        "not_initialized": "Run agent govern prepare once; keep established private state.",
        "invalid_input": "Check agent govern --help and the fixed private JSON schema, then rerun.",
        "sign_in_required": "Sign in again in the local workspace to view your governance cases.",
        "source_invalid": (
            "Compare the private event with the enrolled scalar selectors and size/time bounds."
        ),
        "replay_conflict": (
            "Inspect the original receipt; use a new provider event ID only for a "
            "genuinely new event."
        ),
        "registry_conflict": (
            "Ask the Vault owner to inspect the exact reserved entity/name; do not overwrite it."
        ),
        "review_stale": (
            "Run readiness, import/review current evidence, then create a new enrollment review."
        ),
        "creation_uncertain": (
            "Run govern reconcile for this candidate; import provider completion "
            "evidence and explicitly resolve the retained attempt."
        ),
        "bootstrap_mismatch": (
            "Ask the identity administrator to enable JWT access tokens with the "
            "exact actor subject, Vault audience and requested vault:path_access "
            "details; rerun readiness and the proof."
        ),
        "trust_unavailable": (
            "Have the Vault owner check the reviewed SPIFFE public discovery/JWKS "
            "URLs, role and signing algorithm; rerun readiness."
        ),
        "identity_rejected": (
            "Check the independently pinned issuer, SPIFFE subject, entity, "
            "audience and 300-second TTL; rerun identity after readiness."
        ),
        "capacity_exhausted": (
            "Resolve retained attempts and close expired cases; preserve unknown "
            "issuance and rerun after storage is available."
        ),
        "storage_error": (
            "Restore the original owner-only private installation from its complete "
            "backup; do not reset or edit the journal."
        ),
        "missing_authority": (
            "Prepare existing response/recovery anchors and the fixed governance "
            "credentials/draft; check the documented readiness prerequisites."
        ),
        "unsupported": "Use only commands and scenarios listed by agent govern --help.",
        "provider_denied": (
            "Have the provider owner grant the exact documented metadata/create "
            "capability to the isolated operator, then rerun readiness."
        ),
        "effect_uncertain": (
            "Inspect status for the retained attempt; reconcile/import completion "
            "evidence before any new effect."
        ),
        "challenge_invalid": (
            "Start the private relying service and run a fresh identity proof for "
            "the current registered generation."
        ),
        "closed": (
            "This case is locally archived. Prepare a separate case for new work; "
            "provider authority was not removed."
        ),
    }
)
assert set(ACTIONS) == REASONS - {"ok"}
