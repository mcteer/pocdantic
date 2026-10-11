"""Digest-bound local attestations with explicit conflicts, role requirements and exceptions.

Reviewer labels record operator attestations, not authenticated identities. Eligibility is
computed from source evidence before criterion approval, and package signoff also requires an
actual witness reference. No review edits original criteria or provider state.
"""

from .catalog import OWNERS
from .models import ROLES, Review, Source, digest, fresh_id, now, require, validate

PRODUCT_ROLE = {
    "vault": "vault_owner",
    "verify": "verify_owner",
    "vip": "vip_owner",
    "application": "agent_engineering",
    "logfire": "agent_engineering",
    "customer": "customer_security",
}


def reviews(store, head):
    """Read all private decisions, retaining every rejected and superseded record."""
    return [validate(Review, payload) for _, payload in store.records(head, "review")]


def active_decisions(values, kind, subject_id, expected_digest, criterion=None):
    """Select exact applicable decisions without a silent latest-timestamp-wins rule."""
    selected = [
        v
        for v in values
        if v.kind == kind
        and str(v.subject_id) == str(subject_id)
        and v.expected_digest == expected_digest
        and v.criterion == criterion
    ]
    superseded = {v for r in selected for v in r.supersedes}
    return [v for v in selected if v.review_id not in superseded]


def role_decisions(values):
    """Reject unresolved role conflicts instead of hiding a rejection behind a new approval."""
    result = {}
    for role in ROLES:
        choices = {v.decision for v in values if v.role == role}
        result[role] = "conflict" if len(choices) > 1 else next(iter(choices), "missing")
    return result


def source_reviewed(store, head, source, values=None):
    """Require exact current source profile and independent extraction digests for native use."""
    from .sources import profile_for

    values = values if values is not None else reviews(store, head)
    profile = profile_for(store.inventory(head), source.profile_id)
    role = PRODUCT_ROLE[profile.product]
    p = role_decisions(
        active_decisions(values, "source-profile", profile.profile_id, digest(profile))
    )
    if source.origin_kind != "import":
        # Captured native reducers already enforce their own source review contracts;
        # inventory profile attestation is still required to join their deployment.
        return p[role] == "approve" and source.provenance == "native"
    ref = store.ref(head, source.source_id, "source")
    r = active_decisions(values, "source", source.source_id, ref.seal_digest)
    expected = digest(
        {
            "facts": [f.model_dump(mode="json") for f in source.facts],
            "normalized": source.normalized,
        }
    )
    r = [v for v in r if v.extraction_digest == expected]
    return (
        p[role] == "approve"
        and role_decisions(r)[role] == "approve"
        and source.provenance == "native"
        and source.manifest.complete
    )


def record(store, head, value):
    """Validate one typed attestation against immutable references before appending it."""
    from .models import Assessment, canonical
    from .sources import profile_for, reject_secrets

    reject_secrets(canonical(value))
    require(isinstance(value, dict) and "review_id" not in value and "reviewed_at" not in value)
    review = validate(
        Review, value | {"review_id": str(fresh_id()), "reviewed_at": now().isoformat()}
    )
    inv = store.inventory(head)
    for attestation in review.attestations:
        store.ref(head, attestation, "source")
    existing = reviews(store, head)
    for predecessor in review.supersedes:
        found = next((v for v in existing if v.review_id == predecessor), None)
        require(
            found is not None
            and found.kind == review.kind
            and found.role == review.role
            and found.subject_id == review.subject_id
            and found.criterion == review.criterion,
            "review_conflict",
        )
    if review.kind == "source-profile":
        profile = profile_for(inv, review.subject_id)
        require(review.expected_digest == digest(profile), "review_stale")
        require(review.role == PRODUCT_ROLE[profile.product])
    else:
        ref = store.ref(head, review.subject_id)
        require(ref.seal_digest == review.expected_digest, "review_stale")
        require(ref.environment_digest == digest(inv), "review_stale")
        if review.kind in {"source", "attachment"}:
            require(ref.kind == "source")
            source = validate(Source, store.read(head.dossier_id, ref))
            profile = profile_for(inv, source.profile_id)
            require(review.role == PRODUCT_ROLE[profile.product])
            if review.kind == "source":
                require(source.format != "attachment-v1")
                expected = digest(
                    {
                        "facts": [f.model_dump(mode="json") for f in source.facts],
                        "normalized": source.normalized,
                    }
                )
                require(review.extraction_digest == expected, "review_stale")
            else:
                require(source.format == "attachment-v1")
        elif review.kind in {"criterion", "exception"}:
            require(ref.kind == "assessment")
            assessment = validate(Assessment, store.read(head.dossier_id, ref))
            from .assessment import applicability

            require(applicability(store, head, assessment) == "current", "review_stale")
            row = next(r for r in assessment.rows if r.criterion == review.criterion)
            require(review.role in OWNERS[row.criterion] or review.role == "customer_security")
            if review.kind == "criterion" and review.decision == "approve":
                require(row.proof == "pass" and not row.unsafe, "proof_incomplete")
                evidence_ids = {
                    identifier
                    for obligation in row.obligations
                    for identifier in obligation.references
                }
                selected = [
                    validate(
                        Source, store.read(head.dossier_id, store.ref(head, identifier, "source"))
                    )
                    for identifier in review.attestations
                ]
                require(
                    any(
                        source.source_id in evidence_ids
                        or any(f.fact_id in evidence_ids for f in source.facts)
                        for source in selected
                    ),
                    "evidence_missing",
                )
            if review.kind == "exception":
                require(row.proof != "pass" and not row.unsafe, "cleanup_outstanding")
        else:
            require(ref.kind == "package")
            from .package import report

            result = report(store, head, ref.object_id)
            require(result["applicability"] == "current", "review_stale")
            if review.decision == "approve":
                require(review.witnessed is True, "witness_missing")
                sources = [
                    validate(Source, store.read(head.dossier_id, store.ref(head, att, "source")))
                    for att in review.attestations
                ]
                witnesses = [
                    f
                    for s in sources
                    if source_reviewed(store, head, s)
                    for f in s.facts
                    if f.kind == "witness"
                    and f.values.witnessed_digest == ref.seal_digest
                    and review.role in f.values.participants
                    and f.values.meeting_at == review.observed_at
                ]
                require(bool(witnesses), "witness_missing")
    return store.append(
        head.dossier_id, head.revision, "review", review, object_id=review.review_id
    )
