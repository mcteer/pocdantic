"""Immutable private readout cores and separately sealed, explicitly witnessed handoffs.

Raw originals and operator rationale remain outside bundles. Safe compiled summaries and
independently sanitized attachments are the only supporting material included in a core.
"""

from .assessment import applicability, combine
from .assessment import report as assessment_report
from .catalog import OWNERS, catalog, guide
from .models import (
    ROLES,
    Assessment,
    CorePackage,
    Handoff,
    Source,
    canonical,
    fresh_id,
    now,
    require,
    validate,
)
from .review import active_decisions, reviews, role_decisions, source_reviewed
from .sources import reject_secrets


def criterion_reviews(store, head, assessment_ref):
    """Select every applicable criterion/exception decision without hiding conflicts."""
    return [
        r
        for r in reviews(store, head)
        if r.kind in {"criterion", "exception"}
        and r.subject_id == assessment_ref.object_id
        and r.expected_digest == assessment_ref.seal_digest
    ]


def build(store, head, assessment_id):
    """Seal a safe reproducible core, including blocked rows for concrete gap review."""
    assessment_ref = store.ref(head, assessment_id, "assessment")
    assessment = validate(Assessment, store.read(head.dossier_id, assessment_ref))
    require(applicability(store, head, assessment) == "current", "review_stale")
    selected = criterion_reviews(store, head, assessment_ref)
    attachments, files = {}, {}
    all_reviews = reviews(store, head)
    for ref, payload in store.records(head, "source"):
        source = validate(Source, payload)
        if (
            source.format != "attachment-v1"
            or source.environment_digest != assessment.environment_digest
        ):
            continue
        applicable = active_decisions(all_reviews, "attachment", source.source_id, ref.seal_digest)
        if not applicable or any(r.decision != "approve" or not r.sanitized for r in applicable):
            continue
        raw = store.read_files(head.dossier_id, ref)["source.raw"]
        reject_secrets(raw)
        suffix = {"text/plain": "txt", "image/png": "png", "image/jpeg": "jpg"}[
            source.manifest.media_type
        ]
        files[f"attachment-{source.source_id}.{suffix}"] = raw
        attachments[str(source.source_id)] = ref.seal_digest
        selected.extend(applicable)
    dependencies = {
        str(r.review_id): store.ref(head, r.review_id, "review").seal_digest for r in selected
    }
    core = CorePackage(
        package_id=fresh_id(),
        assessment_id=assessment_id,
        assessment_digest=assessment_ref.seal_digest,
        environment_digest=assessment.environment_digest,
        created_at=now(),
        review_dependencies=dependencies,
        attachment_dependencies=attachments,
    )
    projection = assessment_report(store, head, assessment_id)
    matrix = "\n".join(
        f"| {row['criterion']} | {row['proof']} | {', '.join(row['owners'])} |"
        for row in projection["criteria"]
    )
    from .models import Measurement

    measurements = [
        {
            "measurement_id": str(value.measurement_id),
            "scenario": value.scenario,
            "outcome": value.outcome,
            "provenance": value.provenance,
            "counts": value.counts,
            "reason": value.reason,
        }
        for ref, payload in store.records(head, "measurement")
        if str(ref.object_id) in assessment.measurements
        for value in [validate(Measurement, payload)]
    ]
    files["measurements.json"] = canonical(
        {"measurements": measurements, "timing": assessment.timing}
    )
    files["gaps.md"] = (
        "# Required proof and owner rechecks\n\n"
        + "\n".join(
            f"{row['criterion']}: {row['proof']}. {row['action']}" for row in projection["criteria"]
        )
        + "\n"
    ).encode()
    files.update(
        {
            "criteria.md": (
                (
                    "# Original acceptance criteria\n\n| Criterion | Proof | Owners |\n| "
                    "--- | --- | --- |\n"
                )
                + matrix
                + "\n"
            ).encode(),
            "assessment.json": canonical(projection),
            "guides.json": canonical(guide()),
            "inventory.json": canonical(
                {
                    "schema_version": 1,
                    "environment_digest": assessment.environment_digest,
                    "catalog": catalog(),
                    "profiles": [
                        {
                            "profile_id": str(p.profile_id),
                            "product": p.product,
                            "schema_digest": p.schema_digest,
                            "capability_states": list(p.capabilities.values()),
                        }
                        for p in store.inventory(head).sources
                    ],
                }
            ),
            "evidence-index.json": canonical(
                {
                    "members": assessment.members,
                    "measurements": assessment.measurements,
                    "attachments": attachments,
                }
            ),
            "readout.md": (
                (
                    "Closeout readout\n\nSoftware checks establish workflow behavior. Na"
                    "tive proof and witness reviews remain separately required.\n\n"
                )
                + matrix
                + "\n"
            ).encode(),
            "reproduce.md": (
                b"Use agent closeout inspect and report for immutable verification. "
                b"Follow agent closeout guide for each use case and experiment. "
                b"No guide command runs automatically.\n"
            ),
            "reset.md": (
                b"Preserve source stores and uncertain cleanup. Inspect agent recover status "
                b"and agent respond status; follow their exact repair steps. "
                b"Do not delete evidence or replay effects.\n"
            ),
        }
    )
    return store.append(
        head.dossier_id, head.revision, "package", core, files, object_id=core.package_id
    )


def applicable_role_reviews(store, head, core_ref):
    """Bind signoff to the immutable core digest, keeping rejected records visible."""
    return active_decisions(
        reviews(store, head), "package", core_ref.object_id, core_ref.seal_digest
    )


def software_valid(store, head, assessment):
    """Require complete sealed two-profile software coverage for phase-gate acceptance."""
    from .sources import current_origin

    return any(
        source.origin_kind == "regression"
        and source.implementation_digest == assessment.implementation_digest
        and source.source_assessment.get("software_outcome") == "pass"
        and source.source_assessment.get("complete_catalog") is True
        and set(source.source_assessment.get("profiles", [])) == {"baseline", "restricted"}
        and current_origin(store, source) == "current"
        for _, payload in store.records(head, "source")
        for source in [validate(Source, payload)]
    )


def decisions(store, head, core, core_ref, assessment):
    """Apply original proof, explicit exceptions, source-backed witnesses and all five roles."""
    values = reviews(store, head)
    assessment_ref = store.ref(head, core.assessment_id, "assessment")
    role_values = applicable_role_reviews(store, head, core_ref)
    roles = role_decisions(role_values)
    if any(v in {"reject", "conflict"} for v in roles.values()):
        return "failed", roles
    exceptions = False
    unmet = False
    for row in assessment.rows:
        owners = set(OWNERS[row.criterion])
        ordinary = active_decisions(
            values, "criterion", core.assessment_id, assessment_ref.seal_digest, row.criterion
        )
        ordinary_roles = role_decisions(ordinary)
        if (
            any(v in {"reject", "conflict"} for v in ordinary_roles.values())
            or row.unsafe
            or row.proof == "fail"
        ):
            return "failed", roles
        if row.proof == "pass":
            if any(ordinary_roles[r] != "approve" for r in owners):
                unmet = True
        else:
            agreements = active_decisions(
                values, "exception", core.assessment_id, assessment_ref.seal_digest, row.criterion
            )
            agreed = role_decisions(agreements)
            required = owners | {"customer_security"}
            if (
                all(agreed[r] == "agree_exception" for r in required)
                and len({r.alternative for r in agreements}) == 1
            ):
                exceptions = True
            else:
                unmet = True
    counts = [assessment.tests.get("F13-T5"), assessment.tests.get("F13-T6")]
    if combine(counts) != "pass" or unmet or not software_valid(store, head, assessment):
        return "blocked", roles
    if any(roles[r] != "approve" for r in ROLES):
        return "ready_for_review", roles
    for review in role_values:
        if review.decision != "approve":
            continue
        witnessed = False
        for identifier in review.attestations:
            source = validate(
                Source, store.read(head.dossier_id, store.ref(head, identifier, "source"))
            )
            if not source_reviewed(store, head, source):
                continue
            witnessed |= any(
                f.kind == "witness"
                and f.values.witnessed_digest == core_ref.seal_digest
                and review.role in f.values.participants
                and f.values.meeting_at == review.observed_at
                for f in source.facts
            )
        if not witnessed:
            return "ready_for_review", roles
    return "accepted_with_exceptions" if exceptions else "accepted", roles


def report(store, head, package_id):
    """Verify bundles and return current applicability separately from historical decision."""
    ref = store.ref(head, package_id)
    require(ref.kind in {"package", "handoff"})
    payload = store.read(head.dossier_id, ref)
    final = validate(Handoff, payload) if ref.kind == "handoff" else None
    core_ref = store.ref(head, final.package_id, "package") if final else ref
    if final:
        require(core_ref.seal_digest == final.package_digest, "integrity_failed")
    core = validate(CorePackage, store.read(head.dossier_id, core_ref))
    assessed_ref = store.ref(head, core.assessment_id, "assessment")
    require(assessed_ref.seal_digest == core.assessment_digest, "integrity_failed")
    assessment = validate(Assessment, store.read(head.dossier_id, assessed_ref))
    for identifier, expected in {
        **core.review_dependencies,
        **core.attachment_dependencies,
    }.items():
        dependency = store.ref(head, identifier)
        require(dependency.seal_digest == expected, "integrity_failed")
        store.read_files(head.dossier_id, dependency)
    applicable = applicability(store, head, assessment)
    decision_head = head.model_copy(update={"inventory_id": assessment.inventory_id})
    status, roles = decisions(store, decision_head, core, core_ref, assessment)
    selected = criterion_reviews(store, head, assessed_ref)
    frozen_criterion_ids = {
        identifier
        for identifier in core.review_dependencies
        if store.read(head.dossier_id, store.ref(head, identifier, "review"))["kind"]
        in {"criterion", "exception"}
    }
    if frozen_criterion_ids != {str(r.review_id) for r in selected}:
        applicable = "historical"
    if final:
        current = {
            str(r.review_id): store.ref(head, r.review_id, "review").seal_digest
            for r in applicable_role_reviews(store, head, core_ref)
        }
        if final.review_dependencies != current:
            applicable = "historical"
    return {
        "schema_version": 1,
        "package_id": str(package_id),
        "core_id": str(core.package_id),
        "content_digest": ref.seal_digest,
        "assessment_id": str(core.assessment_id),
        "status": status,
        "recorded_status": final.recorded_status if final else status,
        "applicability": applicable,
        "roles": roles,
        "criteria": assessment_report(store, head, core.assessment_id)["criteria"],
        "tests": {
            **assessment.tests,
            **{
                f"F13-T{i}": "pass"
                if status in {"accepted", "accepted_with_exceptions"}
                else "blocked"
                for i in (1, 2, 3)
            },
        },
        "gates": {
            f"P4-G{i}": "pass" if status in {"accepted", "accepted_with_exceptions"} else "blocked"
            for i in range(1, 6)
        },
    }


def handoff(store, head, package_id):
    """Copy an unchanged core and applicable external signoffs into a newly sealed final record."""
    core_ref = store.ref(head, package_id, "package")
    core = validate(CorePackage, store.read(head.dossier_id, core_ref))
    result = report(store, head, package_id)
    selected = applicable_role_reviews(store, head, core_ref)
    dependencies = {
        str(r.review_id): store.ref(head, r.review_id, "review").seal_digest for r in selected
    }
    final = Handoff(
        handoff_id=fresh_id(),
        package_id=package_id,
        package_digest=core_ref.seal_digest,
        environment_digest=core.environment_digest,
        created_at=now(),
        review_dependencies=dependencies,
        recorded_status=result["status"],
    )
    files = {
        f"core-{name}": raw for name, raw in store.read_files(head.dossier_id, core_ref).items()
    }
    files["role-records.json"] = canonical([r.model_dump(mode="json") for r in selected])
    return store.append(
        head.dossier_id, head.revision, "handoff", final, files, object_id=final.handoff_id
    )
