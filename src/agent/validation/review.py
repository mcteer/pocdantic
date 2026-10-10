"""Explicit immutable local reviews, bound to unchanged evidence rather than free text."""

import json
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from ..evidence import CRITERIA, Evidence
from .models import Contract, Digest, Reason, now


class ReviewInput(Contract):
    reviewer: str = Field(min_length=1, max_length=128, repr=False)
    rationale: str = Field(min_length=1, max_length=2000, repr=False)
    expected_revision: Digest
    observed_at: datetime
    references: tuple[UUID, ...] = ()

    @field_validator("reviewer", "rationale")
    @classmethod
    def meaningful(cls, value):
        if not value.strip():
            raise ValueError("schema_invalid")
        return value

    @field_validator("references")
    @classmethod
    def unique(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("schema_invalid")
        return value


class ReviewDecision(ReviewInput):
    review_id: UUID = Field(default_factory=uuid4)
    validation_id: UUID
    criterion: str
    decision: Literal["pass", "fail", "blocked", "alternative"]
    reviewed_at: datetime = Field(default_factory=now)

    @field_validator("criterion")
    @classmethod
    def criterion_known(cls, value):
        if value not in CRITERIA:
            raise ValueError("schema_invalid")
        return value

    def public_json(self):
        return json.dumps({"review_id": str(self.review_id), "status": "applicable"})


# Unsupported criteria cannot be waived by choosing alternative or adding arbitrary references.
SUPPORTED = {
    "UC1-01": ("live-database", {"vault", "logfire"}),
    "UC1-05": ("live-database", {"vault", "logfire"}),
}


def eligible(criterion, report, run, artifacts, references, transactions=()):
    if criterion == "UC2-02":
        resolved = {t.artifact_id: t for t in transactions}
        return bool(
            run.mode == "live"
            and run.suite == "live-phone"
            and not report.blockers
            and references
            and all(ref in resolved for ref in references)
            and all(resolved[ref].decision == "approved" for ref in references)
            and all(
                s.scenario == "phone-approved" and s.outcome == "pass" for s in report.scenarios
            )
        )
    rule = SUPPORTED.get(criterion)
    if not rule or run.mode != "live" or run.suite != rule[0] or report.blockers:
        return False
    if not references or not all(
        s.outcome == "pass" and all(a.strength == "live" for a in s.assertions)
        for s in report.scenarios
    ):
        return False
    resolved = {a.artifact_id: a for a in artifacts}
    if any(ref not in resolved for ref in references):
        return False
    sources = {resolved[ref].manifest.source_kind for ref in references}
    matched = {ref for c in report.correlations if c.status == "matched" for ref in c.artifact_refs}
    return rule[1] <= sources and set(references) <= matched


def apply_review_records(writer, report, run, artifacts, bindings, transactions=()):
    records = []
    for path in sorted(writer.path.glob("review-*.json")):
        record = ReviewDecision.model_validate(writer.read_json(path.name))
        if record.validation_id != run.validation_id:
            raise ValueError("digest_mismatch")
        records.append(record)
    result = []
    for criterion in report.acceptance:
        relevant = [r for r in records if r.criterion == criterion.criterion]
        if not relevant:
            result.append(criterion)
            continue
        review = max(relevant, key=lambda r: (r.reviewed_at, str(r.review_id)))
        if review.expected_revision != criterion.evidence_revision:
            result.append(criterion.model_copy(update={"reason": Reason.review_stale}))
            continue
        if review.decision in {"pass", "alternative"} and not eligible(
            review.criterion, report, run, artifacts, review.references, transactions
        ):
            result.append(criterion.model_copy(update={"reason": Reason.evidence_missing}))
            continue
        # Compose with the existing customer evidence validator. Private text is never projected.
        Evidence(
            criterion=review.criterion,
            status=review.decision,
            owner="operator",
            reason=review.rationale,
            source="live" if review.decision in {"pass", "alternative"} else "none",
            references=[str(r) for r in review.references],
            reviewer=review.reviewer,
            observed_at=review.observed_at,
        )
        result.append(
            criterion.model_copy(
                update={
                    "status": review.decision,
                    "reason": None
                    if review.decision in {"pass", "alternative"}
                    else Reason.review_required,
                }
            )
        )
    return tuple(result)


def record_review(writer, criterion, decision, review):
    from .importers import load_artifacts, load_transactions
    from .models import ValidationRun
    from .report import read_bindings, rebuild_report

    if criterion not in CRITERIA:
        raise ValueError("schema_invalid")
    review = ReviewInput.model_validate(review)
    report = rebuild_report(writer, apply_reviews=False)
    current = next(c for c in report.acceptance if c.criterion == criterion)
    if (
        review.expected_revision != current.evidence_revision
        or Reason.digest_mismatch in report.blockers
    ):
        raise ValueError("review_stale")
    run = ValidationRun.model_validate(writer.read_json("run.json"))
    artifacts = load_artifacts(writer)
    transactions = load_transactions(writer)
    if decision in {"pass", "alternative"} and not eligible(
        criterion, report, run, artifacts, review.references, transactions
    ):
        raise ValueError("evidence_missing")
    record = ReviewDecision(
        **review.model_dump(),
        validation_id=run.validation_id,
        criterion=criterion,
        decision=decision,
    )
    # The run lock protects the final read-check-write; external edits still rechecked on reports.
    again = rebuild_report(writer, apply_reviews=False)
    if (
        next(c for c in again.acceptance if c.criterion == criterion).evidence_revision
        != review.expected_revision
    ):
        raise ValueError("review_stale")
    read_bindings(writer)
    writer.write_json(f"review-{record.review_id}.json", record)
    return record
