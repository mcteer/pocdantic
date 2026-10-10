"""Fixed public projections. Wider acceptance never follows from an offline pass."""

from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from ..evidence import CRITERIA
from .models import (
    Bounds,
    Contract,
    CorrelationResult,
    Digest,
    Label,
    Mode,
    Reason,
    ScenarioObservation,
    digest,
)


class Acceptance(Contract):
    criterion: Literal[
        "UC1-01",
        "UC1-02",
        "UC1-03",
        "UC1-04",
        "UC1-05",
        "UC2-01",
        "UC2-02",
        "UC2-03",
        "UC3-01",
        "UC3-02",
        "UC3-03",
        "UC3-04",
        "UC4-01",
        "UC4-02",
        "UC4-03",
    ]
    status: Literal["pass", "fail", "blocked", "alternative"] = "blocked"
    owner: Literal["operator", "reviewer"] = "reviewer"
    reason: Reason | None = Reason.review_required
    evidence_revision: Digest = "0" * 64


class ValidationReport(Contract):
    validation_id: UUID
    suite: Label
    suite_revision: Digest
    revision: Digest
    mode: Mode
    selected: int = Field(ge=1, le=32)
    completed: int = Field(ge=0, le=32)
    terminal: int = Field(ge=1, le=32)
    scenarios: tuple[ScenarioObservation, ...]
    acceptance: tuple[Acceptance, ...]
    bounds: Bounds
    duration: float = Field(ge=0, allow_inf_nan=False)
    blockers: tuple[Reason, ...] = ()
    correlations: tuple[CorrelationResult, ...] = ()
    delivery: Literal["disabled", "attempted", "acknowledged", "received", "failed", "unknown"]

    @model_validator(mode="after")
    def projections(self):
        if (
            len(self.scenarios) != self.selected
            or self.terminal != self.selected
            or len({s.scenario for s in self.scenarios}) != self.selected
            or sorted(a.criterion for a in self.acceptance) != sorted(CRITERIA)
        ):
            raise ValueError("schema_invalid")
        return self

    def exit_code(self, *, operational=False):
        outcomes = {s.outcome for s in self.scenarios}
        if "interrupted" in outcomes or Reason.interrupted in self.blockers:
            return 130
        if (
            "fail" in outcomes
            or Reason.digest_mismatch in self.blockers
            or any(c.outcome == "fail" for c in self.correlations)
            or Reason.telemetry_export_failed in self.blockers
        ):
            return 1
        effective = tuple(
            b
            for b in self.blockers
            if not operational
            or b
            not in {
                Reason.evidence_missing,
                Reason.evidence_ambiguous,
                Reason.evidence_outside_window,
                Reason.export_incomplete,
                Reason.source_unsupported,
                Reason.telemetry_receipt_missing,
            }
        )
        if "blocked" in outcomes or effective:
            return 2
        return 0


def assemble(
    run,
    observations,
    *,
    duration=0,
    blockers=(),
    delivery=None,
    correlations=(),
    evidence_inputs=None,
    acceptance=None,
):
    inputs = evidence_inputs or {"run": run, "observations": observations, "mapping_version": 1}
    evidence_revision = digest(inputs)
    criteria = tuple(
        Acceptance(
            criterion=c, evidence_revision=digest({"criterion": c, "evidence": evidence_revision})
        )
        for c in CRITERIA
    )
    value = dict(
        validation_id=run.validation_id,
        suite=run.suite,
        suite_revision=run.suite_revision,
        mode=run.mode,
        selected=len(run.selected),
        terminal=len(observations),
        completed=sum(s.outcome in {"pass", "fail"} for s in observations),
        scenarios=tuple(observations),
        acceptance=tuple(acceptance or criteria),
        bounds=run.bounds,
        duration=duration,
        blockers=tuple(dict.fromkeys(blockers)),
        correlations=tuple(correlations),
        delivery=delivery or ("disabled" if run.mode == "offline" else "unknown"),
    )
    revision = digest({"report": value, "evidence": evidence_revision})
    return ValidationReport(revision=revision, **value)


def markdown(report):
    lines = [
        "# Validation report",
        "",
        f"Run: {report.validation_id}",
        f"Suite: {report.suite}",
        f"Revision: {report.revision}",
        "",
        "| Scenario | Assertion | Cleanup | Operation |",
        "| --- | --- | --- | --- |",
    ]
    for s in report.scenarios:
        lines.append(
            f"| {s.scenario} | {s.outcome} | {s.cleanup} | {s.operation_outcome or 'blocked'} |"
        )
    lines += ["", "| Criterion | Disposition | Reason |", "| --- | --- | --- |"]
    lines.extend(f"| {a.criterion} | {a.status} | {a.reason or ''} |" for a in report.acceptance)
    lines += [
        "",
        "Customer acceptance requires unchanged live source evidence and explicit review.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def persist_report(writer, report):
    for name, raw in [
        (f"report-{report.revision}.json", report.model_dump_json().encode()),
        (f"report-{report.revision}.md", markdown(report)),
    ]:
        if not (writer.path / name).exists():
            writer.write_bytes(name, raw)
        elif writer.read_bytes(name) != raw:
            raise ValueError("digest_mismatch")
    writer.write_json("report.json", report, replace=True)
    writer.write_bytes("report.md", markdown(report), replace=True)


def evidence_inputs(writer, run, observations, artifacts, bindings):
    delivery = (
        writer.read_json("delivery.json")
        if (writer.path / "delivery.json").exists()
        else {"state": "disabled" if run.mode == "offline" else "unknown"}
    )
    from .models import implementation_revision

    return {
        "implementation": implementation_revision(),
        "run": run,
        "observations": observations,
        "bindings": bindings,
        "artifacts": artifacts,
        "delivery": delivery,
        "mapping_version": 1,
    }


def read_bindings(writer):
    from .models import PrivateOperationBinding
    from .store import decode_json

    if not (writer.path / "bindings.jsonl").exists():
        return ()
    latest = {}
    for line in writer.read_bytes("bindings.jsonl").splitlines():
        item = PrivateOperationBinding.model_validate(decode_json(line))
        latest[item.operation_ref] = item
    return tuple(latest.values())


def seal_execution(writer):
    import hashlib

    names = ["run.json", "events.jsonl", "bindings.jsonl", "delivery.json"]
    names += [p.name for p in writer.path.glob("observation-*.json")]
    values = {
        n: hashlib.sha256(writer.read_bytes(n)).hexdigest()
        for n in names
        if (writer.path / n).exists()
    }
    writer.write_json("integrity.json", values)


def rebuild_report(writer, *, apply_reviews=True):
    import hashlib
    from uuid import uuid5

    from .catalog import load_catalog
    from .correlation import correlate
    from .importers import load_artifacts, load_transactions
    from .models import ValidationRun
    from .store import StoreError

    run = ValidationRun.model_validate(writer.read_json("run.json"))
    blockers = [Reason.interrupted] if run.state != "finalized" else []
    if (writer.path / "integrity.json").exists():
        for name, expected in writer.read_json("integrity.json").items():
            try:
                if hashlib.sha256(writer.read_bytes(name)).hexdigest() != expected:
                    blockers.append(Reason.digest_mismatch)
            except StoreError:
                blockers.append(Reason.digest_mismatch)
    found = {}
    for path in writer.path.glob("observation-*.json"):
        value = ScenarioObservation.model_validate(writer.read_json(path.name))
        if (
            value.scenario in found
            or value.validation_id != run.validation_id
            or value.scenario not in run.selected
        ):
            blockers.append(Reason.digest_mismatch)
        found[value.scenario] = value
    catalog = load_catalog()
    suite = next((s for s in catalog.suites if s.label == run.suite), None)
    definitions = {s.label: s for s in suite.scenarios} if suite else {}
    if suite is None or suite.revision != run.suite_revision:
        blockers.append(Reason.review_stale)
    observations = []
    for label in run.selected:
        if label in found:
            observations.append(found[label])
        else:
            observations.append(
                ScenarioObservation(
                    observation_id=uuid5(run.validation_id, label),
                    validation_id=run.validation_id,
                    scenario=label,
                    scenario_revision=definitions[label].revision
                    if label in definitions
                    else run.suite_revision,
                    outcome="interrupted",
                    reason=Reason.interrupted,
                    started_at=run.created_at,
                    finished_at=run.completed_at or run.created_at,
                )
            )
    try:
        artifacts = load_artifacts(writer)
        transactions = load_transactions(writer)
    except StoreError:
        artifacts = []
        transactions = []
        blockers.append(Reason.digest_mismatch)
    bindings = read_bindings(writer)
    correlations = [correlate(b, artifacts) for b in bindings]
    if run.mode == "live":
        if run.suite == "live-database":
            vault = [
                c for b, c in zip(bindings, correlations, strict=True) if b.source_kind == "vault"
            ]
            if not vault:
                blockers.append(Reason.evidence_missing)
            blockers.extend(c.reason for c in vault if c.reason)
        elif run.suite == "live-phone":
            if not transactions:
                blockers.append(Reason.evidence_missing)
    inputs = evidence_inputs(writer, run, observations, artifacts, bindings)
    inputs["transactions"] = transactions
    duration = (
        max(0, (run.completed_at - run.created_at).total_seconds()) if run.completed_at else 0
    )
    delivery = inputs["delivery"]["state"]
    if delivery == "failed":
        blockers.append(Reason.telemetry_export_failed)
    telemetry_checks = [
        (b, c) for b, c in zip(bindings, correlations, strict=True) if b.source_kind == "logfire"
    ]
    attempted = {tuple(pair) for pair in inputs["delivery"].get("attempted", ())}
    bound = {(b.trace_id, b.span_id) for b, _ in telemetry_checks}
    receipt = bool(
        attempted and attempted == bound and all(c.status == "matched" for _, c in telemetry_checks)
    )
    if receipt:
        delivery = "received"
        blockers = [b for b in blockers if b != Reason.telemetry_receipt_missing]
    elif run.mode == "live" and run.suite == "live-database":
        blockers.append(Reason.telemetry_receipt_missing)
    report = assemble(
        run,
        observations,
        duration=duration,
        blockers=blockers,
        delivery=delivery,
        correlations=correlations,
        evidence_inputs=inputs,
    )
    if apply_reviews:
        from .review import apply_review_records

        acceptance = apply_review_records(writer, report, run, artifacts, bindings, transactions)
        report = assemble(
            run,
            observations,
            duration=duration,
            blockers=blockers,
            delivery=delivery,
            correlations=correlations,
            evidence_inputs=inputs,
            acceptance=acceptance,
        )
    persist_report(writer, report)
    return report
