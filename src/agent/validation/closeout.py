"""Explicit, immutable private snapshots; no effects and no new acceptance authority."""

import time

from ..evidence import CRITERIA
from .catalog import load_catalog
from .importers import load_artifacts, load_transactions
from .models import (
    LIVE_CASES,
    CaseReference,
    CloseoutCase,
    CloseoutCriterion,
    CloseoutMember,
    CloseoutResult,
    CloseoutSnapshot,
    CriterionMember,
    DeploymentContext,
    Reason,
    ValidationRun,
    digest,
    implementation_revision,
)
from .report import read_bindings, rebuild_report
from .review import ReviewDecision
from .store import StoreError


def outcome(values):
    return next((v for v in ("interrupted", "fail", "blocked") if v in values), "pass")


def check_deadline(deadline):
    if time.monotonic() > deadline:
        raise StoreError("suite_timeout")


def collect(writer):
    run = ValidationRun.model_validate(writer.read_json("run.json"))
    if (
        run.validation_id.hex != writer.path.name.replace("-", "")
        or run.mode != "live"
        or run.suite not in {"live-database", "live-phone"}
        or any(s not in LIVE_CASES for s in run.selected)
    ):
        raise StoreError("invalid_selection")
    before = writer.inventory()
    report = rebuild_report(writer, persist=False)
    artifacts = []
    transactions = []
    bindings = []
    reasons = list(report.blockers)
    context = None
    try:
        bindings = read_bindings(writer)
        artifacts = load_artifacts(writer)
        transactions = load_transactions(writer)
    except ValueError as error:
        reasons.append(
            Reason(str(error)) if str(error) in Reason._value2member_map_ else Reason.schema_invalid
        )
    if "context.json" not in before:
        reasons.append(Reason.context_missing)
    else:
        try:
            context = DeploymentContext.model_validate(writer.read_json("context.json"))
            integrity = writer.read_json("integrity.json")
            required = {
                "context.json",
                "run.json",
                *(f"observation-{o.observation_id}.json" for o in report.scenarios),
            }
            if not required <= integrity.keys():
                reasons.append(Reason.digest_mismatch)
        except ValueError:
            reasons.append(Reason.digest_mismatch)
    if writer.inventory() != before:
        raise StoreError("input_changed")
    return dict(
        run=run,
        report=report,
        artifacts=artifacts,
        transactions=transactions,
        bindings=bindings,
        context=context,
        reasons=tuple(dict.fromkeys(reasons)),
        inventory=before,
    )


def case_evidence(data, observation):
    report = data["report"]
    bindings = data["bindings"]
    reasons = []
    if data["reasons"]:
        reasons.extend(data["reasons"])
    if report.delivery != "received":
        reasons.append(Reason.telemetry_receipt_missing)
    by_id = {c.operation_ref: c for c in report.correlations}
    own = [b for b in bindings if b.observation_id == observation.observation_id]
    if observation.scenario in {"phone-approved", "phone-denied"}:
        transactions = [
            t for t in data["transactions"] if t.observation_id == observation.observation_id
        ]
        expected = "approved" if observation.scenario == "phone-approved" else "denied"
        if len(transactions) != 1 or transactions[0].decision != expected:
            reasons.append(Reason.decision_unverified)
    else:
        vault = [b for b in own if b.source_kind == "vault"]
        credential = [b for b in vault if b.phase == "credential"]
        cleanup = [b for b in vault if b.phase == "cleanup"]
        if observation.scenario == "delegated-database-read":
            if not credential or not cleanup or observation.cleanup != "revoked":
                reasons.append(Reason.evidence_missing)
            elif not all(b.native_lease_id for b in credential + cleanup) or {
                b.native_lease_id for b in credential
            } != {b.native_lease_id for b in cleanup}:
                reasons.append(Reason.source_unsupported)
        elif len(credential) != 1 or credential[0].expected_outcome != "denied":
            reasons.append(Reason.evidence_missing)
        for b in credential + cleanup:
            c = by_id.get(b.operation_ref)
            if not c or c.status != "matched":
                reasons.append(c.reason if c and c.reason else Reason.evidence_missing)
    failures = {
        Reason.digest_mismatch,
        Reason.evidence_contradicted,
        Reason.forbidden_effect,
        Reason.telemetry_export_failed,
    }
    state = (
        "interrupted"
        if Reason.interrupted in reasons
        else "fail"
        if failures & set(reasons)
        else "blocked"
        if reasons
        else "pass"
    )
    return state, tuple(dict.fromkeys(reasons))


def assemble_closeout(items):
    contexts = {d["context"].digest for d in items.values() if d["context"]}
    global_reasons = []
    if len(contexts) > 1:
        global_reasons.append(Reason.context_mismatch)
    if any(not d["context"] for d in items.values()):
        global_reasons.append(Reason.context_missing)
    native = set()
    for d in items.values():
        for t in d["transactions"]:
            key = (t.source_instance, t.native_transaction_id)
            if key in native:
                global_reasons.append(Reason.evidence_contradicted)
            native.add(key)
    definitions = {s.label: s for suite in load_catalog().suites for s in suite.scenarios}
    cases = []
    for label in LIVE_CASES:
        found = [
            (run_id, d, o)
            for run_id, d in items.items()
            for o in d["report"].scenarios
            if o.scenario == label
        ]
        refs = tuple(
            CaseReference(validation_id=i, observation_id=o.observation_id) for i, d, o in found
        )
        if len(found) != 1:
            reason = Reason.selection_incomplete if not found else Reason.evidence_ambiguous
            cases.append(
                CloseoutCase(
                    scenario=label,
                    references=refs,
                    operational="blocked",
                    evidence="blocked",
                    reasons=(reason,),
                )
            )
            continue
        _, d, o = found[0]
        op = o.outcome
        local = list(global_reasons)
        if (
            o.scenario_revision != definitions[label].revision
            or Reason.review_stale in d["reasons"]
        ):
            local.append(Reason.review_stale)
        if op == "pass" and (
            {a.label for a in o.assertions} != set(definitions[label].expected_assertions)
            or any(
                a.outcome != "pass"
                or a.strength != "live"
                or a.forbidden_effects
                or a.effect_attempts != 1
                for a in o.assertions
            )
        ):
            op = "fail"
            local.append(Reason.effect_not_attempted)
        ev, reasons = case_evidence(d, o)
        local.extend(reasons)
        if label == "delegated-database-read" and o.cleanup != "revoked" and op == "pass":
            op = "fail"
            local.append(Reason.cleanup_failed)
        if label.startswith("phone-"):
            tx = [t for t in d["transactions"] if t.observation_id == o.observation_id]
            expected = "approved" if label == "phone-approved" else "denied"
            if not tx or any(t.decision != expected for t in tx):
                if op == "pass":
                    op = "blocked"
                local.append(Reason.decision_unverified)
        if local:
            ev = outcome(
                [
                    ev,
                    "fail"
                    if Reason.evidence_contradicted in local or Reason.digest_mismatch in local
                    else "blocked",
                ]
            )
        cases.append(
            CloseoutCase(
                scenario=label,
                references=refs,
                operational=op,
                evidence=outcome([op, ev]),
                cleanup=o.cleanup,
                reasons=tuple(dict.fromkeys(local)),
            )
        )
    criteria = []
    for criterion in CRITERIA:
        projections = []
        for i, d in items.items():
            current = next(c for c in d["report"].acceptance if c.criterion == criterion)
            reviews = [
                ReviewDecision.model_validate(d["writer"].read_json(p.name))
                for p in d["writer"].path.glob("review-*.json")
            ]
            applicable = [r for r in reviews if r.criterion == criterion]
            latest = (
                max(applicable, key=lambda r: (r.reviewed_at, str(r.review_id)))
                if applicable
                else None
            )
            projections.append(
                CriterionMember(
                    validation_id=i,
                    status=current.status,
                    reason=current.reason,
                    evidence_revision=current.evidence_revision,
                    review_id=latest.review_id
                    if latest and latest.expected_revision == current.evidence_revision
                    else None,
                )
            )
        criteria.append(CloseoutCriterion(criterion=criterion, members=tuple(projections)))
    content = dict(
        schema_version=1,
        members=tuple(
            CloseoutMember(
                validation_id=i,
                report_revision=d["report"].revision,
                input_revision=digest(d["inventory"]),
            )
            for i, d in items.items()
        ),
        cases=tuple(cases),
        criteria=tuple(criteria),
        operational=outcome([c.operational for c in cases]),
        evidence=outcome([c.evidence for c in cases]),
        blockers=tuple(dict.fromkeys(global_reasons)),
        unsupported="verify-events-linkage",
        unsupported_owner="integration_owner",
    )
    return CloseoutSnapshot(content_revision=digest(content), **content)


def markdown(snapshot):
    lines = [
        "# Live closeout",
        "",
        f"Snapshot: {snapshot.snapshot_id}",
        f"Revision: {snapshot.content_revision}",
        f"Operational: {snapshot.operational}",
        f"Evidence: {snapshot.evidence}",
        "",
        f"Created: {snapshot.created_at.isoformat()}",
        f"Blockers: {', '.join(snapshot.blockers)}",
        "",
        "| Run | Report revision | Input revision |",
        "| --- | --- | --- |",
        *(
            f"| {m.validation_id} | {m.report_revision} | {m.input_revision} |"
            for m in snapshot.members
        ),
        "",
        "| Case | References (run/observation) | Operational | Evidence | "
        "Cleanup | Reasons | Owner |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for c in snapshot.cases:
        refs = ", ".join(f"{r.validation_id}/{r.observation_id}" for r in c.references)
        lines.append(
            f"| {c.scenario} | {refs} | {c.operational} | {c.evidence} | "
            f"{c.cleanup} | {', '.join(c.reasons)} | {c.owner} |"
        )
    lines += [
        "",
        "| Criterion | Run | Review disposition | Reason | Review | Evidence revision |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for c in snapshot.criteria:
        lines.extend(
            f"| {c.criterion} | {m.validation_id} | {m.status} | {m.reason or ''} | "
            f"{m.review_id or ''} | {m.evidence_revision} |"
            for m in c.members
        )
    lines += [
        "",
        "Unsupported: verify-events-linkage; owner: integration_owner.",
        "No aggregate customer acceptance decision.",
        "",
    ]
    return "\n".join(lines).encode()


def create_closeout(store, run_ids):
    deadline = time.monotonic() + 30
    with store.open_many(run_ids) as writers:
        items = {}
        for i, w in writers.items():
            check_deadline(deadline)
            items[i] = collect(w) | {"writer": w}
        snapshot = assemble_closeout(items)
        check_deadline(deadline)
        for i, w in writers.items():
            if w.inventory() != items[i]["inventory"]:
                raise StoreError("input_changed")
        with store.create_closeout(snapshot.snapshot_id) as output:
            manifest = {
                "schema_version": 1,
                "implementation": implementation_revision(),
                "inputs": {str(i): d["inventory"] for i, d in items.items()},
                "contexts": {
                    str(i): d["context"].digest if d["context"] else None for i, d in items.items()
                },
                "snapshot_revision": snapshot.content_revision,
            }
            output.write_json("manifest.json", manifest)
            output.write_bytes("closeout.md", markdown(snapshot))
            check_deadline(deadline)
            for i, w in writers.items():
                if w.inventory() != items[i]["inventory"]:
                    raise StoreError("input_changed")
            output.write_json("closeout.json", snapshot)
    return CloseoutResult(snapshot=snapshot)


def inspect_closeout(store, snapshot_id):
    deadline = time.monotonic() + 30
    with store.open_closeout(snapshot_id) as output:
        snapshot = CloseoutSnapshot.model_validate(output.read_json("closeout.json"))
        manifest = output.read_json("manifest.json")
        if output.read_bytes("closeout.md") != markdown(snapshot):
            raise StoreError("digest_mismatch")
        if any(
            digest(manifest.get("inputs", {}).get(str(m.validation_id))) != m.input_revision
            for m in snapshot.members
        ):
            raise StoreError("digest_mismatch")
        if (
            str(snapshot.snapshot_id) != output.path.name
            or manifest["snapshot_revision"] != snapshot.content_revision
        ):
            raise StoreError("digest_mismatch")
    try:
        with store.open_many([m.validation_id for m in snapshot.members]) as writers:
            if set(manifest["inputs"]) != {str(i) for i in writers}:
                raise StoreError("digest_mismatch")
            items = {}
            for i, w in writers.items():
                check_deadline(deadline)
                current_inventory = w.inventory()
                saved_inventory = manifest["inputs"][str(i)]
                if set(saved_inventory) - set(current_inventory):
                    return CloseoutResult(
                        snapshot=snapshot, applicability="missing", reason=Reason.evidence_missing
                    )
                if implementation_revision() != manifest["implementation"]:
                    return CloseoutResult(
                        snapshot=snapshot, applicability="stale", reason=Reason.snapshot_stale
                    )
                try:
                    d = collect(w)
                except ValueError:
                    return CloseoutResult(
                        snapshot=snapshot, applicability="failed", reason=Reason.schema_invalid
                    )
                items[i] = d | {"writer": w}
                if (
                    Reason.digest_mismatch in d["reasons"]
                    or Reason.evidence_contradicted in d["reasons"]
                ):
                    return CloseoutResult(
                        snapshot=snapshot, applicability="failed", reason=Reason.digest_mismatch
                    )
                if current_inventory != saved_inventory:
                    return CloseoutResult(
                        snapshot=snapshot, applicability="stale", reason=Reason.snapshot_stale
                    )
                if manifest["contexts"].get(str(i)) != (
                    d["context"].digest if d["context"] else None
                ):
                    raise StoreError("digest_mismatch")
            if assemble_closeout(items).content_revision != snapshot.content_revision:
                raise StoreError("digest_mismatch")
            check_deadline(deadline)
            if any(w.inventory() != items[i]["inventory"] for i, w in writers.items()):
                raise StoreError("input_changed")
    except StoreError as error:
        if str(error) == "storage_error" and any(
            not (store.root / str(m.validation_id)).exists() for m in snapshot.members
        ):
            return CloseoutResult(
                snapshot=snapshot, applicability="missing", reason=Reason.evidence_missing
            )
        raise
    return CloseoutResult(snapshot=snapshot)
