"""Immutable aggregation of the four required live validation cases.

Closeout checks source linkage, execution context, cleanup, telemetry receipt, and
review separately. Inspecting a snapshot detects drift without rerunning effects or
rewriting the original result; unsupported acceptance remains blocked.
"""

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
    """Combine outcomes with interruption, failure, and blocked taking precedence over
    pass.
    """
    return next((v for v in ("interrupted", "fail", "blocked") if v in values), "pass")


def check_deadline(deadline):
    """Reject work after the bounded closeout computation deadline."""
    if time.monotonic() > deadline:
        raise StoreError("suite_timeout")


def collect(writer):
    """Rebuild selected live runs and verify context and input inventories without
    replaying effects.
    """
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
    """Project the required native cleanup, telemetry, and phone proof for one live case."""
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
    """Aggregate exactly one run per required live case and detect conflicting contexts or
    reuse.

    Keep operational results, source evidence, and reviewed acceptance separate;
    missing or unsupported proof remains explicit.
    """
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
    """Render a sanitized closeout projection without private source fields or reviewer
    prose.
    """
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
    """Lock member runs, recheck their inventories, and persist an immutable closeout
    snapshot.

    Publish the JSON manifest last so a partially written directory is not mistaken
    for a completed closeout.
    """
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
    """Verify a stored closeout and its members against current bytes and implementation.

    Report stale or changed evidence without modifying the snapshot or rerunning
    any provider operation.
    """
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


def provider_closeout(state, incident_id):
    """Assess all nine Function 10 paths independently without editing acceptance files.

    Disk-only evidence must bind the current installation, enrollment, implementation,
    incident and resource generation. Synthetic execution and HTTP acknowledgment cannot
    certify native enforcement. Missing source review, inventory or clock bounds remains
    blocked; a recent contradictory result remains a failure rather than disappearing
    behind an older successful observation.
    """
    from datetime import timedelta

    from agent.recovery.models import now
    from agent.response.providers.enrollment import digest as provider_digest
    from agent.response.providers.models import require
    from agent.response.providers.proof import PATHS
    from agent.response.providers.report import interval, loss_interval

    incident = next((i for i in state.incidents if i.incident_id == incident_id), None)
    require(incident is not None, "target_unknown")
    plan = next(
        (p for p in getattr(state, "provider_plans", ()) if p.incident_id == incident_id), None
    )
    policy = getattr(state, "enrollment", None)
    actions = [
        a for a in getattr(state, "provider_actions", ()) if plan and a.action_id in plan.action_ids
    ]
    probes = [
        p
        for p in getattr(state, "probe_acquisitions", ())
        if any(o.incident_id == incident_id for o in p.observations)
    ]
    observations = [
        o for a in (*actions, *probes) for o in a.observations if o.incident_id == incident_id
    ]
    current_digest = implementation_revision()

    def reviewed(observation):
        """Require fresh native review and all authority/revision correlations."""
        return bool(
            policy
            and observation.source == "native_evidence"
            and observation.reviewer
            and observation.reviewed_at
            and observation.reviewed_at <= now()
            and now() - timedelta(seconds=300) <= observation.observed_at <= now()
            and observation.implementation_digest == current_digest
            and observation.enrollment_digest == provider_digest(policy)
            and observation.installation_id == state.installation_id
            and observation.environment_digest == state.environment_digest
        )

    def latest(path, records=observations):
        """Preserve the latest contradiction regardless of which source reported it."""
        values = [o for o in records if o.path == path]
        return max(values, key=lambda o: o.observed_at) if values else None

    def proven(path, records=observations):
        """A path passes only with its latest independently proven native reviewed result."""
        value = latest(path, records)
        return bool(value and reviewed(value) and value.result == "proven")

    intake = latest("native_intake")
    native = bool(
        plan
        and plan.mode == "native"
        and policy
        and intake
        and proven("native_intake")
        and intake.event_digest == incident.payload_digest
        and intake.observed_at == incident.received_at
        and any(
            s.alias == incident.source
            and s.provenance == "native"
            and s.collector_digest
            and s.reviewed_by
            for s in policy.sources
        )
    )
    dynamic = all(proven(path) for path in ("dynamic_fresh", "dynamic_session")) and bool(probes)
    dynamic = dynamic and all(
        any(
            a.kind == "revoke_exact"
            and a.target_id == p.recovery_incident_id
            and a.status == "confirmed"
            for a in incident.actions
        )
        for p in probes
    )
    same = proven("same_jwt")
    user = all(proven(path) for path in ("tenant_user", "tenant_sessions", "notification"))
    static = all(proven(path) for path in ("static_old", "static_new"))
    security = [a for a in actions if a.kind != "notify_teams"]
    required_complete = bool(security) and all(
        a.state in {"acknowledged", "reconciled"}
        and all(proven(path, a.observations) for path in PATHS[a.kind])
        for a in security
    )
    timings = [loss_interval(state, plan, a) for a in security] if plan else []
    bounded = bool(timings) and all(t and t["upper_ms"] < 1800000 for t in timings)
    native_token = proven("native_token")
    root_peer = (
        incident.target.kind == "root_run"
        and native_token
        and all(
            a.binding.exclusive_tree and a.binding.root_run_id == incident.target.root_run_id
            for a in security
            if a.kind == "revoke_native_token"
        )
    )
    inventory_complete = bool(policy) and not any(
        a.state in {"intent", "submitted", "uncertain"}
        for a in getattr(state, "native_acquisitions", ())
    )
    inventory_complete = inventory_complete and not any(
        p.state not in {"cleaned", "denied_no_issuance"}
        and not (
            p.credential_class == "oauth_jwt"
            and p.state == "issued"
            and p.credential_digest
            and p.credential_expires_at
            and proven("fresh_issuance")
        )
        for p in getattr(state, "probe_acquisitions", ())
    )
    for acquisition in getattr(state, "native_acquisitions", ()):
        if acquisition.state == "bound":
            matches = [
                a
                for a in security
                if a.kind == "revoke_native_token"
                and a.binding.key() == acquisition.binding.key()
                and a.binding.generation == acquisition.binding.generation
            ]
            inventory_complete = (
                inventory_complete
                and bool(matches)
                and all(proven("native_token", a.observations) for a in matches)
            )
    needed = {
        "registration": {"block_registration"},
        "user": {"suspend_user", "revoke_user_sessions"},
        "static_role": {"rotate_static", "terminate_static_sessions"},
        "native_token": {"revoke_native_token"},
    }
    if policy:
        for binding in policy.bindings:
            if binding.enabled and binding.kind in needed:
                kinds = {
                    a.kind
                    for a in security
                    if a.binding.key() == binding.key()
                    and a.binding.generation == binding.generation
                }
                inventory_complete = inventory_complete and needed[binding.kind] <= kinds
    native_fresh_unverified = bool(policy and policy.native_login_mount)
    # OAuth exchange denial does not certify the separately configured native JWT
    # login role. Existing accessor proof alone cannot close that fresh path.
    definition = (
        not native_fresh_unverified
        and incident.target.kind == "definition"
        and required_complete
        and inventory_complete
        and plan is not None
        and not plan.missing_controls
    )
    old = latest("same_jwt")
    immediate_interval = (
        interval(
            incident.contained_at,
            old.observed_at,
            intake.clock_bound_seconds,
            old.clock_bound_seconds,
        )
        if old and intake
        else None
    )
    immediate = bool(
        same
        and old.credential_expires_at
        and old.observed_at < old.credential_expires_at
        and immediate_interval
        and immediate_interval["upper_ms"] <= 120000
    )
    predicates = (
        bool(actions) and any(a.state in {"acknowledged", "reconciled"} for a in actions),
        dynamic,
        same,
        user,
        static,
        bounded,
        root_peer,
        definition,
        immediate,
    )
    required_paths = (
        ("native_intake",),
        ("dynamic_fresh", "dynamic_session"),
        ("same_jwt",),
        ("tenant_user", "tenant_sessions", "notification"),
        ("static_old", "static_new"),
        (),
        ("native_token",),
        tuple(sorted({p for a in security for p in PATHS[a.kind]})),
        ("same_jwt",),
    )
    cases = []
    for index, predicate in enumerate(predicates, 1):
        paths = required_paths[index - 1]
        contradiction = native and any(
            latest(path) is not None and latest(path).result == "disproven" for path in paths
        )
        cases.append(
            {
                "case": f"F10-T{index}",
                "outcome": "fail"
                if contradiction
                else "pass"
                if native and predicate
                else "blocked",
                "reason_code": "provider_state_observed"
                if native and predicate
                else "source_evidence_missing"
                if not native
                else "proof_required",
                "paths": {
                    path: latest(path).result if latest(path) else "not_run" for path in paths
                },
                "limitations": (["upstream_sessions_unsupported"] if index == 4 else [])
                + (
                    ["native_login_fresh_issuance_unverified"]
                    if index == 8 and native_fresh_unverified
                    else []
                ),
            }
        )
    return {
        "schema_version": 1,
        "incident_id": str(incident_id),
        "cases": cases,
        "source_to_loss": timings,
        "acceptance_updated": False,
    }
