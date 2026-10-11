"""Pure conservative assessment of original criteria and immutable applicability.

Source status strings cannot grant proof. Every compiled obligation needs reviewed native
facts with matching environment, scope and operation; contradictions dominate successes.
"""

import math

from .catalog import OWNERS, RULES, TEST_CRITERIA, catalog, guide
from .models import Assessment, CriterionRow, Obligation, Source, digest, fresh_id, now, validate
from .review import reviews, source_reviewed
from .store import runtime_digest


def timing_bounds(start, end, start_uncertainty, end_uncertainty):
    """Return conservative latency seconds, refusing unknown/inconsistent chronology."""
    if any(
        type(v) not in (float, int) or not math.isfinite(v) or not 0 <= v <= 5
        for v in (start_uncertainty, end_uncertainty)
    ):
        return None
    delta = (end - start).total_seconds()
    uncertainty = start_uncertainty + end_uncertainty
    if not math.isfinite(delta) or delta <= uncertainty:
        return None
    return delta - uncertainty, delta + uncertainty


def predicate(label, fact):
    """Check actual typed values for an obligation, never a claimed pass label."""
    kind, v = fact["kind"], fact["values"]
    result = v.get("result")
    if label == "same-jwt-invalid":
        return (
            kind == "jwt_validation" and result == "denied" and v.get("mechanism") == "jwt_invalid"
        )
    if label in {"sql-read", "child-read", "read-grants", "inside-ceiling"}:
        return kind == "operation_result" and v.get("operation") == "read" and result == "success"
    if label == "parent-write":
        return kind == "operation_result" and v.get("operation") == "write" and result == "success"
    if label in {"sql-write-denied", "outside-ceiling", "vault-policy-denied"}:
        return (
            kind == "operation_result"
            and result == "denied"
            and v.get("issued") == 0
            and (
                v.get("operation") == "write"
                if label == "sql-write-denied"
                else v.get("mechanism") == "policy_denied"
            )
        )
    if label == "zero-issuance":
        return kind == "operation_result" and result == "denied" and v.get("issued") == 0
    if label in {"exact-revoke", "automatic-secret-cleanup"}:
        return (
            kind == "cleanup_result"
            and v.get("action") in {"revoke", "rotate"}
            and v.get("after_result") == "denied"
            and v.get("outstanding") == 0
        )
    if label in {"approval-before-issue", "denied-zero-issue", "timeout-zero-issue"}:
        decision = {
            "approval-before-issue": "approve",
            "denied-zero-issue": "deny",
            "timeout-zero-issue": "timeout",
        }[label]
        return (
            kind == "approval_result"
            and v.get("decision") == decision
            and (
                v.get("issued", 0) > 0 and v.get("effects", 0) > 0 and bool(v.get("issuance_event"))
                if decision == "approve"
                else v.get("issued") == v.get("effects") == 0
            )
        )
    if label == "lineage-audit":
        return (
            kind == "lineage"
            and v.get("parent_ref") != v.get("child_ref")
            and bool(v.get("child_read_event"))
            and bool(v.get("parent_write_event"))
        )
    if label in {"automatic-session-revoke", "user-suspended", "teams-received"}:
        return (
            kind == "session_result"
            and v.get("existing_session") == v.get("new_session") == "denied"
            and v.get("action")
            == (
                "suspend"
                if label == "user-suspended"
                else "notify"
                if label == "teams-received"
                else "revoke"
            )
        )
    if label in {"absent-before", "native-discovery", "notification-before-enrollment"}:
        return kind == "discovery_result" and v.get("classification") == "unknown_agent"
    if label in {"independent-bootstrap", "native-svid", "independent-relying"}:
        return kind == "jwt_validation" and result == "success" and v.get("mechanism") == "unknown"
    if label == "entity-ceiling-binding":
        return (
            kind == "registration_result"
            and len({v.get("bootstrap_ref"), v.get("issuance_ref"), v.get("relying_ref")}) == 3
        )
    if label == "native-revocation-timing":
        if kind != "timing":
            return False
        from datetime import datetime

        if any(
            v.get(k) is None
            for k in ("trigger_at", "end_at", "trigger_uncertainty", "end_uncertainty")
        ):
            return False
        bounds = timing_bounds(
            datetime.fromisoformat(v["trigger_at"]),
            datetime.fromisoformat(v["end_at"]),
            v["trigger_uncertainty"],
            v["end_uncertainty"],
        )
        return bounds is not None and bounds[1] < 1800
    if label == "customer-receipt":
        return kind == "witness" and "customer_security" in v.get("participants", [])
    if label == "signed-obo-rar":
        return kind == "jwt_validation" and result == "success" and v.get("mechanism") == "unknown"
    if label == "lease-ttl":
        return (
            kind == "operation_result"
            and v.get("operation") == "issue"
            and result == "success"
            and v.get("issued") == 1
            and bool(v.get("lease_ref"))
            and v.get("ttl_seconds") is not None
            and 0 < v["ttl_seconds"] <= 900
        )
    if label == "scoped-issuance":
        return (
            kind == "operation_result"
            and v.get("operation") == "issue"
            and result == "success"
            and v.get("issued") == 1
        )
    if label == "complete-audit-index":
        return (
            kind == "operation_result"
            and v.get("operation") == "read"
            and result == "success"
            and v.get("issued") == 0
        )
    if label in {"deployed-secret-scan", "adapter-isolation", "no-permission-group"}:
        return (
            kind == "operation_result"
            and result == "success"
            and v.get("operation") == "read"
            and v.get("issued") == 0
            and (
                v.get("embedded_secrets") == 0 and v.get("deployment_digest") is not None
                if label == "deployed-secret-scan"
                else v.get("adapter_isolated") is True and v.get("deployment_digest") is not None
                if label == "adapter-isolation"
                else v.get("permission_groups") == 0
            )
        )
    if label == "vault-human-actor-audit":
        return kind == "identity_mapping" and v.get("category") == "human"
    if label in {"native-user-risk", "native-secret-detection", "native-trigger"}:
        return (
            kind == "discovery_result"
            and v.get("classification")
            == {
                "native-user-risk": "user_compromise",
                "native-secret-detection": "secret_misuse",
                "native-trigger": "agent_compromise",
            }[label]
        )
    if label == "generation-after-check":
        return (
            kind == "cleanup_result"
            and v.get("after_result") == "denied"
            and v.get("outstanding") == 0
        )
    return False


def correlated(label, fact, facts, products=None):
    """Require referenced events to exist in the same exact correlated operation."""
    v = fact.values
    references = {
        "approval-before-issue": [v.decision_event, v.issuance_event],
        "lineage-audit": [v.child_read_event, v.parent_write_event],
        "notification-before-enrollment": [
            v.absent_event,
            v.activity_event,
            v.finding_event,
            v.notification_ref,
            v.registration_event,
        ],
        "native-revocation-timing": [v.trigger_event, v.end_event],
    }.get(label, [])
    events = {f.source_event_id: f for f in facts if f.correlation == fact.correlation}
    if any(ref not in events for ref in references):
        return False
    if label == "approval-before-issue":
        issued = events[v.issuance_event]
        return (
            events[v.decision_event].occurred_at < issued.occurred_at
            and issued.kind == "operation_result"
            and issued.values.operation == "issue"
            and issued.values.issued == v.issued
            and issued.values.request_digest == v.action_digest
            and issued.values.scope_digest == v.parameters_digest
            and v.resource_digest == digest(fact.correlation.resource)
            and v.requester_digest
            == digest({"actor": fact.correlation.actor, "subject": fact.correlation.subject})
            and any(
                f.kind == "operation_result"
                and f.values.operation == "write"
                and f.values.result == "success"
                and f.correlation == fact.correlation
                and f.values.request_digest == v.action_digest
                and f.occurred_at >= issued.occurred_at
                for f in facts
            )
        )
    if label in {"denied-zero-issue", "timeout-zero-issue"}:
        return any(
            f.kind == "operation_result"
            and f.values.result == "denied"
            and f.values.issued == 0
            and f.correlation == fact.correlation
            and f.values.request_digest == v.action_digest
            and products
            and products.get(f.fact_id) == "vault"
            for f in facts
        )
    if label == "notification-before-enrollment":
        return (
            events[v.absent_event].occurred_at
            < events[v.finding_event].occurred_at
            <= events[v.notification_ref].occurred_at
            < events[v.registration_event].occurred_at
        )
    if label == "native-revocation-timing":
        return (
            events[v.trigger_event].occurred_at == v.trigger_at
            and events[v.end_event].occurred_at == v.end_at
        )
    if label in {"same-jwt-invalid", "signed-obo-rar"}:
        if (
            v.expires_at <= fact.occurred_at
            or not fact.correlation.subject
            or not fact.correlation.actor
        ):
            return False
        if v.subject_ref != fact.correlation.subject:
            return False
    if label == "lease-ttl":
        return any(
            f.kind == "cleanup_result"
            and f.values.lease_ref == v.lease_ref
            and f.correlation == fact.correlation
            for f in facts
        )
    if label in {"independent-bootstrap", "native-svid", "independent-relying"}:
        return (
            v.subject_ref == fact.correlation.actor
            and v.expires_at > fact.occurred_at
            and (v.expires_at - fact.occurred_at).total_seconds() <= 300
        )
    if label == "entity-ceiling-binding":
        refs = [v.bootstrap_ref, v.issuance_ref, v.relying_ref]
        if any(ref not in events for ref in refs):
            return False
        bootstrap, svid, relying = [events[ref] for ref in refs]
        return (
            all(
                f.kind == "jwt_validation" and f.values.result == "success"
                for f in (bootstrap, svid, relying)
            )
            and svid.values.token_digest
            == relying.values.token_digest
            != bootstrap.values.token_digest
            and svid.values.verifier_ref != relying.values.verifier_ref
            and bootstrap.occurred_at <= svid.occurred_at <= relying.occurred_at
            and v.entity_ref == fact.correlation.actor
        )
    if label == "lineage-audit":
        return (
            v.parent_policy != v.child_policy
            and events[v.child_read_event].values.operation == "read"
            and events[v.child_read_event].values.result == "success"
            and events[v.child_read_event].values.policy_digest == v.child_policy
            and events[v.parent_write_event].values.operation == "write"
            and events[v.parent_write_event].values.result == "success"
            and events[v.parent_write_event].values.policy_digest == v.parent_policy
        )
    if label in {"scoped-issuance", "vault-human-actor-audit"}:
        return bool(
            fact.correlation.actor
            and fact.correlation.subject
            and fact.correlation.actor != fact.correlation.subject
        )
    if label in {"automatic-session-revoke", "user-suspended", "teams-received"}:
        trigger = events.get(v.automatic_event)
        return (
            trigger is not None
            and trigger.kind == "discovery_result"
            and trigger.values.classification == "user_compromise"
            and trigger.occurred_at < fact.occurred_at
            and not any(
                f.kind == "approval_result"
                and trigger.occurred_at <= f.occurred_at <= fact.occurred_at
                for f in events.values()
            )
        )
    if label in {"generation-after-check", "automatic-secret-cleanup"}:
        return bool(fact.correlation.generation and fact.correlation.resource)
    return True


def proof_sources(store, head):
    """Load complete selected source history; witnesses/attachments do not stale proof."""
    env = digest(store.inventory(head))
    return [
        (ref, validate(Source, payload))
        for ref, payload in store.records(head, "source")
        if ref.environment_digest == env
        and payload["format"] != "attachment-v1"
        and not (
            payload.get("facts")
            and all(
                f["kind"] == "witness"
                and f["values"]["witnessed_digest"]
                in {r.seal_digest for r in head.records if r.kind == "package"}
                for f in payload["facts"]
            )
        )
    ]


def member_coverage(sources):
    """Map only obligations already established by maintained pure native reducers."""
    coverage = {}
    governance = {
        "F11-T1": ("absent-before", "native-discovery", "notification-before-enrollment"),
        "F11-T3": ("independent-bootstrap", "native-svid", "independent-relying"),
        "F11-T2": ("entity-ceiling-binding",),
        "F11-T7": ("inside-ceiling", "outside-ceiling"),
    }
    response = {
        "F10-T2": ("exact-revoke",),
        "F10-T4": ("user-suspended", "teams-received"),
        "F10-T5": ("automatic-secret-cleanup", "generation-after-check"),
        "F10-T6": ("native-revocation-timing",),
    }
    for source in sources:
        if source.origin_kind == "validation":
            for row in source.source_assessment.get("acceptance", []):
                if row.get("criterion") == "UC1-05" and row.get("status") in {"pass", "fail"}:
                    coverage.setdefault("vault-human-actor-audit", []).append(
                        (source.source_id, row["status"])
                    )
        if source.origin_kind not in {"governance", "response"}:
            continue
        mapping = governance if source.origin_kind == "governance" else response
        field, key = (
            ("tests", "test_id") if source.origin_kind == "governance" else ("cases", "case")
        )
        for row in source.source_assessment.get(field, []):
            if row.get("outcome") not in {"pass", "fail"}:
                continue
            for label in mapping.get(row.get(key), ()):
                coverage.setdefault(label, []).append((source.source_id, row["outcome"]))
    return coverage


def combine(outcomes):
    """Fail dominates blocked, and pass requires every independent obligation."""
    return "fail" if "fail" in outcomes else "blocked" if "blocked" in outcomes else "pass"


def assemble(store, head):
    """Freeze all fifteen rows without mutating sources or renewing captured freshness."""
    inv = store.inventory(head)
    sources = proof_sources(store, head)
    decisions = reviews(store, head)
    eligible = [
        s
        for _, s in sources
        if s.implementation_digest == runtime_digest()
        and source_reviewed(store, head, s, decisions)
    ]
    from .sources import profile_for

    label_products = {
        "deployed-secret-scan": {"application"},
        "adapter-isolation": {"application"},
        "same-jwt-invalid": {"verify"},
        "signed-obo-rar": {"verify"},
        "lease-ttl": {"vault"},
        "independent-bootstrap": {"verify"},
        "native-svid": {"vault"},
        "independent-relying": {"application"},
        "vault-human-actor-audit": {"vault"},
        "vault-policy-denied": {"vault"},
        "zero-issuance": {"vault"},
        "outside-ceiling": {"vault"},
        "inside-ceiling": {"vault"},
        "native-user-risk": {"vip"},
        "native-secret-detection": {"vip"},
        "native-discovery": {"vip"},
        "customer-receipt": {"customer"},
    }
    facts = [
        f
        for s in eligible
        for f in s.facts
        if profile_for(inv, s.profile_id).product
        in label_products.get(
            f.obligation, {"vault", "verify", "vip", "logfire", "application", "customer"}
        )
        and (
            f.obligation not in {"vault-human-actor-audit", "complete-audit-index", "lineage-audit"}
            or profile_for(inv, s.profile_id).capabilities.get("audit") == "supported"
        )
        and (
            f.obligation not in {"deployed-secret-scan", "adapter-isolation"}
            or f.values.deployment_digest == inv.implementation_digest
        )
        and (
            f.kind != "operation_result"
            or f.values.policy_digest in {p.digest for p in inv.policies}
            and f.values.scope_digest in {d.digest for d in inv.datasets}
        )
    ]
    products = {
        f.fact_id: profile_for(inv, s.profile_id).product for s in eligible for f in s.facts
    }
    # Separate scopes cannot be assembled into one apparently complete demonstration.
    contexts = {
        (
            f.correlation.scope,
            f.correlation.actor,
            f.correlation.subject,
            f.correlation.resource,
            f.correlation.generation,
        )
        for f in facts
    }
    contexts |= {(s.scope, None, None, None, None) for s in eligible}

    native_coverage = member_coverage(eligible)
    rows = []
    for criterion, labels in RULES.items():
        obligations = []
        unsafe = any(
            f.kind == "cleanup_result" and f.values.outstanding > 0
            for f in facts
            if f.obligation in labels
        )
        unsafe |= any(
            s.source_assessment.get("cleanup_outstanding") is True
            for s in eligible
            if criterion.startswith(
                "UC3"
                if s.origin_kind == "response"
                else "UC4"
                if s.origin_kind == "governance"
                else "unsupported"
            )
        )
        for label in labels:
            matches = [f for f in facts if f.obligation == label]
            passing = [
                f
                for f in matches
                if predicate(label, f.model_dump(mode="json"))
                and correlated(label, f, facts, products)
            ]
            failed = any(
                f.kind == "cleanup_result"
                and f.values.outstanding > 0
                or f.kind == "operation_result"
                and f.values.result == "success"
                and label in {"sql-write-denied", "outside-ceiling", "vault-policy-denied"}
                for f in matches
            )
            failed = failed or any(
                f.kind == "approval_result"
                and label in {"denied-zero-issue", "timeout-zero-issue"}
                and (f.values.issued > 0 or f.values.effects > 0)
                or f.kind == "jwt_validation"
                and label == "same-jwt-invalid"
                and f.values.result == "success"
                for f in matches
            )
            inherited = native_coverage.get(label, [])
            failed = failed or any(outcome == "fail" for _, outcome in inherited)
            outcome = (
                "fail"
                if failed
                else "pass"
                if passing or any(outcome == "pass" for _, outcome in inherited)
                else "blocked"
            )
            obligations.append(
                Obligation(
                    label=label,
                    outcome=outcome,
                    references=[f.fact_id for f in matches]
                    + [identifier for identifier, _ in inherited],
                    reason=None
                    if outcome == "pass"
                    else "evidence_conflict"
                    if failed
                    else "evidence_missing",
                )
            )
        proof = "fail" if unsafe else combine([o.outcome for o in obligations])
        if proof == "pass" and not any(
            all(
                any(
                    f.obligation == label
                    and (
                        f.correlation.scope,
                        f.correlation.actor,
                        f.correlation.subject,
                        f.correlation.resource,
                        f.correlation.generation,
                    )
                    == context
                    and predicate(label, f.model_dump(mode="json"))
                    and correlated(label, f, facts, products)
                    for f in facts
                )
                or any(
                    s.scope == context[0]
                    and any(
                        identifier == s.source_id and outcome == "pass"
                        for identifier, outcome in native_coverage.get(label, [])
                    )
                    for s in eligible
                )
                for label in labels
            )
            for context in contexts
        ):
            proof = "blocked"
        rows.append(
            CriterionRow(
                criterion=criterion,
                owners=OWNERS[criterion],
                operation=proof,
                proof=proof,
                obligations=obligations,
                unsafe=unsafe,
                reason=None
                if proof == "pass"
                else "cleanup_outstanding"
                if unsafe
                else "proof_incomplete",
            )
        )
    by_id = {r.criterion: r.proof for r in rows}
    measurements = {
        str(ref.object_id): ref.seal_digest
        for ref, _ in store.records(head, "measurement")
        if ref.environment_digest == digest(inv)
    }
    tests = {
        key: combine([by_id[c] for c in criteria]) if criteria else "blocked"
        for key, criteria in TEST_CRITERIA.items()
    }
    # Counting completion is independently assessed; merely having four files is insufficient.
    from .counting import latest_outcomes

    count_outcomes = latest_outcomes(store, head)
    tests["F13-T4"] = "pass"
    tests["F13-T5"] = count_outcomes["agent-repeat"]
    tests["F13-T6"] = combine([v for k, v in count_outcomes.items() if k != "agent-repeat"])
    # A bare assessment has neither its core nor a witnessed owner decision.
    # Those gates can only become fulfilled in the separately verified package.
    gates = {
        **{f"P4-G{i}": "blocked" for i in range(1, 5)},
        "P4-G5": combine(list(count_outcomes.values())),
    }
    intervals = [
        timing_bounds(
            f.values.trigger_at,
            f.values.end_at,
            f.values.trigger_uncertainty,
            f.values.end_uncertainty,
        )
        for f in facts
        if f.kind == "timing" and correlated("native-revocation-timing", f, facts, products)
    ]
    intervals = [value for value in intervals if value is not None]
    for source in eligible:
        if source.origin_kind == "response":
            intervals.extend(
                (v["lower_ms"] / 1000, v["upper_ms"] / 1000)
                for v in source.source_assessment.get("source_to_loss", [])
                if isinstance(v, dict)
                and all(
                    type(v.get(k)) in (int, float) and math.isfinite(v[k]) and v[k] >= 0
                    for k in ("lower_ms", "upper_ms")
                )
            )
    timing = (
        {
            "UC3-04-lower-ms": min(v[0] for v in intervals) * 1000,
            "UC3-04-upper-ms": max(v[1] for v in intervals) * 1000,
        }
        if intervals
        else {}
    )
    assessment = Assessment(
        assessment_id=fresh_id(),
        environment_digest=digest(inv),
        inventory_id=head.inventory_id,
        implementation_digest=runtime_digest(),
        catalog_digest=digest(catalog()),
        evaluated_at=now(),
        members={str(ref.object_id): ref.seal_digest for ref, _ in sources},
        rows=rows,
        tests=tests,
        gates=gates,
        measurements=measurements,
        review_dependencies=source_decisions(store, head, sources),
        timing=timing,
    )
    return store.append(
        head.dossier_id, head.revision, "assessment", assessment, object_id=assessment.assessment_id
    )


def source_decisions(store, head, sources):
    """Fingerprint only source eligibility decisions; criterion signoff cannot stale itself."""
    ids = {s.source_id for _, s in sources} | {s.profile_id for _, s in sources}
    return {
        str(r.review_id): store.ref(head, r.review_id, "review").seal_digest
        for r in reviews(store, head)
        if r.kind in {"source", "source-profile"} and r.subject_id in ids
    }


def applicability(store, head, assessment):
    """Preserve historical snapshots while refusing changed environment/code/source sets."""
    if (
        assessment.environment_digest != digest(store.inventory(head))
        or assessment.implementation_digest != runtime_digest()
        or assessment.catalog_digest != digest(catalog())
    ):
        return "historical"
    sources = proof_sources(store, head)
    if assessment.members != {str(ref.object_id): ref.seal_digest for ref, _ in sources}:
        return "historical"
    if assessment.review_dependencies != source_decisions(store, head, sources):
        return "historical"
    from .sources import current_origin

    for ref, source in sources:
        store.read_files(head.dossier_id, ref)
        origin_status = current_origin(store, source)
        if origin_status != "current":
            return origin_status
    measurements = {
        str(ref.object_id): ref.seal_digest
        for ref, _ in store.records(head, "measurement")
        if ref.environment_digest == assessment.environment_digest
    }
    return "current" if measurements == assessment.measurements else "historical"


def report(store, head, assessment_id):
    """Return safe evidence-only projections with compiled owner actions and no private text."""
    value = validate(
        Assessment, store.read(head.dossier_id, store.ref(head, assessment_id, "assessment"))
    )
    applicable = applicability(store, head, value)
    status = (
        "failed"
        if any(r.proof == "fail" for r in value.rows)
        or "fail" in value.tests.values()
        or "fail" in value.gates.values()
        else "ready_for_review"
        if all(r.proof == "pass" for r in value.rows)
        else "blocked"
    )
    return {
        "schema_version": 1,
        "assessment_id": str(value.assessment_id),
        "applicability": applicable,
        "status": status,
        "criteria": [
            {
                "criterion": r.criterion,
                "proof": r.proof,
                "operation": r.operation,
                "owners": r.owners,
                "reason": r.reason,
                "action": guide(r.criterion[:3])["recheck"],
            }
            for r in value.rows
        ],
        "tests": value.tests,
        "gates": value.gates,
        "timing": value.timing,
    }
