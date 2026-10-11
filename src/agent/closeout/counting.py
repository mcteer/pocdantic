"""Exact scoped native client reconciliation without running or provisioning a cohort.

Imports retain every row. Experiments precede external operations, and measurement separates
scenario cardinality from reused clients and incremental activity; it predicts no invoice.
"""

from datetime import datetime

from .models import (
    SCENARIOS,
    Activity,
    Execution,
    Experiment,
    ExperimentInput,
    Mapping,
    Measurement,
    MeasurementInput,
    Source,
    decode,
    digest,
    fresh_id,
    now,
    require,
    validate,
)
from .review import reviews, source_reviewed
from .sources import profile_for
from .store import runtime_digest


def parse_records(format_name, raw, manifest):
    """Parse bounded JSONL; reject unknown fields and conflicting first-use spellings."""
    lines = raw.splitlines()
    require(
        len(lines) <= 10000 and (lines or format_name == "vault-activity-v1"), "capacity_exceeded"
    )
    result = []
    for line in lines:
        require(0 < len(line) <= 65536, "capacity_exceeded")
        row = decode(line)
        if format_name == "vault-activity-v1":
            require(
                manifest is not None and manifest.first_use_field is not None, "source_unsupported"
            )
            field = manifest.first_use_field
            other = (
                "client_first_usage_time"
                if field == "client_first_used_time"
                else "client_first_used_time"
            )
            require(field in row and other not in row)
            row = {**row, "first_used_at": row[field]}
            del row[field]
            model = Activity
        else:
            model = Mapping if format_name == "entity-mapping-v1" else Execution
        result.append(validate(model, row).model_dump(mode="json"))
    return result


def reconcile(scenario, rows, baseline, final):
    """Validate exactly 100 executions and return independently expected count sets."""
    require(scenario in SCENARIOS and len(rows) == 100, "cohort_invalid")
    for field in (
        "execution_ref",
        "operation_ref",
        "issuance_ref",
        "trace_ref",
        "verification_ref",
    ):
        require(len({r[field] for r in rows}) == 100, "cohort_invalid")
    require(all(r["mode"] == scenario and r["result"] == "success" for r in rows), "cohort_invalid")
    agents = {r["agent_entity"] for r in rows if r["agent_entity"]}
    humans = {r["human_entity"] for r in rows if r["human_entity"]}
    subjects = {(r["issuer"], r["subject"]) for r in rows if r["issuer"] and r["subject"]}
    require(len(agents) == (0 if scenario == "direct-users" else 1), "cohort_invalid")
    require(len(subjects) == (0 if scenario == "agent-repeat" else 100), "cohort_invalid")
    require(
        len(humans) == (100 if scenario in {"agent-obo-users", "direct-users"} else 0),
        "cohort_invalid",
    )
    require(not agents & humans, "cohort_invalid")
    expected = agents | humans
    return {
        "scenario": len(expected),
        "observed": len(expected & final),
        "incremental": len(expected - baseline),
        "reused": len(expected & baseline),
        "missing": len(expected - final),
        "extra": len(final - baseline - expected),
        "unrelated": len(final - expected),
        "non_entity": 0,
    }


def source(store, head, identifier, format_name):
    """Resolve one current typed artifact and its exact sealed dependency."""
    ref = store.ref(head, identifier, "source")
    value = validate(Source, store.read(head.dossier_id, ref))
    require(value.environment_digest == digest(store.inventory(head)), "context_mismatch")
    require(value.format == format_name, "source_unsupported")
    return ref, value


def prepare_experiment(store, head, value):
    """Freeze pre-operation baseline, independently observed mappings and declared cohort."""
    request = validate(ExperimentInput, value)
    inv = store.inventory(head)
    profile = profile_for(inv, request.profile_id)
    baseline_ref, baseline = source(store, head, request.baseline_id, "vault-activity-v1")
    mapping_ref, mapping = source(store, head, request.mapping_id, "entity-mapping-v1")
    cohort_ref, cohort = source(store, head, request.cohort_id, "entity-mapping-v1")
    require(
        baseline.profile_id == profile.profile_id and profile.product == "vault", "context_mismatch"
    )
    require(
        baseline.manifest is not None
        and baseline.manifest.period_start == request.period_start
        and baseline.manifest.period_end == request.period_end
        and set(baseline.manifest.mounts) == set(request.mounts),
        "baseline_invalid",
    )
    require(
        all(s.observed_at <= s.captured_at <= now() for s in (baseline, mapping, cohort)),
        "baseline_invalid",
    )
    require(
        not any(
            payload["scenario"] == request.scenario
            for _, payload in store.records(head, "experiment")
        ),
        "cohort_invalid",
    )
    experiment = validate(
        Experiment,
        request.model_dump(mode="json")
        | {
            "experiment_id": str(fresh_id()),
            "prepared_at": now().isoformat(),
            "environment_digest": digest(inv),
            "baseline_digest": baseline_ref.seal_digest,
            "mapping_digest": mapping_ref.seal_digest,
            "cohort_digest": cohort_ref.seal_digest,
        },
    )
    return store.append(
        head.dossier_id, head.revision, "experiment", experiment, object_id=experiment.experiment_id
    )


def activity_set(artifact, profile, mounts):
    """Deduplicate exact client keys and reject inconsistent times or scope before counting."""
    seen = {}
    non_entity = set()
    for raw in artifact.normalized:
        row = validate(Activity, raw)
        require(
            row.namespace_id == profile.namespace
            or row.namespace_id.startswith(profile.namespace.rstrip("/") + "/"),
            "context_mismatch",
        )
        require(row.mount_accessor in mounts, "context_mismatch")
        key = (profile.cluster, row.namespace_id, row.client_type, row.client_id)
        require(key not in seen or seen[key] == row, "evidence_conflict")
        seen[key] = row
        if row.client_type != "entity":
            non_entity.add(key)
    return {key for key in seen if key[2] == "entity"}, non_entity


def measure(store, head, experiment_id, value):
    """Join mappings/operations/activity and publish conservative native measurement."""
    experiment_ref = store.ref(head, experiment_id, "experiment")
    experiment = validate(Experiment, store.read(head.dossier_id, experiment_ref))
    request = validate(MeasurementInput, value)
    inv = store.inventory(head)
    require(experiment.environment_digest == digest(inv), "context_mismatch")
    profile = profile_for(inv, experiment.profile_id)
    base_ref, baseline = source(store, head, experiment.baseline_id, "vault-activity-v1")
    final_ref, final = source(store, head, request.final_id, "vault-activity-v1")
    roster_ref, roster = source(store, head, request.roster_id, "execution-roster-v1")
    map_ref, mapping = source(store, head, request.mapping_id, "entity-mapping-v1")
    cohort_ref, cohort = source(store, head, experiment.cohort_id, "entity-mapping-v1")
    original_map_ref, original_mapping = source(
        store, head, experiment.mapping_id, "entity-mapping-v1"
    )
    require(base_ref.seal_digest == experiment.baseline_digest, "integrity_failed")
    for artifact in (roster, mapping, cohort, original_mapping):
        member_profile = profile_for(inv, artifact.profile_id)
        require(
            (
                member_profile.cluster,
                member_profile.namespace,
                member_profile.version,
                member_profile.edition,
            )
            == (profile.cluster, profile.namespace, profile.version, profile.edition),
            "context_mismatch",
        )
    fp = profile_for(inv, final.profile_id)
    require(
        (profile.cluster, profile.namespace, profile.version, profile.edition)
        == (fp.cluster, fp.namespace, fp.version, fp.edition),
        "context_mismatch",
    )
    require(
        final.manifest is not None
        and final.manifest.period_start == experiment.period_start
        and final.manifest.period_end == experiment.period_end
        and set(final.manifest.mounts) == set(experiment.mounts),
        "context_mismatch",
    )
    rows = [validate(Execution, row).model_dump(mode="json") for row in roster.normalized]
    base_keys, _ = activity_set(baseline, profile, experiment.mounts)
    final_keys, non_entity = activity_set(final, profile, experiment.mounts)
    counts = reconcile(
        experiment.scenario, rows, {k[3] for k in base_keys}, {k[3] for k in final_keys}
    )
    parsed = [validate(Mapping, row) for row in mapping.normalized]
    index = {(m.issuer, m.subject): m for m in parsed}
    require(len(index) == len(parsed), "evidence_conflict")
    old = {(r["issuer"], r["subject"]): r["entity_id"] for r in original_mapping.normalized}
    require(
        all(key not in old or old[key] == item.entity_id for key, item in index.items()),
        "evidence_conflict",
    )
    cohort_keys = {
        (r["issuer"], r["subject"]) for r in cohort.normalized if r["category"] == "human"
    }
    for row in rows:
        require(
            datetime.fromisoformat(row["occurred_at"].replace("Z", "+00:00"))
            > experiment.prepared_at,
            "baseline_invalid",
        )
        require(
            row["namespace_id"] == profile.namespace and row["mount_accessor"] in experiment.mounts,
            "context_mismatch",
        )
        if experiment.scenario != "agent-repeat":
            key = (row["issuer"], row["subject"])
            require(
                key in cohort_keys and key in index and index[key].category == "human",
                "cohort_invalid",
            )
            require(index[key].verification_ref == row["verification_ref"], "cohort_invalid")
            require(
                index[key].namespace_id == row["namespace_id"]
                and index[key].mount_accessor == row["mount_accessor"],
                "context_mismatch",
            )
            if row["human_entity"]:
                require(index[key].entity_id == row["human_entity"], "cohort_invalid")
        if row["agent_entity"]:
            require(
                any(
                    m.category == "agent"
                    and m.entity_id == row["agent_entity"]
                    and m.namespace_id == row["namespace_id"]
                    and m.mount_accessor == row["mount_accessor"]
                    and m.definition_ref
                    for m in parsed
                ),
                "cohort_invalid",
            )
    expected_keys = {
        (profile.cluster, r["namespace_id"], "entity", entity)
        for r in rows
        for entity in (r["agent_entity"], r["human_entity"])
        if entity
    }
    counts["missing"] = len(expected_keys - final_keys)
    counts["incremental"] = len(expected_keys - base_keys)
    counts["reused"] = len(expected_keys & base_keys)
    counts["observed"] = len(expected_keys & final_keys)
    counts["non_entity"] = len(non_entity)
    extras = {k[3] for k in final_keys - base_keys - expected_keys} | {k[3] for k in non_entity}
    explanations = {d.client_id: d for d in request.explanations}
    require(len(explanations) == len(request.explanations), "evidence_conflict")
    proven_explanations = set()
    explanation_refs = []
    for explanation in request.explanations:
        for reference in explanation.references:
            source_ref = store.ref(head, reference, "source")
            require(source_ref.environment_digest == digest(inv), "context_mismatch")
            explanation_refs.append(source_ref)
            evidence = validate(Source, store.read(head.dossier_id, source_ref))
            if source_reviewed(store, head, evidence) and any(
                f.kind == "operation_result"
                and f.values.target_ref == explanation.client_id
                and f.values.result == "success"
                for f in evidence.facts
            ):
                if (
                    explanation.classification == "non-entity"
                    and explanation.client_id in {k[3] for k in non_entity}
                    or explanation.classification == "unrelated"
                    and explanation.client_id in experiment.other_consumers
                ):
                    proven_explanations.add(explanation.client_id)
    native = all(
        source_reviewed(store, head, s)
        for s in (baseline, final, roster, mapping, cohort, original_mapping)
    )
    delay = profile.reporting_delay
    last = max(datetime.fromisoformat(r["occurred_at"].replace("Z", "+00:00")) for r in rows)
    require(mapping.observed_at >= last, "evidence_missing")
    counts["unrelated"] = len(final_keys - expected_keys)
    complete = (
        baseline.manifest.complete
        and final.manifest.complete
        and delay is not None
        and (final.observed_at - last).total_seconds() >= delay
    )
    outcome = (
        "fail"
        if counts["missing"]
        else "blocked"
        if not native or not complete or extras - proven_explanations
        else "pass"
    )
    counts["extra"] = len(extras - proven_explanations)
    measurement = validate(
        Measurement,
        request.model_dump(mode="json")
        | {
            "measurement_id": str(fresh_id()),
            "experiment_id": str(experiment_id),
            "scenario": experiment.scenario,
            "environment_digest": digest(inv),
            "measured_at": now().isoformat(),
            "implementation_digest": runtime_digest(),
            "review_dependencies": {
                str(r.review_id): digest(r)
                for r in reviews(store, head)
                if r.kind in {"source-profile", "source"}
            },
            "dependencies": {
                str(r.object_id): r.seal_digest
                for r in (
                    experiment_ref,
                    base_ref,
                    final_ref,
                    roster_ref,
                    map_ref,
                    cohort_ref,
                    original_map_ref,
                    *explanation_refs,
                )
            },
            "outcome": outcome,
            "provenance": "native" if native else "synthetic",
            "reason": None if outcome == "pass" else "proof_incomplete",
            "counts": counts,
        },
    )
    return store.append(
        head.dossier_id,
        head.revision,
        "measurement",
        measurement,
        object_id=measurement.measurement_id,
    )


def latest_outcomes(store, head):
    """Retain verified contradictions instead of cherry-picking a later success."""
    results = {scenario: "blocked" for scenario in SCENARIOS}
    for scenario in SCENARIOS:
        values = [
            validate(Measurement, p)
            for ref, p in store.records(head, "measurement")
            if ref.environment_digest == digest(store.inventory(head)) and p["scenario"] == scenario
        ]
        outcomes = []
        current_reviews = {
            str(r.review_id): digest(r)
            for r in reviews(store, head)
            if r.kind in {"source-profile", "source"}
        }
        for value in values:
            if value.provenance != "native":
                continue
            valid = value.implementation_digest == runtime_digest() and all(
                current_reviews.get(k) == v for k, v in value.review_dependencies.items()
            )
            for identifier, expected in value.dependencies.items():
                ref = store.ref(head, identifier)
                require(ref.seal_digest == expected, "integrity_failed")
                payload = store.read(head.dossier_id, ref)
                if ref.kind == "source":
                    valid &= source_reviewed(store, head, validate(Source, payload))
            # A verified contradiction remains a failure even if later reviews change.
            outcomes.append(value.outcome if valid or value.outcome == "fail" else "blocked")
        results[scenario] = (
            "fail"
            if "fail" in outcomes
            else "pass"
            if outcomes and all(o == "pass" for o in outcomes)
            else "blocked"
        )
    return results
