"""Independent exact-cohort arithmetic and conservative reporting tests."""

import pytest

from agent.closeout.counting import parse_records, reconcile
from agent.closeout.models import CloseoutError


def roster(scenario):
    """Build a controlled hundred-operation fixture with native-shaped mapping keys."""
    return [
        {
            "execution_ref": f"e{i}",
            "operation_ref": f"o{i}",
            "issuance_ref": f"t{i}",
            "trace_ref": f"r{i}",
            "verification_ref": f"v{i}",
            "occurred_at": "2026-10-10T12:00:00Z",
            "result": "success",
            "mode": scenario,
            "issuer": "issuer" if scenario != "agent-repeat" else None,
            "subject": f"u{i}" if scenario != "agent-repeat" else None,
            "agent_entity": "agent" if scenario != "direct-users" else None,
            "human_entity": f"human{i}"
            if scenario in {"agent-obo-users", "direct-users"}
            else None,
            "namespace_id": "ns",
            "mount_accessor": "mount",
        }
        for i in range(100)
    ]


@pytest.mark.parametrize(
    "scenario,total",
    [("agent-repeat", 1), ("agent-only-users", 1), ("agent-obo-users", 101), ("direct-users", 100)],
)
def test_exact_sets_and_reuse(scenario, total):
    """Scenario totals are independent of how many clients were already active."""
    rows = roster(scenario)
    expected = {r["human_entity"] for r in rows if r["human_entity"]} | {
        r["agent_entity"] for r in rows if r["agent_entity"]
    }
    result = reconcile(scenario, rows, expected, expected)
    assert result["scenario"] == total
    assert result["incremental"] == 0
    assert result["reused"] == total


def test_repeated_human_with_new_tokens_is_not_hundred_users():
    """Unique token references cannot disguise a reused verified subject."""
    rows = roster("agent-only-users")
    for row in rows:
        row["subject"] = "same"
    with pytest.raises(CloseoutError, match="cohort_invalid"):
        reconcile("agent-only-users", rows, set(), {"agent"})


def test_unknown_export_shape_never_drops_rows():
    """A misspelled first-use field is rejected instead of counted as missing."""
    import json

    with pytest.raises(CloseoutError):
        parse_records("vault-activity-v1", json.dumps({"client_id": "x"}).encode(), None)


def measurement_lifecycle(closeout_project, monkeypatch, scenario, defect=None, capsys=None):
    """Exercise real parsers/preparation/review/measurement with a simulated external clock."""
    import json
    from datetime import timedelta
    from uuid import uuid4

    from closeout_support import inventory

    import agent.closeout.counting as counting
    import agent.closeout.models as models
    import agent.closeout.review as review
    import agent.closeout.sources as sources
    from agent.closeout.counting import measure, prepare_experiment
    from agent.closeout.models import Inventory, byte_digest, digest, now, validate
    from agent.closeout.review import record
    from agent.closeout.sources import import_source
    from agent.closeout.store import Store

    if capsys is not None:
        from closeout_support import private_file
        from test_closeout_cli import command

        def prepare_experiment(store, head, request):
            """Exercise the actual CLI preparation boundary with original synthetic imports."""
            path = private_file(closeout_project / "experiment-input", request)
            code, result = command(
                capsys,
                "experiment",
                "--dossier",
                head.dossier_id,
                "--revision",
                head.revision,
                "--input",
                path,
            )
            assert code == 0
            return store.ref(store.head(head.dossier_id), result["object_id"], "experiment")

        def measure(store, head, experiment_id, request):
            """Exercise CLI measurement with the complete source-shaped roster."""
            path = private_file(closeout_project / "measurement-input", request)
            code, result = command(
                capsys,
                "measure",
                "--dossier",
                head.dossier_id,
                "--revision",
                head.revision,
                "--experiment",
                experiment_id,
                "--input",
                path,
            )
            assert code == 0 and result["content_status"] == "pass"
            return store.ref(store.head(head.dossier_id), result["object_id"], "measurement")

    clock = now()
    for module in (models, sources, review, counting):
        monkeypatch.setattr(module, "now", lambda: clock)
    inv = inventory()
    template = inv["sources"][0]
    inv["sources"] = [
        {**template, "profile_id": str(uuid4()), "format": format_name, "namespace": "ns"}
        for format_name in ("vault-activity-v1", "entity-mapping-v1", "execution-roster-v1")
    ]
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inv))
    scope = str(uuid4())
    start = clock.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    profiles = {p.format: p for p in store.inventory(head).sources}
    reviewed = set()

    def ingest(format_name, rows):
        """Import complete original source bytes and attest exact profile/extraction hashes."""
        profile = profiles[format_name]
        head = store.head(store_id)
        raw = b"\n".join(json.dumps(row).encode() for row in rows)
        manifest = {
            "profile_id": str(profile.profile_id),
            "format": format_name,
            "provenance": "synthetic" if defect == "synthetic" else "native",
            "input_digest": byte_digest(raw),
            "observed_at": clock.isoformat(),
            "environment_digest": digest(store.inventory(head)),
            "scope": scope,
            "complete": True,
        }
        if format_name == "vault-activity-v1":
            manifest.update(
                first_use_field="client_first_used_time",
                period_start=start.isoformat(),
                period_end=end.isoformat(),
                mounts=["mount"],
            )
        if format_name == "vault-activity-v1" and rows:
            if defect == "partial":
                manifest["complete"] = False
            if defect == "wrong-period":
                manifest["period_start"] = end.isoformat()
                manifest["period_end"] = (end + timedelta(days=40)).replace(day=1).isoformat()
        ref = import_source(store, head, manifest, raw)
        source = store.read(store_id, ref)
        base = {
            "reviewer": "fixture-owner",
            "role": "vault_owner",
            "observed_at": clock.isoformat(),
            "decision": "approve",
            "rationale": "complete reviewed source fixture",
            "attestations": [str(ref.object_id)],
        }
        if profile.profile_id not in reviewed:
            record(
                store,
                store.head(store_id),
                base
                | {
                    "kind": "source-profile",
                    "subject_id": str(profile.profile_id),
                    "expected_digest": digest(profile),
                },
            )
            reviewed.add(profile.profile_id)
        record(
            store,
            store.head(store_id),
            base
            | {
                "kind": "source",
                "subject_id": str(ref.object_id),
                "expected_digest": ref.seal_digest,
                "extraction_digest": digest(
                    {"facts": source["facts"], "normalized": source["normalized"]}
                ),
            },
        )
        return ref

    store_id = head.dossier_id
    mappings = [
        {
            "issuer": "issuer",
            "subject": f"u{i}",
            "entity_id": f"human{i}",
            "namespace_id": "ns",
            "mount_accessor": "mount",
            "category": "human",
            "observed_at": clock.isoformat(),
            "verification_ref": f"v{i}",
        }
        for i in range(100)
    ]
    mappings.append(
        {
            "issuer": "agent-issuer",
            "subject": "agent-subject",
            "entity_id": "agent",
            "namespace_id": "ns",
            "mount_accessor": "mount",
            "category": "agent",
            "definition_ref": "agent-fixture",
            "observed_at": clock.isoformat(),
            "verification_ref": "agent-verification",
        }
    )
    baseline = ingest("vault-activity-v1", [])
    mapping = ingest("entity-mapping-v1", mappings)
    cohort = ingest("entity-mapping-v1", mappings[:100])
    clock += timedelta(seconds=1)
    experiment = prepare_experiment(
        store,
        store.head(store_id),
        {
            "scenario": scenario,
            "profile_id": str(profiles["vault-activity-v1"].profile_id),
            "baseline_id": str(baseline.object_id),
            "mapping_id": str(mapping.object_id),
            "cohort_id": str(cohort.object_id),
            "mounts": ["mount"],
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
        },
    )
    clock += timedelta(seconds=1)
    operations = roster(scenario)
    for row in operations:
        row["occurred_at"] = clock.isoformat()
        if defect == "repeated-user":
            row["subject"] = "same"
        if defect == "wrong-mount":
            row["mount_accessor"] = "other"
    roster_ref = ingest("execution-roster-v1", operations)
    clock += timedelta(seconds=10 if defect == "lag" else 1201)
    if defect == "remapped":
        mappings[0]["entity_id"] = "changed-entity"
    expected = {r["human_entity"] for r in operations if r["human_entity"]} | {
        r["agent_entity"] for r in operations if r["agent_entity"]
    }
    if defect == "missing":
        expected.remove(sorted(expected)[0])
    if defect == "mapping-scope":
        mappings[0]["namespace_id"] = "other-namespace"
    post_mapping = ingest("entity-mapping-v1", mappings)
    final = ingest(
        "vault-activity-v1",
        [
            {
                "client_id": entity,
                "client_type": "entity",
                "namespace_id": "ns",
                "mount_accessor": "mount",
                "client_first_used_time": operations[0]["occurred_at"],
            }
            for entity in sorted(expected)
        ],
    )
    result = measure(
        store,
        store.head(store_id),
        experiment.object_id,
        {
            "final_id": str(final.object_id),
            "roster_id": str(roster_ref.object_id),
            "mapping_id": str(post_mapping.object_id),
        },
    )
    measurement = store.read(store_id, result)
    if defect == "review-rejected":
        assert counting.latest_outcomes(store, store.head(store_id))[scenario] == "pass"
        payload = store.read(store_id, post_mapping)
        record(
            store,
            store.head(store_id),
            {
                "kind": "source",
                "subject_id": str(post_mapping.object_id),
                "expected_digest": post_mapping.seal_digest,
                "extraction_digest": digest(
                    {"facts": payload["facts"], "normalized": payload["normalized"]}
                ),
                "reviewer": "fixture-owner",
                "role": "vault_owner",
                "observed_at": clock.isoformat(),
                "decision": "reject",
                "rationale": "changed source eligibility",
                "attestations": [str(post_mapping.object_id)],
            },
        )
        assert counting.latest_outcomes(store, store.head(store_id))[scenario] == "blocked"
        assert store.read(store_id, result)["outcome"] == "pass"
    return measurement


@pytest.mark.parametrize(
    "scenario,total",
    [("agent-repeat", 1), ("agent-only-users", 1), ("agent-obo-users", 101), ("direct-users", 100)],
)
def test_reviewed_native_shaped_measurement_lifecycle(
    closeout_project, monkeypatch, scenario, total
):
    """Four independently reviewed cohorts produce exact expected and incremental totals."""
    measurement = measurement_lifecycle(closeout_project, monkeypatch, scenario)
    assert measurement["outcome"] == "pass"
    assert measurement["counts"]["scenario"] == total
    assert measurement["counts"]["incremental"] == total
    assert measurement["counts"]["reused"] == 0


@pytest.mark.parametrize(
    "defect,outcome",
    [("partial", "blocked"), ("lag", "blocked"), ("synthetic", "blocked"), ("missing", "fail")],
)
def test_incomplete_or_non_native_measurements_cannot_pass(
    closeout_project, monkeypatch, defect, outcome
):
    """Completeness, reporting lag, native review and exact missing clients are independent."""
    assert (
        measurement_lifecycle(closeout_project, monkeypatch, "agent-obo-users", defect)["outcome"]
        == outcome
    )


@pytest.mark.parametrize(
    "defect,reason",
    [
        ("repeated-user", "cohort_invalid"),
        ("wrong-mount", "context_mismatch"),
        ("remapped", "evidence_conflict"),
        ("wrong-period", "context_mismatch"),
        ("mapping-scope", "context_mismatch"),
    ],
)
def test_wrong_scope_or_remapping_rejects_measurement(
    closeout_project, monkeypatch, defect, reason
):
    """Verified cohorts cannot be joined across incompatible mappings or reporting scope."""
    with pytest.raises(CloseoutError, match=reason):
        measurement_lifecycle(closeout_project, monkeypatch, "agent-obo-users", defect)


@pytest.mark.parametrize("field", ["client_first_used_time", "client_first_usage_time"])
def test_first_use_versions_are_explicit_and_conflicts_rejected(field):
    """Both reviewed spelling versions normalize, but an ambiguous mixed row is refused."""
    import json
    from types import SimpleNamespace

    row = {
        "client_id": "fixture",
        "client_type": "entity",
        "namespace_id": "ns",
        "mount_accessor": "mount",
        field: "2026-10-10T12:00:00Z",
    }
    assert parse_records(
        "vault-activity-v1", json.dumps(row).encode(), SimpleNamespace(first_use_field=field)
    )[0]["first_used_at"]
    other = (
        "client_first_usage_time" if field == "client_first_used_time" else "client_first_used_time"
    )
    with pytest.raises(CloseoutError):
        parse_records(
            "vault-activity-v1",
            json.dumps(row | {other: row[field]}).encode(),
            SimpleNamespace(first_use_field=field),
        )


def test_identical_activity_dedups_but_conflicting_acquisition_fails():
    """Mount and timestamp disagreement cannot be hidden by the client-key set."""
    from types import SimpleNamespace

    from agent.closeout.counting import activity_set

    row = {
        "client_id": "fixture",
        "client_type": "entity",
        "namespace_id": "ns",
        "mount_accessor": "mount",
        "first_used_at": "2026-10-10T12:00:00Z",
        "metadata": {},
    }
    profile = SimpleNamespace(namespace="ns", cluster="cluster")
    assert len(activity_set(SimpleNamespace(normalized=[row, row]), profile, ["mount"])[0]) == 1
    with pytest.raises(CloseoutError, match="evidence_conflict"):
        activity_set(
            SimpleNamespace(normalized=[row, row | {"first_used_at": "2026-10-10T12:00:01Z"}]),
            profile,
            ["mount"],
        )
    with pytest.raises(CloseoutError, match="context_mismatch"):
        activity_set(
            SimpleNamespace(normalized=[row | {"namespace_id": "other"}]), profile, ["mount"]
        )


def test_later_review_rejection_blocks_frozen_passing_measurement(closeout_project, monkeypatch):
    """Historical counts remain intact, but conflicting current eligibility cannot satisfy F13."""
    measurement_lifecycle(closeout_project, monkeypatch, "agent-repeat", defect="review-rejected")
