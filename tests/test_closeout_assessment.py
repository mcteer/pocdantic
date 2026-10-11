"""Independent complete-matrix, mechanism attribution and historical applicability tests."""

from datetime import timedelta

import pytest
from closeout_support import inventory

from agent.closeout.assessment import assemble, predicate, report, timing_bounds
from agent.closeout.models import Inventory, now, validate
from agent.closeout.store import Store


def test_empty_matrix_explicitly_blocks_every_original_criterion(closeout_project):
    """A useful report is complete even when no provider evidence is available."""
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    ref = assemble(store, head)
    value = report(store, store.head(head.dossier_id), ref.object_id)
    assert len(value["criteria"]) == 15
    assert {r["proof"] for r in value["criteria"]} == {"blocked"}
    assert value["status"] == "blocked"


def test_policy_denial_cannot_satisfy_jwt_invalid():
    """Provider policy denial leaves the original JWT validation requirement unmet."""
    assert not predicate(
        "same-jwt-invalid",
        {
            "kind": "jwt_validation",
            "values": {
                "result": "denied",
                "mechanism": "policy_denied",
                "expires_at": (now() + timedelta(seconds=60)).isoformat(),
            },
        },
    )


def test_conservative_timing_and_unknown_chronology():
    """Compute both uncertainty bounds and refuse inverted event chronology."""
    t = now()
    assert timing_bounds(t, t + timedelta(seconds=12), 1.0, 2.0) == (9.0, 15.0)
    assert timing_bounds(t, t - timedelta(seconds=1), 0.0, 0.0) is None


def test_amended_environment_makes_old_snapshot_historical(closeout_project):
    """Old byte-sealed evidence stays inspectable without certifying a changed environment."""
    store = Store(closeout_project)
    inv = inventory()
    head = store.prepare(validate(Inventory, inv))
    assessment = assemble(store, head)
    inv["policies"][0]["digest"] = "0" * 64
    store.append(head.dossier_id, 2, "inventory", validate(Inventory, inv))
    assert (
        report(store, store.head(head.dossier_id), assessment.object_id)["applicability"]
        == "historical"
    )


def test_all_fifteen_rows_from_reviewed_original_fields(closeout_project):
    """Every original predicate is exercised through parsing and exact extraction reviews."""
    from closeout_support import reviewed_facts

    store, head = reviewed_facts(closeout_project)
    ref = assemble(store, head)
    value = report(store, store.head(head.dossier_id), ref.object_id)
    assert {r["criterion"]: r["proof"] for r in value["criteria"]} == {
        criterion: "pass"
        for criterion in __import__("agent.evidence", fromlist=["CRITERIA"]).CRITERIA
    }
    assert value["status"] == "ready_for_review"


def test_review_cannot_promote_operator_provenance(closeout_project):
    """Even comprehensive attestation leaves operator-created facts non-native."""
    from closeout_support import reviewed_facts

    store, head = reviewed_facts(closeout_project, provenance="operator")
    ref = assemble(store, head)
    assert {
        r["proof"] for r in report(store, store.head(head.dossier_id), ref.object_id)["criteria"]
    } == {"blocked"}


def test_each_obligation_requires_actual_fields(closeout_project):
    """All compiled predicates reject a status string or an unrelated fact discriminator."""
    from closeout_support import reviewed_facts

    from agent.closeout.catalog import RULES

    store, head = reviewed_facts(closeout_project)
    facts = {
        f["obligation"]: f
        for _, s in store.records(head, "source")
        for f in s["facts"]
        if predicate(f["obligation"], f)
    }
    for labels in RULES.values():
        for label in labels:
            assert predicate(label, facts[label]), label
            assert not predicate(
                label, {"kind": facts[label]["kind"], "values": {"outcome": "pass"}}
            ), label
            assert not predicate(
                label, {"kind": "unsupported", "values": facts[label]["values"]}
            ), label


def test_later_denied_path_issuance_cannot_be_hidden(closeout_project):
    """A contradictory zero-issuance receipt fails even with an earlier passing receipt."""
    import json

    from closeout_support import instant, reviewed_facts

    from agent.closeout.models import byte_digest, digest
    from agent.closeout.review import record
    from agent.closeout.sources import import_source

    store, head = reviewed_facts(closeout_project)
    original = next(
        (ref, s)
        for ref, s in store.records(head, "source")
        if any(f["obligation"] == "denied-zero-issue" for f in s["facts"])
    )
    data = json.loads(store.read_files(head.dossier_id, original[0])["source.raw"])
    row = next(r for r in data if r["obligation"] == "denied-zero-issue")
    row["values"]["issued"] = 1
    row["source_event_id"] = "later-denial-contradiction"
    row["occurred_at"] = instant(-1)
    raw = json.dumps([row]).encode()
    manifest = original[1]["manifest"] | {
        "input_digest": byte_digest(raw),
        "observed_at": instant(),
    }
    ref = import_source(store, head, manifest, raw)
    copied = store.read(head.dossier_id, ref)
    record(
        store,
        store.head(head.dossier_id),
        {
            "kind": "source",
            "subject_id": str(ref.object_id),
            "expected_digest": ref.seal_digest,
            "extraction_digest": digest(
                {"facts": copied["facts"], "normalized": copied["normalized"]}
            ),
            "reviewer": "fixture-owner",
            "role": "verify_owner",
            "observed_at": instant(-1),
            "decision": "approve",
            "rationale": "reviewed contradiction",
            "attestations": [str(ref.object_id)],
        },
    )
    assessed = assemble(store, store.head(head.dossier_id))
    value = report(store, store.head(head.dossier_id), assessed.object_id)
    assert next(r for r in value["criteria"] if r["criterion"] == "UC2-02")["proof"] == "fail"


@pytest.mark.parametrize(
    "outcomes,expected",
    [
        (
            {
                "agent-repeat": "pass",
                "agent-only-users": "blocked",
                "agent-obo-users": "blocked",
                "direct-users": "blocked",
            },
            "blocked",
        ),
        (
            {
                "agent-repeat": "pass",
                "agent-only-users": "pass",
                "agent-obo-users": "pass",
                "direct-users": "pass",
            },
            "pass",
        ),
        (
            {
                "agent-repeat": "pass",
                "agent-only-users": "pass",
                "agent-obo-users": "fail",
                "direct-users": "pass",
            },
            "fail",
        ),
    ],
)
def test_phase_gates_require_their_complete_dependencies(
    closeout_project, monkeypatch, outcomes, expected
):
    """A complete matrix is available before witness/core; counting requires all four scenarios."""
    import agent.closeout.counting as counting

    monkeypatch.setattr(counting, "latest_outcomes", lambda store, head: outcomes)
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    assessed = assemble(store, head)
    payload = store.read(head.dossier_id, assessed)
    assert payload["tests"]["F13-T4"] == "pass"
    assert payload["gates"]["P4-G5"] == expected
    assert {payload["gates"][f"P4-G{i}"] for i in range(1, 5)} == {"blocked"}
    summary = report(store, store.head(head.dossier_id), assessed.object_id)
    assert summary["status"] == ("failed" if expected == "fail" else "blocked")
