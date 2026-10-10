import hashlib
from datetime import timedelta
from uuid import uuid4

import pytest

from agent.settings import Settings
from agent.validation.catalog import load_catalog
from agent.validation.closeout import create_closeout, inspect_closeout
from agent.validation.context import capture_context
from agent.validation.importers import import_source
from agent.validation.models import (
    AssertionResult,
    ImportManifest,
    PrivateOperationBinding,
    ScenarioObservation,
    TransactionEvidence,
    ValidationRun,
    canonical,
    now,
)
from agent.validation.report import seal_execution
from agent.validation.store import PrivateStore, StoreError


def live_run(store, labels, *, context=None, state="SUCCESS", extra_events=0, transaction_id=None):
    suite = next(s for s in load_catalog().suites if labels[0] in {d.label for d in s.scenarios})
    stamp = now()
    run = ValidationRun(
        suite=suite.label,
        suite_revision=suite.revision,
        mode="live",
        selected=tuple(labels),
        configuration_fingerprint="a" * 64,
        state="finalized",
        created_at=stamp,
        completed_at=stamp + timedelta(seconds=1),
    )
    with store.create(run.validation_id) as w:
        w.write_json("run.json", run)
        w.write_json("context.json", context or capture_context(Settings.model_construct()))
        vault = []
        spans = []
        bindings = []
        for index, label in enumerate(labels):
            native = uuid4()
            definition = next(d for d in suite.scenarios if d.label == label)
            o = ScenarioObservation(
                validation_id=run.validation_id,
                scenario=label,
                scenario_revision=definition.revision,
                run_id=native,
                outcome="pass",
                operation_outcome="pass"
                if label in {"phone-approved", "delegated-database-read"}
                else "fail",
                cleanup="revoked" if label == "delegated-database-read" else "not_acquired",
                started_at=stamp,
                finished_at=stamp + timedelta(seconds=1),
                assertions=(
                    AssertionResult(
                        label=definition.expected_assertions[0],
                        outcome="pass",
                        strength="live",
                        effect_attempts=1,
                    ),
                ),
            )
            w.write_json(f"observation-{o.observation_id}.json", o)
            trace = f"{index + 1:032x}"
            span = f"{index + 1:016x}"
            b = PrivateOperationBinding(
                validation_id=run.validation_id,
                observation_id=o.observation_id,
                run_id=native,
                phase="telemetry",
                source_kind="logfire",
                source_instance="private-project",
                trace_id=trace,
                span_id=span,
                started_at=stamp,
                finished_at=stamp + timedelta(seconds=1),
            )
            bindings.append(b)
            spans.append(
                {
                    "trace_id": trace,
                    "span_id": span,
                    "start_timestamp": stamp.isoformat(),
                    "attributes": {"validation_id": str(run.validation_id), "run_id": str(native)},
                }
            )
            if suite.label == "live-database":
                phases = (
                    ["credential", "cleanup"]
                    if label == "delegated-database-read"
                    else ["credential"]
                )
                for phase in phases:
                    req = str(uuid4())
                    lease = "private-lease" if label == "delegated-database-read" else None
                    b = PrivateOperationBinding(
                        validation_id=run.validation_id,
                        observation_id=o.observation_id,
                        run_id=native,
                        phase=phase,
                        source_kind="vault",
                        source_instance="private-vault",
                        native_request_id=req,
                        native_lease_id=lease,
                        expected_outcome="denied" if label == "actor-only-denial" else "success",
                        started_at=stamp,
                        finished_at=stamp + timedelta(seconds=1),
                    )
                    bindings.append(b)
                    for kind in ("request", "response"):
                        row = {
                            "type": kind,
                            "time": stamp.isoformat(),
                            "request": {
                                "id": req,
                                "path": "sys/leases/revoke"
                                if phase == "cleanup"
                                else "database/creds/read",
                                "data": {"lease_id": lease} if phase == "cleanup" else {},
                            },
                        }
                        if kind == "response" and phase == "credential" and lease:
                            row["response"] = {"secret": {"lease_id": lease}}
                        if kind == "response" and label == "actor-only-denial":
                            row["error"] = "denied"
                        vault.append(row)
            else:
                approval = uuid4()
                tx = transaction_id or str(uuid4())
                decision = (
                    "approved"
                    if state in {"SUCCESS", "VERIFY_SUCCESS"}
                    else "denied"
                    if state in {"DENIED", "VERIFY_DENIED", "USER_DENIED"}
                    else "unverified"
                )
                bindings.append(
                    PrivateOperationBinding(
                        validation_id=run.validation_id,
                        observation_id=o.observation_id,
                        run_id=native,
                        phase="approval",
                        source_kind="verify",
                        source_instance="private-verify",
                        native_transaction_id=tx,
                        approval_ref=approval,
                        action_digest="c" * 64,
                    )
                )
                raw = canonical(
                    {
                        "id": tx,
                        "state": state,
                        "transactionData": {
                            "additionalData": [
                                {"name": "approval_id", "value": str(approval)},
                                {"name": "action_digest", "value": "c" * 64},
                            ]
                        },
                    }
                )
                t = TransactionEvidence(
                    validation_id=run.validation_id,
                    observation_id=o.observation_id,
                    run_id=native,
                    source_instance="private-verify",
                    native_transaction_id=tx,
                    approval_ref=approval,
                    action_digest="c" * 64,
                    decision=decision,
                    raw_digest=hashlib.sha256(raw).hexdigest(),
                )
                w.write_json(f"transaction-{t.artifact_id}.json", t)
                w.write_bytes(f"source-{t.artifact_id}.raw", raw)
        for b in bindings:
            w.append_event(b, "bindings.jsonl")
        pairs = [(r["trace_id"], r["span_id"]) for r in spans]
        w.write_json(
            "delivery.json", {"state": "acknowledged", "attempted": pairs, "acknowledged": pairs}
        )
        if extra_events:
            vault.extend(
                {
                    "type": "request",
                    "time": stamp.isoformat(),
                    "request": {"id": f"unused-{i}", "path": "database/creds/read"},
                }
                for i in range(extra_events - len(vault) - len(spans))
            )
        seal_execution(w)
        for source, rows, instance in [
            ("vault", vault, "private-vault"),
            ("logfire", spans, "private-project"),
        ]:
            if not rows:
                continue
            path = store.root.parent / f"{uuid4()}.json"
            path.write_bytes(
                b"\n".join(canonical(r) for r in rows)
                if source == "vault"
                else canonical({"rows": rows})
            )
            m = ImportManifest(
                source_kind=source,
                format_label="vault-jsonl" if source == "vault" else "logfire-rows",
                format_version=2,
                source_instance=instance,
                window_start=stamp - timedelta(seconds=1),
                window_end=stamp + timedelta(seconds=2),
                completeness="complete",
            )
            import_source(w, source, path, m)
    return run.validation_id


@pytest.fixture
def store(tmp_path):
    return PrivateStore(tmp_path / ".local/validation", project=tmp_path)


def test_complete_stable_closeout_no_network(store, monkeypatch):
    runs = [
        live_run(store, ["delegated-database-read", "actor-only-denial"]),
        live_run(store, ["phone-approved"]),
        live_run(store, ["phone-denied"], state="DENIED"),
    ]
    import socket

    monkeypatch.setattr(socket.socket, "connect", lambda *args: pytest.fail("network attempted"))
    a = create_closeout(store, runs)
    b = create_closeout(store, list(reversed(runs)))
    assert a.snapshot.content_revision == b.snapshot.content_revision
    assert a.snapshot.snapshot_id != b.snapshot.snapshot_id
    assert a.exit_code() == 0 and len(a.snapshot.cases) == 4 and len(a.snapshot.criteria) == 15
    assert all(r.status == "blocked" for c in a.snapshot.criteria for r in c.members)
    assert "private" not in a.model_dump_json()
    assert inspect_closeout(store, a.snapshot.snapshot_id).exit_code() == 0


def test_missing_duplicate_context_and_stale(store):
    a = live_run(store, ["actor-only-denial"])
    partial = create_closeout(store, [a])
    assert partial.exit_code() == 2
    duplicate = create_closeout(store, [a, live_run(store, ["actor-only-denial"])])
    assert duplicate.exit_code() == 2
    different = live_run(
        store,
        ["phone-approved"],
        context=capture_context(Settings.model_construct(database_host="another")),
    )
    assert create_closeout(store, [a, different]).exit_code() == 2
    with store.open(a) as w:
        w.write_json("review-extra.json", {})
    stale = inspect_closeout(store, partial.snapshot.snapshot_id)
    assert stale.exit_code() != 0
    with pytest.raises(StoreError):
        create_closeout(store, [a, a])


@pytest.mark.parametrize("state", ["TIMEOUT", "EXPIRED", "FAILED", "CANCELED"])
def test_nonapproval_is_not_witnessed_denial(store, state):
    result = create_closeout(store, [live_run(store, ["phone-denied"], state=state)])
    denied = next(c for c in result.snapshot.cases if c.scenario == "phone-denied")
    assert denied.operational != "pass" and denied.evidence != "pass"


def test_snapshot_tampering_fails(store):
    result = create_closeout(store, [live_run(store, ["actor-only-denial"])])
    with store.open_closeout(result.snapshot.snapshot_id) as w:
        raw = w.read_json("closeout.json")
        raw["operational"] = "pass"
        w.write_json("closeout.json", raw, replace=True)
    with pytest.raises(ValueError):
        inspect_closeout(store, result.snapshot.snapshot_id)


def test_contended_lock_and_interruption_leave_no_final_snapshot(store, monkeypatch):
    import agent.validation.closeout as module

    run = live_run(store, ["actor-only-denial"])
    with store.open(run):
        with pytest.raises(StoreError):
            create_closeout(store, [run])
    assert not (store.root / "closeouts").exists()
    original = module.check_deadline
    calls = 0

    def interrupted(deadline):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise KeyboardInterrupt
        original(deadline)

    monkeypatch.setattr(module, "check_deadline", interrupted)
    with pytest.raises(KeyboardInterrupt):
        create_closeout(store, [run])
    assert not list((store.root / "closeouts").glob("*/closeout.json"))
    with store.open(run) as w:
        assert w.read_json("run.json")["validation_id"] == str(run)


def test_inventory_mutation_before_finalization(store, monkeypatch):
    import agent.validation.closeout as module

    run = live_run(store, ["actor-only-denial"])
    original = module.assemble_closeout

    def mutation(items):
        result = original(items)
        next(iter(items.values()))["writer"].write_json("new-input.json", {})
        return result

    monkeypatch.setattr(module, "assemble_closeout", mutation)
    with pytest.raises(StoreError, match="input_changed"):
        create_closeout(store, [run])
    assert not list((store.root / "closeouts").glob("*/closeout.json"))


def test_manifest_and_markdown_tampering(store):
    run = live_run(store, ["actor-only-denial"])
    result = create_closeout(store, [run])
    with store.open_closeout(result.snapshot.snapshot_id) as w:
        manifest = w.read_json("manifest.json")
        manifest["inputs"][str(run)] = {}
        w.write_json("manifest.json", manifest, replace=True)
    with pytest.raises(StoreError, match="digest_mismatch"):
        inspect_closeout(store, result.snapshot.snapshot_id)
    second = create_closeout(store, [run])
    with store.open_closeout(second.snapshot.snapshot_id) as w:
        w.write_bytes("closeout.md", b"Operational: pass", replace=True)
    with pytest.raises(StoreError, match="digest_mismatch"):
        inspect_closeout(store, second.snapshot.snapshot_id)


def test_four_maximum_runs_assembly_budget(store, monkeypatch):
    import socket
    import time

    from agent.validation.closeout import assemble_closeout, collect

    monkeypatch.setattr(socket.socket, "connect", lambda *args: pytest.fail("network attempted"))
    runs = [
        live_run(
            store,
            [label],
            state="DENIED" if label == "phone-denied" else "SUCCESS",
            extra_events=10_000,
        )
        for label in (
            "delegated-database-read",
            "actor-only-denial",
            "phone-approved",
            "phone-denied",
        )
    ]
    with store.open_many(runs) as writers:
        # Parse and reconstruct the full maximum native inventories before timing pure assembly.
        items = {i: collect(w) | {"writer": w} for i, w in writers.items()}
        assert all(sum(a.event_count for a in d["artifacts"]) == 10_000 for d in items.values())
        start = time.monotonic()
        result = assemble_closeout(items)
        elapsed = time.monotonic() - start
        assert elapsed < 10
        assert result.operational == result.evidence == "pass"
        assert len(result.criteria) == 15


@pytest.mark.parametrize(
    "mutation",
    [
        "validation_id",
        "observation_id",
        "run_id",
        "source_instance",
        "approval_ref",
        "action_digest",
    ],
)
def test_wrong_transaction_join_cannot_close(store, mutation):
    from agent.validation.importers import load_transactions

    run = live_run(store, ["phone-approved"])
    with store.open(run) as w:
        path = next(w.path.glob("transaction-*.json"))
        value = w.read_json(path.name)
        value[mutation] = (
            "b" * 64
            if mutation == "action_digest"
            else "another-source"
            if mutation == "source_instance"
            else str(uuid4())
        )
        w.write_json(path.name, value, replace=True)
        with pytest.raises(StoreError):
            load_transactions(w)
    result = create_closeout(store, [run])
    assert result.snapshot.evidence == "fail"


def test_missing_legacy_context_and_tampered_context(store):
    run = live_run(store, ["actor-only-denial"])
    with store.open(run) as w:
        (w.path / "context.json").unlink()
        integrity = w.read_json("integrity.json")
        integrity.pop("context.json")
        w.write_json("integrity.json", integrity, replace=True)
    assert create_closeout(store, [run]).snapshot.evidence == "blocked"
    other = live_run(store, ["actor-only-denial"])
    with store.open(other) as w:
        value = w.read_json("context.json")
        value["selectors"]["database_host"] = "mutated"
        w.write_json("context.json", value, replace=True)
    assert create_closeout(store, [other]).snapshot.evidence == "fail"


def test_inspection_missing_tampered_and_changed_inputs(store):
    run = live_run(store, ["actor-only-denial"])
    result = create_closeout(store, [run])
    with store.open(run) as w:
        value = w.read_json("context.json")
        w.write_json("context.json", value | {"digest": "a" * 64}, replace=True)
    inspected = inspect_closeout(store, result.snapshot.snapshot_id)
    assert inspected.applicability == "failed" and inspected.exit_code() == 1
    with store.open(run) as w:
        (w.path / "context.json").unlink()
    assert inspect_closeout(store, result.snapshot.snapshot_id).applicability == "missing"
    other = live_run(store, ["actor-only-denial"])
    result = create_closeout(store, [other])
    with store.open(other) as w:
        w.write_json("new-manual-input.json", {})
    assert inspect_closeout(store, result.snapshot.snapshot_id).applicability == "stale"
    with store.open(other):
        with pytest.raises(StoreError, match="storage_error"):
            inspect_closeout(store, result.snapshot.snapshot_id)


async def test_closeout_cli_creation_and_inspection(store, capsys):
    import argparse
    import json

    from agent.validation.commands import add_validation_parser, execute_validation

    run = live_run(store, ["actor-only-denial"])
    parser = argparse.ArgumentParser()
    add_validation_parser(parser.add_subparsers(dest="command", required=True))
    args = parser.parse_args(["validate", "closeout", "--run", str(run), "--root", str(store.root)])
    # The CLI derives the project from cwd; fixtures intentionally use their own local project.
    from unittest.mock import patch

    with patch("agent.validation.commands.PrivateStore", return_value=store):
        assert await execute_validation(args) == 2
        first = json.loads(capsys.readouterr().out)
        snapshot = first["snapshot"]
        assert len(snapshot["cases"]) == 4 and len(snapshot["criteria"]) == 15
        args = parser.parse_args(["validate", "closeout", "--closeout", snapshot["snapshot_id"]])
        assert await execute_validation(args) == 2
        assert json.loads(capsys.readouterr().out)["applicability"] == "current"
    with store.open_closeout(snapshot["snapshot_id"]) as w:
        md = w.read_bytes("closeout.md").decode()
        assert all(c["scenario"] in md for c in snapshot["cases"])
        assert all(c["criterion"] in md for c in snapshot["criteria"])


def test_phone_review_requires_live_simulated_effect(store):
    from agent.validation.importers import load_transactions
    from agent.validation.report import rebuild_report
    from agent.validation.review import eligible

    run = live_run(store, ["phone-approved"])
    with store.open(run) as w:
        report = rebuild_report(w, persist=False)
        tx = load_transactions(w)
        value = ValidationRun.model_validate(w.read_json("run.json"))
        assert eligible("UC2-02", report, value, [], [tx[0].artifact_id], tx)
        bad = report.model_copy(
            update={"scenarios": (report.scenarios[0].model_copy(update={"assertions": ()}),)}
        )
        assert not eligible("UC2-02", bad, value, [], [tx[0].artifact_id], tx)


def test_reused_native_transaction_across_runs_fails(store):
    tx = str(uuid4())
    a = live_run(store, ["phone-approved"], transaction_id=tx)
    b = live_run(store, ["phone-denied"], state="DENIED", transaction_id=tx)
    result = create_closeout(store, [a, b])
    assert result.snapshot.evidence == "fail"
    assert "evidence_contradicted" in result.snapshot.blockers


def test_native_user_denied_is_intentional_denial(store):
    run = live_run(store, ["phone-denied"], state="USER_DENIED")
    result = create_closeout(store, [run])
    case = next(c for c in result.snapshot.cases if c.scenario == "phone-denied")
    assert case.operational == case.evidence == "pass"
