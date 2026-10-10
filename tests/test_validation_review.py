from uuid import uuid4

import pytest

from agent.validation.models import now
from agent.validation.review import ReviewInput, record_review
from agent.validation.runner import run_suite
from agent.validation.store import PrivateStore


async def test_local_evidence_cannot_be_promoted_or_alternative(tmp_path):
    store = PrivateStore(tmp_path / ".local/validation", project=tmp_path)
    report = await run_suite(store=store, names=["delegated-read"])
    with store.open(report.validation_id) as writer:
        for decision in ["pass", "alternative"]:
            with pytest.raises(ValueError):
                record_review(
                    writer,
                    "UC1-02",
                    decision,
                    ReviewInput(
                        reviewer="private-reviewer",
                        rationale="private-rationale",
                        observed_at=now(),
                        expected_revision=report.acceptance[1].evidence_revision,
                        references=(uuid4(),),
                    ),
                )


async def test_review_is_private_immutable_and_stale_digest_rejected(tmp_path):
    store = PrivateStore(tmp_path / ".local/validation", project=tmp_path)
    report = await run_suite(store=store, names=["delegated-read"])
    review = ReviewInput(
        reviewer="<script>private-reviewer",
        rationale="private-rationale",
        observed_at=now(),
        expected_revision=report.acceptance[0].evidence_revision,
    )
    with store.open(report.validation_id) as writer:
        result = record_review(writer, "UC1-01", "blocked", review)
        assert (writer.path / f"review-{result.review_id}.json").exists()
        assert "private" not in result.public_json()
        with pytest.raises(ValueError, match="review_stale"):
            record_review(
                writer,
                "UC1-01",
                "blocked",
                review.model_copy(update={"expected_revision": "a" * 64}),
            )


async def test_complete_transaction_review_and_tamper_workflow(tmp_path):
    import hashlib

    from agent.validation.catalog import load_catalog
    from agent.validation.models import (
        AssertionResult,
        ScenarioObservation,
        TransactionEvidence,
        ValidationRun,
        canonical,
    )
    from agent.validation.report import rebuild_report, seal_execution

    source = {
        "id": "synthetic-transaction",
        "state": "SUCCESS",
        "transactionData": {
            "additionalData": [
                {"name": "approval_id", "value": str(uuid4())},
                {"name": "action_digest", "value": "c" * 64},
            ]
        },
    }
    suite = load_catalog().suites[2]
    run = ValidationRun(
        suite=suite.label,
        suite_revision=suite.revision,
        mode="live",
        selected=("phone-approved",),
        configuration_fingerprint="a" * 64,
        state="finalized",
        completed_at=now(),
    )
    observation = ScenarioObservation(
        validation_id=run.validation_id,
        scenario="phone-approved",
        scenario_revision=suite.scenarios[0].revision,
        outcome="pass",
        assertions=(
            AssertionResult(
                label="phone-approved", outcome="pass", strength="live", effect_attempts=1
            ),
        ),
    )
    raw = canonical(source)
    transaction = TransactionEvidence(
        validation_id=run.validation_id,
        observation_id=observation.observation_id,
        run_id=uuid4(),
        source_instance="synthetic",
        native_transaction_id=source["id"],
        approval_ref=source["transactionData"]["additionalData"][0]["value"],
        action_digest="c" * 64,
        decision="approved",
        raw_digest=hashlib.sha256(raw).hexdigest(),
    )
    store = PrivateStore(tmp_path / ".local/validation", project=tmp_path)
    with store.create(run.validation_id) as writer:
        writer.write_json("run.json", run)
        writer.write_json(f"observation-{observation.observation_id}.json", observation)
        writer.write_bytes(f"source-{transaction.artifact_id}.raw", raw)
        writer.write_json(f"transaction-{transaction.artifact_id}.json", transaction)
        seal_execution(writer)
        report = rebuild_report(writer)
        criterion = next(c for c in report.acceptance if c.criterion == "UC2-02")
        review = ReviewInput(
            reviewer="private-reviewer",
            rationale="private-rationale",
            observed_at=now(),
            expected_revision=criterion.evidence_revision,
            references=(transaction.artifact_id,),
        )
        record_review(writer, "UC2-02", "pass", review)
        report = rebuild_report(writer)
        assert next(c for c in report.acceptance if c.criterion == "UC2-02").status == "pass"
        assert "private" not in report.model_dump_json()
        writer.write_bytes(f"source-{transaction.artifact_id}.raw", raw + b" ", replace=True)
        report = rebuild_report(writer)
        assert report.exit_code() == 1
        assert next(c for c in report.acceptance if c.criterion == "UC2-02").status == "blocked"


def test_live_fixture_import_receipt_review_and_mapping_drift(tmp_path):
    import json
    from datetime import timedelta

    from agent.validation.catalog import load_catalog
    from agent.validation.importers import import_source
    from agent.validation.models import (
        AssertionResult,
        ImportManifest,
        PrivateOperationBinding,
        ScenarioObservation,
        ValidationRun,
    )
    from agent.validation.report import rebuild_report, seal_execution

    suite = load_catalog().suites[1]
    time = now()
    run = ValidationRun(
        suite=suite.label,
        suite_revision=suite.revision,
        mode="live",
        selected=("delegated-database-read",),
        configuration_fingerprint="a" * 64,
        state="finalized",
        created_at=time,
        completed_at=time + timedelta(seconds=1),
    )
    native_run = uuid4()
    observation = ScenarioObservation(
        validation_id=run.validation_id,
        scenario="delegated-database-read",
        scenario_revision=suite.scenarios[0].revision,
        run_id=native_run,
        outcome="pass",
        cleanup="revoked",
        assertions=(
            AssertionResult(
                label="delegated-database-read", outcome="pass", strength="live", effect_attempts=1
            ),
        ),
    )
    vault_binding = PrivateOperationBinding(
        validation_id=run.validation_id,
        observation_id=observation.observation_id,
        run_id=native_run,
        phase="credential",
        source_kind="vault",
        source_instance="synthetic-vault",
        native_request_id="synthetic-request",
        started_at=time,
        finished_at=time + timedelta(seconds=1),
    )
    trace = "a" * 32
    span_ids = ["b" * 16, "c" * 16]
    logfire = [
        PrivateOperationBinding(
            validation_id=run.validation_id,
            observation_id=observation.observation_id,
            run_id=native_run,
            phase="telemetry",
            source_kind="logfire",
            source_instance="synthetic-project",
            trace_id=trace,
            span_id=span,
            parent_span_id=span_ids[0] if i else None,
            started_at=time,
            finished_at=time + timedelta(seconds=1),
        )
        for i, span in enumerate(span_ids)
    ]
    vault_rows = [
        {
            "type": kind,
            "time": time.isoformat(),
            "request": {
                "id": "synthetic-request",
                "path": "database/creds/read",
                "headers": {"x-correlation-id": [str(vault_binding.operation_ref)]},
            },
        }
        for kind in ["request", "response"]
    ]
    rows = [
        {
            "project": "synthetic-project",
            "trace_id": trace,
            "span_id": b.span_id,
            "parent_span_id": b.parent_span_id,
            "start_timestamp": time.isoformat(),
            "attributes": {"validation_id": str(run.validation_id), "run_id": str(native_run)},
        }
        for b in logfire
    ]
    store = PrivateStore(tmp_path / ".local/validation", project=tmp_path)
    with store.create(run.validation_id) as writer:
        writer.write_json("run.json", run)
        writer.write_json(f"observation-{observation.observation_id}.json", observation)
        for binding in [vault_binding, *logfire]:
            writer.append_event(binding, "bindings.jsonl")
        writer.write_json(
            "delivery.json",
            {
                "state": "acknowledged",
                "attempted": [(trace, span) for span in span_ids],
                "acknowledged": [(trace, span) for span in span_ids],
            },
        )
        seal_execution(writer)
        assert rebuild_report(writer).delivery != "received"
        artifacts = []
        for source, raw, instance, label in [
            (
                "vault",
                "\n".join(json.dumps(r) for r in vault_rows),
                "synthetic-vault",
                "vault-jsonl",
            ),
            ("logfire", json.dumps({"rows": rows}), "synthetic-project", "logfire-rows"),
        ]:
            path = tmp_path / f"{source}.json"
            path.write_text(raw)
            manifest = ImportManifest(
                source_kind=source,
                source_instance=instance,
                format_label=label,
                window_start=time - timedelta(seconds=1),
                window_end=time + timedelta(seconds=2),
                completeness="complete",
            )
            artifacts.append(import_source(writer, source, path, manifest))
        report = rebuild_report(writer)
        assert report.delivery == "received" and not report.blockers
        criterion = next(c for c in report.acceptance if c.criterion == "UC1-05")
        record_review(
            writer,
            "UC1-05",
            "pass",
            ReviewInput(
                reviewer="private-reviewer",
                rationale="private-rationale",
                expected_revision=criterion.evidence_revision,
                observed_at=time,
                references=tuple(a.artifact_id for a in artifacts),
            ),
        )
        report = rebuild_report(writer)
        assert next(c for c in report.acceptance if c.criterion == "UC1-05").status == "pass"
        assert "synthetic-project" not in report.model_dump_json()
        # Additional evidence changes the revision rather than silently inheriting a prior decision.
        import_source(writer, "logfire", tmp_path / "logfire.json", artifacts[1].manifest)
        report = rebuild_report(writer)
        criterion = next(c for c in report.acceptance if c.criterion == "UC1-05")
        assert criterion.status == "blocked" and criterion.reason == "review_stale"
