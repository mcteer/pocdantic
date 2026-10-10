import json

import pytest

from agent.evidence import CRITERIA
from agent.validation.models import AssertionResult, ScenarioObservation, ValidationRun
from agent.validation.report import assemble, markdown, rebuild_report
from agent.validation.runner import run_suite
from agent.validation.store import PrivateStore


@pytest.mark.parametrize(
    "outcome,code", [("pass", 0), ("blocked", 2), ("fail", 1), ("interrupted", 130)]
)
def test_projection_parity_and_all_criteria(outcome, code):
    run = ValidationRun(
        suite="offline-security",
        suite_revision="a" * 64,
        mode="offline",
        selected=("policy-denial",),
        configuration_fingerprint="b" * 64,
    )
    observation = ScenarioObservation(
        validation_id=run.validation_id,
        scenario="policy-denial",
        scenario_revision="c" * 64,
        outcome=outcome,
        assertions=(AssertionResult(label="policy-denial", outcome=outcome),),
    )
    report = assemble(run, [observation])
    assert report.exit_code() == code
    assert tuple(a.criterion for a in report.acceptance) == CRITERIA
    text = markdown(report).decode()
    assert all(f"| {c} | blocked |" in text for c in CRITERIA)
    assert outcome in text and "<script>" not in text


async def test_rebuild_integrity_and_immutable_revision(tmp_path):
    store = PrivateStore(tmp_path / ".local/validation", project=tmp_path)
    initial = await run_suite(store=store, names=["delegated-read"])
    with store.open(initial.validation_id) as writer:
        report = rebuild_report(writer)
        assert report.revision == initial.revision
        path = next(writer.path.glob("observation-*.json"))
        value = json.loads(path.read_text())
        value["outcome"] = "fail"
        writer.write_json(path.name, value, replace=True)
        report = rebuild_report(writer)
        assert report.exit_code() == 1 and "digest_mismatch" in report.blockers
        assert (writer.path / f"report-{initial.revision}.json").exists()


def test_unfinished_run_recovers_without_effects(tmp_path):
    store = PrivateStore(tmp_path / ".local/validation", project=tmp_path)
    run = ValidationRun(
        suite="offline-security",
        suite_revision="a" * 64,
        mode="offline",
        selected=("delegated-read", "policy-denial"),
        configuration_fingerprint="b" * 64,
        state="running",
    )
    with store.create(run.validation_id) as writer:
        writer.write_json("run.json", run)
    with store.open(run.validation_id) as writer:
        report = rebuild_report(writer)
        assert report.exit_code() == 130 and report.terminal == 2
        assert all(s.outcome == "interrupted" for s in report.scenarios)


def test_ten_thousand_normalized_event_report_budget():
    import time

    from agent.validation.models import NormalizedSourceEvent, now

    run = ValidationRun(
        suite="offline-security",
        suite_revision="a" * 64,
        mode="offline",
        selected=("delegated-read",),
        configuration_fingerprint="b" * 64,
    )
    observation = ScenarioObservation(
        validation_id=run.validation_id,
        scenario="delegated-read",
        scenario_revision="c" * 64,
        outcome="pass",
    )
    events = tuple(
        NormalizedSourceEvent(
            source_event_id=f"synthetic-{i}",
            source_kind="verify",
            source_instance="synthetic",
            observed_at=now(),
            kind="audit",
        )
        for i in range(10000)
    )
    start = time.monotonic()
    report = assemble(run, [observation], evidence_inputs={"events": events, "mapping_version": 1})
    assert time.monotonic() - start <= 5
    assert len(report.acceptance) == 15
