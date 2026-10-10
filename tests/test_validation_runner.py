import asyncio
import socket
from uuid import UUID

import pytest

from agent.validation.models import Bounds
from agent.validation.runner import run_suite
from agent.validation.store import PrivateStore


@pytest.fixture
def store(tmp_path):
    return PrivateStore(tmp_path / ".local/validation", project=tmp_path)


async def test_offline_ignores_poisoned_environment_and_network(store, monkeypatch):
    for key in [
        "LOGFIRE_TOKEN",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "GOOGLE_API_KEY",
        "PROFILES_FILE",
        "POCDANTIC_PROFILES_FILE",
        "TIMEOUT_SECONDS",
        "POCDANTIC_TIMEOUT_SECONDS",
    ]:
        monkeypatch.setenv(key, "private-invalid-canary")

    def denied(*args, **kwargs):
        raise AssertionError("network forbidden")

    monkeypatch.setattr(socket.socket, "connect", denied)
    report = await run_suite(store=store)
    assert report.completed == report.selected == report.terminal == 9
    assert all(s.outcome == "pass" for s in report.scenarios)
    assert all(c.status == "blocked" for c in report.acceptance)
    assert report.exit_code() == 0
    assert "canary" not in report.model_dump_json()
    with store.open(report.validation_id) as writer:
        assert writer.read_json("run.json")["state"] == "finalized"
        assert writer.read_json("report.json")["revision"] == report.revision


async def test_timeout_and_terminal_projection(store):
    async def slow(*args, **kwargs):
        await asyncio.sleep(3)

    report = await run_suite(store=store, bounds=Bounds(scenario_timeout=1), factory=slow)
    assert len(report.scenarios) == 9
    assert all(s.reason == "scenario_timeout" for s in report.scenarios)
    assert report.exit_code() == 1


async def test_cancel_stops_scheduling_and_preserves_partial_report(store):
    started = asyncio.Event()
    calls = []

    async def slow(label, **kwargs):
        calls.append(label)
        started.set()
        await asyncio.sleep(10)

    task = asyncio.create_task(run_suite(store=store, factory=slow))
    await started.wait()
    task.cancel()
    report = await task
    assert calls == ["delegated-read"]
    assert all(s.outcome == "interrupted" for s in report.scenarios)
    assert report.exit_code() == 130
    with store.open(report.validation_id) as writer:
        assert writer.read_json("run.json")["state"] == "interrupted"


async def test_live_missing_prerequisites_blocks_without_fallback(store):
    from agent.settings import Settings

    settings = Settings.model_construct()
    report = await run_suite(
        store=store, suite_label="live-database", mode="live", settings=settings
    )
    assert all(s.outcome == "blocked" for s in report.scenarios)
    assert report.exit_code() == 2
    assert UUID(str(report.validation_id))


async def test_ten_repeatable_runs_under_budget(store):
    import time

    ids, classifications = set(), []
    for _ in range(10):
        start = time.monotonic()
        report = await run_suite(store=store)
        assert time.monotonic() - start <= 30
        assert report.validation_id not in ids
        ids.add(report.validation_id)
        classifications.append(
            tuple((s.scenario, s.outcome, s.cleanup, s.operation_outcome) for s in report.scenarios)
        )
    assert all(c == classifications[0] for c in classifications)
    assert all(s[1] == "pass" for s in classifications[0])


async def test_two_synthetic_profile_configurations(store, tmp_path):
    import json

    from agent.runtime import load_definitions
    from agent.validation.scenarios import offline_settings

    definitions = load_definitions("config/agents.json")
    for index in range(2):
        path = tmp_path / f"profiles-{index}.json"
        values = [
            d.model_dump(mode="json") | {"instructions": f"Synthetic configuration {index}"}
            for d in definitions.values()
        ]
        path.write_text(json.dumps(values))
        report = await run_suite(
            store=store, settings=offline_settings().model_copy(update={"profiles_file": str(path)})
        )
        assert report.exit_code() == 0


async def test_uncertain_effect_stops_pending_work_without_retry(store):
    from agent.validation.models import Reason
    from agent.validation.scenarios import EffectResult

    calls = []

    async def uncertain(label, **kwargs):
        calls.append(label)
        return EffectResult("fail", 1, reason=Reason.operation_uncertain)

    report = await run_suite(store=store, factory=uncertain)
    assert calls == ["delegated-read"] and report.scenarios[0].outcome == "fail"
    assert all(s.outcome == "blocked" for s in report.scenarios[1:])
