"""Sequential bounded runs with one terminal projection per selection."""

import asyncio
import time
from uuid import uuid4

from ..observability import StoreSink
from ..settings import Settings
from ..telemetry import Telemetry, configure_telemetry
from .catalog import load_catalog, select_suite
from .models import AssertionResult, Bounds, Reason, ScenarioObservation, ValidationRun, digest, now
from .report import rebuild_report, seal_execution
from .scenarios import offline_scenario
from .store import PrivateStore


async def run_suite(
    *,
    store=None,
    suite_label="offline-security",
    names=None,
    mode="offline",
    interactive=False,
    bounds=None,
    settings=None,
    factory=None,
):
    suite, selection = select_suite(load_catalog(), suite_label, names, mode, interactive)
    bounds = bounds or Bounds(scenario_timeout=30 if mode == "offline" else 150)
    store = store or PrivateStore()
    if mode == "live":
        settings = settings or Settings()
    config = {"suite": suite.revision, "bounds": bounds}
    if mode == "offline" and settings is not None:
        from ..runtime import load_definitions

        config["definitions"] = load_definitions(settings.profiles_file)
    if settings is not None and mode == "live":
        config["settings"] = {
            name: getattr(settings, name)
            for name in (
                "profiles_file",
                "workload_definition",
                "model",
                "oauth_provider",
                "oauth_issuer",
                "oauth_audience",
                "vault_addr",
                "vault_namespace",
                "vault_read_path",
                "vault_audience",
                "database_host",
                "database_port",
                "database_name",
                "logfire_base_url",
                "logfire_project",
            )
        }
    run = ValidationRun(
        suite=suite.label,
        suite_revision=suite.revision,
        mode=mode,
        selected=tuple(s.label for s in selection),
        bounds=bounds,
        configuration_fingerprint=digest(config),
        state="running",
    )
    observations = []
    start = time.monotonic()
    interrupted = False
    stop_reason = None
    telemetry = Telemetry()
    with store.create(run.validation_id) as writer:
        writer.write_json("run.json", run)
        writer.write_bytes("events.jsonl", b"")
        telemetry_reason = None
        if mode == "live" and settings.logfire_token:
            from .scenarios import live_preflight

            if not any(live_preflight(settings, s.label) for s in selection):
                try:
                    telemetry = configure_telemetry(settings, private_sink=StoreSink(writer))
                except Exception:
                    telemetry_reason = Reason.prerequisite_missing
            else:
                telemetry_reason = Reason.prerequisite_missing
        for scenario in selection:
            begun = now()
            observation_id = uuid4()
            result = None
            reason = None
            if telemetry_reason:
                outcome, reason = "blocked", telemetry_reason
            elif stop_reason:
                outcome, reason = "blocked", stop_reason
            elif interrupted:
                outcome, reason = "interrupted", Reason.interrupted
            elif time.monotonic() - start >= bounds.suite_timeout:
                outcome, reason = "blocked", Reason.suite_timeout
            else:
                try:
                    if mode == "live":
                        from .scenarios import live_scenario

                        chosen = factory or live_scenario
                    else:
                        chosen = factory or offline_scenario
                    budget = min(
                        bounds.scenario_timeout, bounds.suite_timeout - (time.monotonic() - start)
                    )
                    async with asyncio.timeout(budget):
                        kwargs = {
                            "cleanup_timeout": bounds.cleanup_timeout,
                            "runtime_options": {
                                "event_sink": StoreSink(writer),
                                "definition_ref": store.definition_ref,
                                "validation_id": run.validation_id,
                                "observation_id": observation_id,
                                "telemetry": telemetry,
                            },
                        }
                        if mode == "live":
                            kwargs["settings"] = settings
                        elif settings is not None:
                            kwargs["runtime_options"]["settings"] = settings
                        result = await chosen(scenario.label, **kwargs)
                    outcome, reason = result.outcome, result.reason
                    if reason in {Reason.operation_uncertain, Reason.cleanup_failed}:
                        stop_reason = Reason.operation_uncertain
                except asyncio.CancelledError:
                    interrupted = True
                    outcome, reason = "interrupted", Reason.interrupted
                except TimeoutError:
                    outcome, reason = "fail", Reason.scenario_timeout
                    if mode == "live":
                        stop_reason = Reason.operation_uncertain
                except Exception:
                    outcome, reason = "fail", Reason.agent_run_failed
                    if mode == "live":
                        stop_reason = Reason.operation_uncertain
            observation = ScenarioObservation(
                validation_id=run.validation_id,
                observation_id=observation_id,
                scenario=scenario.label,
                scenario_revision=scenario.revision,
                started_at=begun,
                finished_at=now(),
                outcome=outcome,
                reason=reason,
                request_id=result.request_id if result else None,
                run_id=result.run_id if result else None,
                cleanup=result.cleanup if result else "not_acquired",
                operation_outcome=result.operation_outcome if result else None,
                assertions=(
                    AssertionResult(
                        label=scenario.expected_assertions[0],
                        outcome=outcome,
                        reason=reason,
                        strength="live" if mode == "live" else "local",
                        effect_attempts=result.effect_attempts if result else 0,
                        forbidden_effects=result.forbidden_effects if result else 0,
                    ),
                ),
            )
            observations.append(observation)
            writer.write_json(f"observation-{observation.observation_id}.json", observation)
        run = ValidationRun.model_validate(
            run.model_dump()
            | {"completed_at": now(), "state": "interrupted" if interrupted else "finalized"}
        )
        writer.write_json("run.json", run, replace=True)
        if telemetry.sdk is not None:
            try:
                await asyncio.wait_for(asyncio.to_thread(telemetry.flush), timeout=5)
            except asyncio.CancelledError:
                interrupted = True
                telemetry.delivery.state = "failed"
            except TimeoutError:
                telemetry.delivery.state = "failed"
        writer.write_json(
            "delivery.json",
            {
                "state": telemetry.delivery.state,
                "attempted": sorted(telemetry.delivery.attempted),
                "acknowledged": sorted(telemetry.delivery.acknowledged),
                "spans": list(telemetry.delivery.records.values()),
            },
        )
        if telemetry.sdk is not None:
            try:
                await asyncio.wait_for(asyncio.to_thread(telemetry.shutdown), timeout=5)
            except asyncio.CancelledError:
                interrupted = True
            except TimeoutError:
                pass
        if interrupted and run.state != "interrupted":
            run = run.model_copy(update={"state": "interrupted"})
            writer.write_json("run.json", run, replace=True)
        seal_execution(writer)
        report = rebuild_report(writer)
    return report
