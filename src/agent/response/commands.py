"""Local incident commands with fixed private paths and concrete safe repair instructions.

The OS user is the operator authority; provenance labels do not authenticate. No reset,
provider-selected action, token argument, or alternative state root is exposed.
"""

import json
from uuid import UUID

from agent.settings import Settings

from .coordinator import Coordinator
from .models import REASONS, ResponseError, RiskSignal
from .store import ResponseStore


def add_response_parser(subparsers):
    """Register the bounded local control interface; serve remains loopback-only."""
    parser = subparsers.add_parser("respond", help="Contain and inspect trusted incidents")
    commands = parser.add_subparsers(dest="response_command", required=True)
    init = commands.add_parser("init", help="Enroll local incident controls")
    init.add_argument("--prepare", action="store_true")
    status = commands.add_parser("status", help="Inspect without provider calls")
    status.add_argument("--incident", type=UUID)
    submit = commands.add_parser("submit", help="Persist a local-operator incident")
    submit.add_argument("--event-id", required=True)
    submit.add_argument("--occurred-at", required=True)
    submit.add_argument(
        "--reason", required=True, choices=["suspected_compromise", "policy_violation"]
    )
    target = submit.add_mutually_exclusive_group(required=True)
    target.add_argument("--run", type=UUID)
    target.add_argument("--definition")
    reconcile = commands.add_parser(
        "reconcile", help="Observe existing cleanup proof, never replay"
    )
    reconcile.add_argument("--incident", type=UUID, required=True)
    release = commands.add_parser(
        "release", help="Release current local definition holds after cleanup"
    )
    release.add_argument("--definition", required=True)
    release.add_argument("--incident", type=UUID, action="append", required=True)
    release.add_argument("--revision", type=int, required=True)
    release.add_argument("--operator", required=True)
    commands.add_parser("migrate", help="Offline idempotent response journal upgrade")
    providers = commands.add_parser("providers", help="Manage exact private provider enrollment")
    provider_commands = providers.add_subparsers(dest="provider_command", required=True)
    provider_commands.add_parser(
        "prepare", help="Create private non-overwriting draft and secret map"
    )
    enroll = provider_commands.add_parser(
        "enroll", help="Atomically activate a reviewed private draft"
    )
    enroll.add_argument("--revision", type=int, required=True)
    provider_status = provider_commands.add_parser(
        "status", help="Inspect enrollment without provider calls"
    )
    provider_status.add_argument("--incident", type=UUID)
    for name in ("reconcile", "import"):
        operation = provider_commands.add_parser(
            name, help="Read or record independent provider evidence"
        )
        operation.add_argument("--incident", type=UUID, required=True)
        operation.add_argument("--revision", type=int, required=True)
        if name == "import":
            operation.add_argument("--file", required=True)
            operation.add_argument("--operator", required=True)
    retry = provider_commands.add_parser(
        "retry", help="Create one explicitly reviewed linked action"
    )
    retry.add_argument("--action", type=UUID, required=True)
    retry.add_argument("--revision", type=int, required=True)
    retry.add_argument("--operator", required=True)
    from typing import get_args

    from .providers.models import Scenario

    probe = provider_commands.add_parser("probe", help="Run one explicit fixed independent proof")
    correlation = probe.add_mutually_exclusive_group(required=True)
    correlation.add_argument("--root", type=UUID)
    correlation.add_argument("--incident", type=UUID)
    probe.add_argument("--revision", type=int, required=True)
    probe.add_argument("--scenario", choices=get_args(Scenario), required=True)
    probe.add_argument("--operator", required=True)
    provider_commands.add_parser("readiness", help="Inspect provider setup requirements")
    serve = commands.add_parser("serve", help="Loopback trusted relay intake and bounded worker")
    serve.add_argument("--port", type=int, default=8002)


def report(store, item):
    """Project private opaque correlation and independent controls, never native handles."""
    result = store.summary(item).model_dump(mode="json")
    result.update(
        source=item.source,
        event_id=item.event_id,
        target=item.target.model_dump(mode="json"),
        revision=item.revision,
        source_at=item.source_at.isoformat(),
        received_at=item.received_at.isoformat(),
        contained_at=item.contained_at.isoformat(),
        source_age_ms=int((item.received_at - item.source_at).total_seconds() * 1000),
        source_age_label="source_to_receipt_utc_age",
        local_cancellation=next(a.status for a in item.actions if a.kind == "cancel_local"),
        timings={
            "cancel_request_ms": item.cancel_ms,
            "cleanup_ms": item.cleanup_ms,
            "worker_ms": item.worker_ms,
            "unavailable_reason": "timing_unavailable"
            if any(x is None for x in (item.cancel_ms, item.cleanup_ms, item.worker_ms))
            else None,
        },
        external_controls="per_control" if result["provider_controls"] else "not_performed",
        native_audit="unavailable_on_recorded_tier",
        actions=[
            {
                "action_id": str(a.action_id),
                "kind": a.kind,
                "status": a.status,
                "reason_code": a.reason_code,
                "recovery_incident_id": str(a.target_id) if a.kind == "revoke_exact" else None,
            }
            for a in item.actions
        ],
    )
    repairs = []
    for action in item.actions:
        if action.kind == "revoke_exact" and action.status != "confirmed":
            repairs.append(
                f"agent recover status; agent recover revoke --incident {action.target_id}; "
                f"agent respond reconcile --incident {item.incident_id}"
            )
    if item.reason_code in {"legacy_unattributed", "acquisition_uncertain"}:
        repairs.append(
            "agent recover status; obtain reviewed native evidence for the unresolved "
            "recovery incident before importing it"
        )
    from .providers.report import instructions

    result["provider_instructions"] = instructions(store.read(), item.incident_id)
    state = store.read()
    if any(p.incident_id == item.incident_id for p in getattr(state, "provider_plans", ())):
        from agent.validation.closeout import provider_closeout

        result["provider_closeout"] = provider_closeout(state, item.incident_id)
    result["instructions"] = repairs or (
        [
            "Inspect current holds and revision with agent respond status "
            "before a local definition release"
        ]
        if result["contained"]
        else []
    )
    return result


async def execute_response(args, *, settings=None, project=None, store=None, transport=None):
    """Execute a local command and print safe JSON; acceptance and cleanup are distinct."""
    store = store or ResponseStore(settings or Settings(), project=project)
    worker = Coordinator(store, transport=transport)
    try:
        command = args.response_command
        if command == "migrate":
            changed = store.migrate()
            output = {
                "schema_version": 1,
                "status": "migrated" if changed else "current",
                "next_action": "agent respond providers prepare",
            }
            code = 0
        elif command == "providers":
            from .providers.enrollment import digest, draft, enroll, prepare, readiness

            subcommand = args.provider_command
            state = store.read()
            if state.schema_version != 2:
                raise ResponseError("response_schema_migration_required")
            if subcommand == "prepare":
                prepare(store)
                output = {
                    "schema_version": 1,
                    "status": "prepared",
                    "next_action": (
                        "Edit .local/response/providers.draft.json; run providers readiness; "
                        "use agent respond providers enroll --revision from agent respond status"
                    ),
                }
                code = 0
            elif subcommand == "enroll":
                state = enroll(store, draft(store), args.revision)
                output = {"schema_version": 1, "status": "enrolled", "revision": state.revision}
                code = 0
            elif subcommand == "probe":
                import sys

                from agent.validation.store import decode_json

                from .providers.models import ProofInput
                from .providers.workflow import isolated_probe, run_probe

                if sys.stdin.isatty():
                    raise ResponseError("provider_evidence_invalid")
                raw = sys.stdin.buffer.read(1048577)
                try:
                    if len(raw) > 1048576:
                        raise ValueError()
                    inputs = ProofInput.model_validate(decode_json(raw))
                except Exception:
                    raise ResponseError("provider_evidence_invalid") from None
                operation = isolated_probe if transport is None else run_probe
                output = await operation(
                    store,
                    inputs=inputs,
                    root_id=args.root,
                    incident_id=args.incident,
                    revision=args.revision,
                    scenario=args.scenario,
                    operator=args.operator,
                    **({"transport": transport} if transport is not None else {}),
                )
                code = 0 if output["reason_code"] == "provider_state_observed" else 4
            elif subcommand == "readiness":
                if transport is None:
                    from .providers.models import ProofInput
                    from .providers.workflow import isolated_probe

                    output = await isolated_probe(store, inputs=ProofInput(), operation="readiness")
                    findings = output["instructions"]
                else:
                    findings = await readiness(store, transport=transport)
                    output = {
                        "schema_version": 1,
                        "instructions": findings,
                        "revision": store.read().revision,
                    }
                code = (
                    0 if all(f["reason_code"] == "provider_state_observed" for f in findings) else 3
                )
            elif subcommand == "reconcile":
                from .providers.worker import Worker

                await Worker(store, transport=transport).reconcile(args.incident, args.revision)
                item = worker.reconcile(args.incident)
                output = report(store, item)
                code = 0 if item.phase == "settled" else 4
            elif subcommand == "retry":
                from .providers.worker import reviewed_retry

                action = await reviewed_retry(
                    store, args.action, args.revision, args.operator, transport=transport
                )
                if action.state == "planned":
                    await worker.process(action.incidents[0])
                    from .providers.worker import get_action

                    action = get_action(store.read(), action.action_id)
                output = {
                    "schema_version": 1,
                    "action_id": str(action.action_id),
                    "state": action.state,
                    "revision": store.read().revision,
                }
                code = 0 if action.state in {"acknowledged", "reconciled"} else 4
            elif subcommand == "import":
                from agent.recovery.models import now
                from agent.validation.importers import provider_observation_input
                from agent.validation.models import canonical
                from agent.validation.store import decode_json

                from .providers.models import Observation, require
                from .providers.proof import import_observation

                raw = provider_observation_input(args.file)
                try:
                    value = decode_json(raw)
                    require(isinstance(value, dict), "provider_evidence_invalid")
                    observation = Observation.model_validate(
                        value | {"reviewer": args.operator, "reviewed_at": now()}
                    )
                    require(observation.incident_id == args.incident, "provider_evidence_invalid")
                    # Operator review is assigned here, never inherited from untrusted input.
                    existing = next(
                        (
                            o
                            for a in (*state.provider_actions, *state.probe_acquisitions)
                            for o in a.observations
                            if o.observation_id == observation.observation_id
                        ),
                        None,
                    )
                    if existing:
                        require(
                            existing.reviewer == args.operator
                            and existing.model_dump(exclude={"reviewer", "reviewed_at"})
                            == observation.model_dump(exclude={"reviewer", "reviewed_at"}),
                            "provider_evidence_invalid",
                        )
                        reviewed = existing
                    else:
                        reviewed = Observation.model_validate(
                            observation.model_dump()
                            | {"reviewer": args.operator, "reviewed_at": now()}
                        )
                except ValueError:
                    raise ResponseError("provider_evidence_invalid") from None
                changed = import_observation(store, canonical(reviewed), args.revision)
                output = {
                    "schema_version": 1,
                    "status": "imported" if changed else "duplicate",
                    "revision": store.read().revision,
                }
                code = 0
            else:
                policy = state.enrollment
                output = {
                    "schema_version": 1,
                    "revision": state.revision,
                    "enrolled": policy is not None,
                    "enrollment_digest": digest(policy) if policy else None,
                    "binding_count": len(policy.bindings) if policy else 0,
                    "source_count": len(policy.sources) if policy else 0,
                }
                if getattr(args, "incident", None):
                    output["incident"] = report(store, worker.get(args.incident))
                code = 0
        elif command == "init":
            store.prepare() if args.prepare else store.initialize()
            output = {
                "schema_version": 1,
                "status": "prepared" if args.prepare else "initialized",
                "next_action": "Edit .local/response/policy.json locally, then agent respond init"
                if args.prepare
                else "agent respond status",
            }
            code = 0
        elif command == "submit":
            target = (
                {"kind": "root_run", "root_run_id": args.run}
                if args.run
                else {"kind": "definition", "workload_definition": args.definition}
            )
            try:
                event = RiskSignal(
                    event_id=args.event_id,
                    occurred_at=args.occurred_at,
                    reason=args.reason,
                    target=target,
                )
            except ValueError:
                raise ResponseError("signal_invalid") from None
            item, new = worker.submit(event)
            output = report(store, item) | {"accepted": True, "duplicate": not new}
            code = 0
        elif command == "status":
            state = store.read()
            items = [worker.get(args.incident)] if args.incident else state.incidents
            output = {
                "schema_version": 1,
                "revision": state.revision,
                "storage_schema_version": state.schema_version,
                "next_action": "agent respond migrate"
                if state.schema_version != 2
                else "agent respond providers status",
                "generation": state.generation,
                "restricted": bool(state.holds or state.root_holds),
                "roots": [
                    {
                        "root_run_id": str(r.root_run_id),
                        "state": r.state,
                        "generation": r.generation,
                    }
                    for r in state.runs
                ],
                "holds": [h.model_dump(mode="json") for h in state.holds],
                "incidents": [report(store, i) for i in items],
            }
            code = 1 if state.holds or any(i.phase != "settled" for i in items) else 0
        elif command == "reconcile":
            item = worker.reconcile(args.incident)
            output = report(store, item)
            code = 0 if item.phase == "settled" else 1
        elif command == "release":
            output = worker.release(
                args.definition, args.incident, args.revision, args.operator
            ).model_dump(mode="json")
            code = 0
        else:
            raise ResponseError("signal_invalid")
        print(json.dumps(output))
        return code
    except ResponseError as error:
        reason = str(error)
        print(
            json.dumps({"schema_version": 1, "reason_code": reason, "next_action": REASONS[reason]})
        )
        if args.response_command in {"providers", "migrate"}:
            return 2 if reason in {"signal_invalid", "provider_evidence_invalid"} else 3
        return (
            1
            if reason
            in {
                "contained",
                "response_busy",
                "release_unsafe",
                "revision_conflict",
                "response_capacity",
            }
            else 2
        )

    except Exception:
        # Private filesystem, child and provider exception text never reaches the CLI.
        reason = (
            "provider_uncertain"
            if args.response_command == "providers"
            else "response_storage_error"
        )
        print(
            json.dumps({"schema_version": 1, "reason_code": reason, "next_action": REASONS[reason]})
        )
        return 3 if args.response_command == "providers" else 2
