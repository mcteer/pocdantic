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
        external_controls="not_performed",
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
        if command == "init":
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
