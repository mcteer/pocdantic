"""Validation commands construct only sanitized stdout projections."""

import json
from pathlib import Path
from uuid import UUID

from .catalog import load_catalog, select_suite
from .models import Bounds, Reason
from .runner import run_suite
from .store import PrivateStore, StoreError


def add_validation_parser(sub):
    parser = sub.add_parser("validate", help="Bounded security validation and private evidence")
    commands = parser.add_subparsers(dest="validation_command", required=True)
    listing = commands.add_parser("list")
    listing.add_argument("--mode", choices=["offline", "live"])
    run = commands.add_parser("run")
    run.add_argument("--suite", default="offline-security")
    run.add_argument("--scenario", action="append")
    run.add_argument("--mode", choices=["offline", "live"], default="offline")
    run.add_argument("--interactive", action="store_true")
    run.add_argument("--root")
    run.add_argument("--scenario-timeout", type=int)
    run.add_argument("--suite-timeout", type=int, default=300)
    run.add_argument("--cleanup-timeout", type=int, default=30)
    for name in ("import", "report", "review"):
        command = commands.add_parser(name)
        command.add_argument("--run", type=UUID, required=True)
        command.add_argument("--root")
        if name == "import":
            command.add_argument("--source", choices=["vault", "verify", "logfire"], required=True)
            command.add_argument("--input", required=True)
            command.add_argument("--manifest", required=True)
        if name == "review":
            from ..evidence import CRITERIA

            command.add_argument("--criterion", choices=CRITERIA, required=True)
            command.add_argument(
                "--decision", choices=["pass", "fail", "blocked", "alternative"], required=True
            )
            command.add_argument("--review-file", required=True)


async def execute_validation(args):
    try:
        if args.validation_command == "list":
            catalog = load_catalog()
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        "suites": [
                            s.model_dump(mode="json")
                            for s in catalog.suites
                            if not args.mode or s.mode == args.mode
                        ],
                    }
                )
            )
            return 0
        if args.validation_command == "run":
            # Selection fails before creating a directory, reading settings or performing preflight.
            select_suite(load_catalog(), args.suite, args.scenario, args.mode, args.interactive)
            bounds = Bounds(
                scenario_timeout=(
                    args.scenario_timeout
                    if args.scenario_timeout is not None
                    else 30
                    if args.mode == "offline"
                    else 150
                ),
                suite_timeout=args.suite_timeout,
                cleanup_timeout=args.cleanup_timeout,
            )
            report = await run_suite(
                store=PrivateStore(args.root),
                suite_label=args.suite,
                names=args.scenario,
                mode=args.mode,
                interactive=args.interactive,
                bounds=bounds,
            )
            print(report.model_dump_json())
            return report.exit_code(operational=True)
        from .report import rebuild_report

        with PrivateStore(args.root).open(args.run) as writer:
            if args.validation_command == "report":
                report = rebuild_report(writer)
                print(report.model_dump_json())
                return report.exit_code()
            if args.validation_command == "import":
                from .importers import import_source
                from .store import decode_json, read_private

                artifact = import_source(
                    writer,
                    args.source,
                    Path(args.input),
                    decode_json(read_private(Path(args.manifest))),
                )
                print(json.dumps({"artifact_id": str(artifact.artifact_id), "status": "imported"}))
                return 0
            if args.validation_command == "review":
                from .review import record_review
                from .store import decode_json, read_private

                review = record_review(
                    writer,
                    args.criterion,
                    args.decision,
                    decode_json(read_private(Path(args.review_file))),
                )
                print(review.public_json())
                return 0
        return 2
    except StoreError as error:
        code = str(error) if str(error) in Reason._value2member_map_ else "storage_error"
        failed = code in {"digest_mismatch", "evidence_contradicted"} or (
            args.validation_command == "import" and code in {"schema_invalid", "limits_exceeded"}
        )
        print(json.dumps({"status": "fail" if failed else "blocked", "reason": code}))
        return 1 if failed else 2
    except ValueError as error:
        code = str(error) if str(error) in Reason._value2member_map_ else "schema_invalid"
        print(json.dumps({"status": "blocked", "reason": code}))
        return 2
    except Exception:
        print(json.dumps({"status": "fail", "reason": "agent_run_failed"}))
        return 1
