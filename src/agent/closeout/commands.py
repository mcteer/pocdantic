"""Zero-effect operator command registration, dispatch and safe output projection.

This boundary deliberately runs before runtime Settings construction. It reads explicitly
selected private files and fixed evidence roots only, never credentials or guide commands.
"""

import argparse
import json
import time
from uuid import UUID

from .catalog import OWNERS, catalog, guide
from .models import (
    CloseoutError,
    Inventory,
    canonical_uuid,
    decode,
    digest,
    require,
    validate,
)
from .store import Store, deadline_check, operation, read_owned

ACTIONS = {
    "schema_invalid": (
        "Compare the private input with docs/usage.md#poc-closeout and rerun "
        "with the current revision."
    ),
    "source_unsupported": (
        "Ask the source owner for the documented version and exact reviewed "
        "extraction schema, then import a supported original export."
    ),
    "evidence_missing": (
        "Run agent closeout guide for the selected use case; obtain the named "
        "owner's missing original evidence, then recapture."
    ),
    "storage_invalid": (
        "Restore the original owned 0700 private directory and 0600 one-link "
        "files; do not reset or chmod source stores automatically."
    ),
    "capacity_exceeded": (
        "Have the retention owner archive the complete private installation; "
        "preserve history and start a new dossier instead of overwriting "
        "records."
    ),
    "revision_conflict": (
        "Run agent closeout inspect, use its current revision, and retry with a "
        "new operation ID after the other local writer finishes."
    ),
    "integrity_failed": (
        "Restore the complete original private snapshot from its verified "
        "backup; do not edit seals or remove failed evidence."
    ),
    "cleanup_outstanding": (
        "Inspect agent recover status and agent respond status; resolve exact "
        "uncertain cleanup before requesting acceptance."
    ),
    "witness_missing": (
        "Hold the actual readout meeting; import and review its exact "
        "core-digest receipt with the approving participant role, then submit "
        "signoff."
    ),
    "review_stale": (
        "Inspect current applicability; recapture or rebuild a current "
        "assessment/core and review its exact new digest."
    ),
}
DEFAULT_ACTION = (
    "Run agent closeout inspect and guide; resolve the named proof or "
    "review gap before reassessing."
)


class SafeCloseoutParser(argparse.ArgumentParser):
    """Keep invalid private command arguments out of argparse diagnostic output."""

    def error(self, message):
        """Emit one compiled failure, never argparse's source-containing message."""
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "reason": "schema_invalid",
                    "action": ACTIONS["schema_invalid"],
                }
            )
        )
        raise SystemExit(2)

    def parse_known_args(self, args=None, namespace=None):
        """Reject trailing unknown arguments inside the safe closeout boundary."""
        parsed, remaining = super().parse_known_args(args, namespace)
        if remaining:
            self.error("schema_invalid")
        return parsed, remaining


def id_argument(value):
    """Require canonical UUID command text rather than silently normalizing it."""
    return UUID(canonical_uuid(value))


def add_closeout_parser(sub):
    """Register additive local commands with closed selectors and typed mutation revisions."""
    original = sub._parser_class
    sub._parser_class = SafeCloseoutParser
    try:
        parser = sub.add_parser(
            "closeout", help="Guide and privately review end-to-end PoC evidence"
        )
    finally:
        sub._parser_class = original
    commands = parser.add_subparsers(
        dest="closeout_command", required=True, parser_class=SafeCloseoutParser
    )
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--inventory", required=True)
    for name in (
        "amend",
        "capture",
        "import",
        "experiment",
        "measure",
        "assess",
        "review",
        "package",
        "handoff",
        "guide",
        "inspect",
        "report",
    ):
        item = commands.add_parser(name)
        item.add_argument("--dossier", type=id_argument, required=True)
        if name not in {"guide", "inspect", "report"}:
            item.add_argument("--revision", type=int, required=True)
        if name == "amend":
            item.add_argument("--inventory", required=True)
        if name == "capture":
            item.add_argument(
                "--kind",
                choices=["validation", "response", "governance", "regression"],
                required=True,
            )
            item.add_argument("--member", type=id_argument, required=True)
        if name == "import":
            item.add_argument("--manifest", required=True)
            item.add_argument("--input", required=True)
        if name in {"experiment", "measure", "review"}:
            item.add_argument("--input", required=True)
        if name == "measure":
            item.add_argument("--experiment", type=id_argument, required=True)
        if name == "package":
            item.add_argument("--assessment", type=id_argument, required=True)
        if name == "handoff":
            item.add_argument("--package", type=id_argument, required=True)
        if name == "guide":
            selection = item.add_mutually_exclusive_group()
            selection.add_argument("--use-case", choices=catalog()["use_cases"])
            selection.add_argument("--experiment", choices=catalog()["experiments"])
        if name == "report":
            selection = item.add_mutually_exclusive_group(required=True)
            selection.add_argument("--assessment", type=id_argument)
            selection.add_argument("--package", type=id_argument)


def input_json(path):
    """Read one explicit private file without echoing its path or invalid contents."""
    return decode(read_owned(path))


def inspect(store, head):
    """Project safe inventory coverage, private partial IDs and concrete guide actions."""
    inventory = store.inventory(head)
    from .assessment import report
    from .review import PRODUCT_ROLE

    values = [r for r in head.records if r.kind == "assessment"]
    assessed = report(store, head, values[-1].object_id) if values else None
    rows = (
        assessed["criteria"]
        if assessed
        else [
            {
                "criterion": c,
                "proof": "blocked",
                "owners": OWNERS[c],
                "reason": "evidence_missing",
                "action": guide(c[:3])["recheck"],
            }
            for c in catalog()["criteria"]
        ]
    )
    return {
        "schema_version": 1,
        "operation": "inspect",
        "dossier_id": str(head.dossier_id),
        "revision": head.revision,
        "status": assessed["status"] if assessed else "blocked",
        "proof_status": "blocked",
        "criteria": rows,
        "catalog": catalog(),
        "partials": store.partials(head),
        "environment_digest": digest(inventory),
        "profiles": [
            {
                "profile_id": str(p.profile_id),
                "content_digest": digest(p),
                "owner": PRODUCT_ROLE[p.product],
            }
            for p in inventory.sources
        ],
        "objects": object_projection(store, head),
        "action": (
            "Run agent closeout guide for ordered evidence collection and exac"
            "t native prerequisites."
        ),
    }


def object_projection(store, head):
    """Expose exact review hashes without reading out private source content or names."""
    result = []
    for ref in head.records:
        item = {
            "object_id": str(ref.object_id),
            "kind": ref.kind,
            "content_digest": ref.seal_digest,
            "environment_digest": ref.environment_digest,
        }
        if ref.kind == "source":
            source = store.read(head.dossier_id, ref)
            item.update(
                raw_digest=source["raw_digest"],
                schema_digest=source["schema_digest"],
                provenance=source["provenance"],
                extraction_digest=digest(
                    {"facts": source["facts"], "normalized": source["normalized"]}
                ),
            )
        result.append(item)
    return result


async def execute_closeout(args, *, store=None):
    """Keep one shared deadline over dispatch, all source reads and terminal publication."""
    with operation():
        return await _execute_closeout(args, store=store)


async def _execute_closeout(args, *, store=None):
    """Execute the requested local operation, normalizing every failure to safe JSON."""
    store = store or Store()
    try:
        command = args.closeout_command
        if command == "prepare":
            head = store.prepare(validate(Inventory, input_json(args.inventory)))
            result = {
                "schema_version": 1,
                "operation": command,
                "dossier_id": str(head.dossier_id),
                "revision": head.revision,
                "status": "blocked",
                "proof_status": "blocked",
            }
            code = 0
        else:
            head = store.head(args.dossier)
            if hasattr(args, "revision"):
                require(args.revision == head.revision, "revision_conflict")
            if command == "inspect":
                result, code = inspect(store, head), 0
            elif command == "guide":
                result = inspect(store, head) | {
                    "operation": command,
                    "guides": guide(args.use_case or args.experiment),
                }
                code = 0
            elif command == "amend":
                inv = validate(Inventory, input_json(args.inventory))
                ref = store.append(head.dossier_id, head.revision, "inventory", inv)
                result, code = mutation_result(store, head.dossier_id, command, ref), 0
            else:
                result, code = dispatch(store, head, args)
        deadline_check(time.monotonic() + 30)
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return code
    except KeyboardInterrupt:
        print(json.dumps({"status": "interrupted", "reason": "interrupted"}))
        return 130
    except CloseoutError as error:
        print(
            json.dumps(
                {
                    "status": "failed"
                    if error.reason in {"integrity_failed", "evidence_conflict"}
                    else "blocked",
                    "reason": error.reason,
                    "action": ACTIONS.get(error.reason, DEFAULT_ACTION),
                }
            )
        )
        return 1 if error.reason in {"integrity_failed", "evidence_conflict"} else 2
    except Exception:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "reason": "schema_invalid",
                    "action": ACTIONS["schema_invalid"],
                }
            )
        )
        return 2


def mutation_result(store, dossier_id, operation, ref):
    """Return only opaque identity and revision; local success is never native acceptance."""
    result = {
        "schema_version": 1,
        "operation": operation,
        "dossier_id": str(dossier_id),
        "revision": store.head(dossier_id).revision,
        "object_id": str(ref.object_id),
        "content_digest": ref.seal_digest,
        "status": "created",
        "proof_status": "blocked",
    }

    if ref.kind == "measurement":
        value = store.read(dossier_id, ref)
        result.update(
            content_status=value["outcome"], counts=value["counts"], provenance=value["provenance"]
        )
    elif ref.kind in {"package", "handoff"}:
        from .package import report

        value = report(store, store.head(dossier_id), ref.object_id)
        result.update(content_status=value["status"], applicability=value["applicability"])
    return result


def dispatch(store, head, args):
    """Lazy-load pure workflow services; no runtime/provider constructor is reachable."""
    from . import assessment, counting, package, review, sources

    command = args.closeout_command
    if command == "capture":
        ref = sources.capture(store, head, args.kind, args.member)
    elif command == "import":
        ref = sources.import_source(store, head, input_json(args.manifest), read_owned(args.input))
    elif command == "experiment":
        ref = counting.prepare_experiment(store, head, input_json(args.input))
    elif command == "measure":
        ref = counting.measure(store, head, args.experiment, input_json(args.input))
    elif command == "assess":
        ref = assessment.assemble(store, head)
    elif command == "review":
        ref = review.record(store, head, input_json(args.input))
    elif command == "package":
        ref = package.build(store, head, args.assessment)
    elif command == "handoff":
        ref = package.handoff(store, head, args.package)
    elif command == "report":
        result = (
            assessment.report(store, head, args.assessment)
            if args.assessment
            else package.report(store, head, args.package)
        )
        return result, 1 if result["status"] == "failed" or result[
            "applicability"
        ] == "invalid" else 0 if result["status"] == "accepted" and result[
            "applicability"
        ] == "current" else 2
    else:
        raise CloseoutError()
    return mutation_result(store, head.dossier_id, command, ref), 0
