"""Reconstruct honest current/partial software reports and immutable native blockers."""

from pydantic import ValidationError

from .catalog import CASES, policies, selection_digest
from .isolation import content_digest
from .models import (
    GROUPS,
    Frame,
    Integrity,
    Manifest,
    NativeDisposition,
    Reason,
    RegressionError,
    Seal,
    canonical,
    digest,
)
from .store import Store

NEXT_ACTIONS = {
    code: "Preserve this run. Correct the reported contributor boundary and rerun with a new UUID."
    for code in Reason.__args__
}
NEXT_ACTIONS.update(
    {
        "dependency_missing": (
            "Run the locked contributor sync documented in CONTRIBUTING.md, then create a new run."
        ),
        "run_busy": "Wait for the owning process to finish, then inspect the same UUID.",
        "incomplete_run": (
            "Preserve the abandoned run and start a new run; inspection cannot resume work."
        ),
        "not_selected": "Run the complete catalog with both profiles to cover this group.",
        "content_changed": (
            "Inspect the changed maintained bytes and create a new run; preser"
            "ve the old historical result."
        ),
        "native_evidence_required": (
            "Arrange the separately authorized native workflow with the named provider owner."
        ),
        "audit_unavailable": (
            "Use a licensed environment with native audit evidence; demo-tier "
            "audit remains blocked."
        ),
    }
)
NATIVE = [
    (
        "identity",
        "Reviewed signed token, actor and RAR denial evidence",
        "Configure isolated actors; use 008 readiness and 002 delegation checks.",
        "Review rejection and zero downstream issuance for every signed mutation.",
    ),
    (
        "agent",
        "Reviewed integrated escalation evidence",
        "Run authorized UC2 sandbox with hostile prompt, ticket, child result and parameters.",
        "Inspect trusted dispatch and credential evidence for zero forbidden actions.",
    ),
    (
        "vault",
        "Both native privilege pairings with healthy controls",
        "Configure isolated human ACL and agent ceiling pairs plus exact RAR.",
        "Review native path, capability and parameter denials with distinct positive controls.",
    ),
    (
        "identity",
        "Working phone flow and correlated issuance evidence",
        "Use 002/003 approval and denial checks in an authorized sandbox.",
        "Review exact approval binding and zero denied, expired or replayed effects.",
    ),
    (
        "database",
        "Independent JWT, new-login and held-session observations",
        "Use 007 before/event/after reuse proofs with a healthy peer.",
        "Review each old JWT, next issuance, fresh login and held-session result independently.",
    ),
    (
        "integration",
        "Reviewed VIP multi-action route and notification evidence",
        "Use 007 incident checks for duplicates, lost reply and partial completion.",
        "Review retained holds, exact dispatch counts and acceptance versus delivery.",
    ),
    (
        "security",
        "Private provider exports and licensed native audit",
        "Review authorized actual exports; obtain a tier with audit availability.",
        "Check secret exclusion independently; demo-tier audit remains unavailable.",
    ),
    (
        "security",
        "Native before/after permission change evidence",
        "Change one authorized permission while retaining the same control requests.",
        "Review new configuration receipt and expected decision delta.",
    ),
    (
        "vault",
        "One hundred native entity lookups and spoof rejection",
        "Run separately authorized entity-mapping checks with the Vault owner.",
        "Review stable native mapping; Function 13 owns billing experiments.",
    ),
    (
        "security",
        "Licensed SVID verification and both containment scope proofs",
        "Use 008 independent verification and 007 scope/recovery checks.",
        "Review all covered ingress and fresh-root-only recovery with native evidence.",
    ),
]


def native():
    """Return ten compiled read-only blocked rows; software never promotes native proof."""
    return [
        NativeDisposition.model_validate(
            {
                "group": group,
                "outcome": "blocked",
                "owner": owner,
                "reason": "audit_unavailable" if i == 6 else "native_evidence_required",
                "prerequisite": prerequisite,
                "action": action,
                "recheck": recheck,
            }
        ).model_dump(mode="json")
        for i, (group, (owner, prerequisite, action, recheck)) in enumerate(
            zip(GROUPS, NATIVE, strict=True)
        )
    ]


def precedence(outcomes):
    """A failure dominates incomplete, blocked and passed group members."""
    return next(
        (value for value in ("fail", "incomplete", "blocked", "pass") if value in outcomes),
        "incomplete",
    )


def reconstruct(project, writer):
    """Verify identity, exact inventories, artifacts and seal before deriving a public view."""
    from .runner import phase_outcome

    try:
        manifest = Manifest.model_validate(writer.read("manifest.json"))
        if writer.path.name != manifest.run_id:
            raise RegressionError("artifact_mismatch")
        base = {
            "run_id": manifest.run_id,
            "content_digest": manifest.content_digest,
            "selection_digest": manifest.selection_digest,
            "scope": "full" if manifest.complete_catalog else "partial",
            "versions": manifest.versions,
            "started_at": manifest.started_at,
            "native": native(),
        }
        if not (writer.path / "seal.json").exists():
            return base | {
                "state": "incomplete",
                "freshness": "unknown",
                "reason": "incomplete_run",
                "next_action": NEXT_ACTIONS["incomplete_run"],
                "count": 0,
                "cases": [],
                "groups": [
                    {"group": g, "outcome": "incomplete", "reason": "incomplete_run"}
                    for g in GROUPS
                ],
            }, 2
        seal = Seal.model_validate(writer.read("seal.json"))
        for key in ("run_id", "content_digest", "selection_digest", "profile_digests"):
            if getattr(manifest, key) != getattr(seal, key):
                raise RegressionError("artifact_mismatch")
        expected = {"manifest.json", *(f"{p}.json" for p in manifest.profiles)}
        present = {p.name for p in writer.path.iterdir()} - {
            ".lock",
            "report.json",
            "seal.json",
            "integrity.json",
        }
        if set(seal.artifacts) != present or (seal.state == "completed" and expected != present):
            raise RegressionError("artifact_mismatch")
        for name, identity in seal.artifacts.items():
            if digest(writer.read(name)) != identity:
                raise RegressionError("artifact_mismatch")
        if (writer.path / "integrity.json").exists():
            integrity = Integrity.model_validate(writer.read("integrity.json"))
            if any(
                getattr(integrity, key) != getattr(manifest, key)
                for key in ("run_id", "content_digest", "selection_digest")
            ):
                raise RegressionError("artifact_mismatch")
            if set(integrity.artifacts) != {"seal.json", "report.json"}:
                raise RegressionError("artifact_mismatch")
            for name, identity in integrity.artifacts.items():
                if digest(writer.read(name)) != identity:
                    raise RegressionError("artifact_mismatch")
        selected = [c for c in CASES if c.case_id in manifest.cases]
        if (
            len(selected) != len(manifest.cases)
            or manifest.selection_digest != selection_digest(selected, manifest.profiles)
            or manifest.catalog_digest != digest([c.model_dump() for c in CASES])
            or manifest.profile_digests != {p: digest(policies()[p]) for p in manifest.profiles}
        ):
            # A changed catalog is historical, never silently rebound to today's selection.
            return base | {
                "state": seal.state,
                "freshness": "historical",
                "reason": "content_changed",
                "next_action": NEXT_ACTIONS["content_changed"],
                "count": seal.count,
                "cases": [],
                "groups": [
                    {"group": g, "outcome": "incomplete", "reason": "content_changed"}
                    for g in GROUPS
                ],
            }, 1
        selectors = {s for c in selected for s in c.selectors}
        items = []
        operational = seal.reason
        for profile in manifest.profiles:
            name = f"{profile}.json"
            if name not in seal.artifacts:
                operational = operational or "phase_missing"
                continue
            execution = writer.read(name)
            if (
                set(execution) != {"profile", "frames", "reason", "cleanup", "exit_code"}
                or execution["profile"] != profile
            ):
                raise RegressionError("artifact_mismatch")
            inventory, seen, terminal, collected = [], set(), None, False
            inventory_nodes = set()
            for sequence, raw in enumerate(execution["frames"], 1):
                event = Frame.model_validate(raw)
                if (
                    event.seq != sequence
                    or event.run_id != manifest.run_id
                    or event.content_digest != manifest.content_digest
                    or event.selection_digest != manifest.selection_digest
                    or event.profile != profile
                    or terminal is not None
                ):
                    raise RegressionError("artifact_mismatch")
                if event.kind == "collection":
                    if event.node_digest:
                        if (
                            collected
                            or event.selector not in selectors
                            or event.ordinal != len(inventory) + 1
                            or event.node_digest in inventory_nodes
                        ):
                            raise RegressionError("artifact_mismatch")
                        inventory.append([event.selector, event.node_digest, event.ordinal])
                        inventory_nodes.add(event.node_digest)
                    else:
                        if (
                            collected
                            or event.count != len(inventory)
                            or event.inventory_digest != digest(inventory)
                            or set(row[0] for row in inventory) != selectors
                        ):
                            raise RegressionError("artifact_mismatch")
                        collected = True
                elif event.kind == "item":
                    if (
                        not collected
                        or event.ordinal is None
                        or event.ordinal > len(inventory)
                        or inventory[event.ordinal - 1]
                        != [event.selector, event.node_digest, event.ordinal]
                        or event.node_digest in seen
                    ):
                        raise RegressionError("artifact_mismatch")
                    seen.add(event.node_digest)
                    items.append(event)
                elif event.kind == "terminal":
                    terminal = event
                elif event.kind == "error":
                    operational = operational or event.reason or "protocol_invalid"
            if (
                not terminal
                or not collected
                or terminal.count != len(seen)
                or len(seen) != len(inventory)
            ):
                operational = operational or "phase_missing"
            elif (
                terminal.inventory_digest != digest(inventory)
                or terminal.exit_code != execution["exit_code"]
            ):
                raise RegressionError("artifact_mismatch")
            else:
                operational = operational or terminal.reason or execution["reason"]
                if terminal.exit_code:
                    operational = operational or (
                        "test_failed" if terminal.exit_code == 1 else "child_failed"
                    )
            if execution["cleanup"] != "drained":
                operational = "cleanup_unknown"
        if len(items) != seal.count or len(items) > 10000:
            raise RegressionError("artifact_mismatch")
        results = []
        for case in selected:
            for profile in manifest.profiles:
                mapped = [
                    item
                    for item in items
                    if item.profile == profile and item.selector in case.selectors
                ]
                outcomes = [phase_outcome(item.phases) for item in mapped]
                missing = set(case.selectors) - {item.selector for item in mapped}
                outcome = precedence([o for o, _ in outcomes] + (["incomplete"] if missing else []))
                reason = next((r for o, r in outcomes if o == outcome), None) or (
                    "phase_missing" if missing else None
                )
                totals = {
                    key: sum(item.counters[key] for item in mapped if key in item.counters)
                    for key in ("attempted", "issued", "completed", "forbidden")
                    if any(key in item.counters for item in mapped)
                }
                if any(value > 10000 for value in totals.values()):
                    raise RegressionError("limits_exceeded")
                results.append(
                    {
                        "case_id": case.case_id,
                        "profile": profile,
                        "configuration_applicability": case.configuration_applicability,
                        "outcome": outcome,
                        "count": len(mapped),
                        "reason": reason,
                        "severity": case.severity,
                        "owner": case.owner,
                        "reproduction": (
                            "uv run python scripts/run_security_regression.py "
                            f"run --case {case.case_id} --profile {profile}"
                        ),
                        "next_action": NEXT_ACTIONS.get(reason),
                        "counters": {
                            key: sum(item.counters[key] for item in mapped if key in item.counters)
                            for key in ("attempted", "issued", "completed", "forbidden")
                            if any(key in item.counters for item in mapped)
                        },
                    }
                )
        groups = []
        for group in GROUPS:
            members = {c.case_id for c in CASES if group in c.groups}
            rows = [r for r in results if r["case_id"] in members]
            omitted = members - set(manifest.cases)
            outcome = precedence([r["outcome"] for r in rows] + (["incomplete"] if omitted else []))
            groups.append(
                {
                    "group": group,
                    "outcome": outcome,
                    "reason": "not_selected"
                    if omitted
                    else next((r["reason"] for r in rows if r["outcome"] == outcome), None),
                }
            )
        try:
            freshness = (
                "current" if content_digest(project) == manifest.content_digest else "historical"
            )
        except (OSError, RegressionError):
            freshness = "unknown"
        if freshness != "current":
            operational = (
                "content_changed" if freshness == "historical" else "current_content_unavailable"
            )
        if seal.cleanup != "drained":
            operational = "cleanup_unknown"
        has_fail = any(r["outcome"] == "fail" for r in results)
        incomplete = any(r["outcome"] != "pass" for r in results)
        if seal.state == "completed" and (operational or incomplete or not results):
            # A completed claim contradicting its own execution is integrity failure.
            if freshness == "current":
                raise RegressionError("artifact_mismatch")
        code = (
            130
            if seal.reason == "interrupted"
            else 1
            if has_fail
            or operational
            in {
                "test_failed",
                "unexpected_pass",
                "isolation_failed",
                "protocol_invalid",
                "content_changed",
            }
            else 2
            if operational or incomplete or seal.state != "completed"
            else 0
        )
        result = base | {
            "state": seal.state,
            "freshness": freshness,
            "finished_at": seal.finished_at,
            "count": seal.count,
            "reason": operational,
            "next_action": NEXT_ACTIONS.get(operational),
            "cases": results,
            "groups": groups,
            "profile_digests": manifest.profile_digests,
            "cleanup": seal.cleanup,
        }
        if len(canonical(result)) > 8 * 1024 * 1024:
            raise RegressionError("limits_exceeded")
        return result, code
    except ValidationError:
        raise RegressionError("artifact_mismatch") from None


def inspect(project, run_id):
    """Read one existing run under a nonmutating lock; never resume or erase it."""
    with Store(project, readonly=True).open(run_id) as writer:
        result, code = reconstruct(project, writer)
        if (writer.path / "seal.json").exists() and not (writer.path / "integrity.json").exists():
            return result | {
                "state": "incomplete",
                "reason": "incomplete_run",
                "next_action": NEXT_ACTIONS["incomplete_run"],
            }, 2
        return result, code
