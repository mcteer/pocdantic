"""Installed read-only parser for contributor regression seals, always software evidence.

The runtime never imports or launches contributor scripts. Closed format checks validate
original phase records and their identity/digest closure without adopting a native claim.
"""

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

from .models import Contract, Count, Digest, Id, byte_digest, decode, digest, require, validate

REGRESSION_SELECTORS = {
    "signed-authority": (
        "tests/test_security_regression_identity.py::test_signed_authority_mutations",
        "tests/test_identity.py::test_wrong_identity_claims_rejected",
        "tests/test_identity.py::test_id_token_not_accepted_as_access_token",
        "tests/test_identity.py::test_forged_signature_rejected",
        "tests/test_broker.py::test_invalid_actor_rejected_before_exchange",
        "tests/test_broker.py::test_expanded_or_wrong_delegation_never_reaches_vault",
    ),
    "four-source-escalation": (
        "tests/test_security_regression_escalation.py::test_four_content_sources_cannot_escalate",
        "tests/test_runtime.py::test_injection_cannot_give_child_a_write_tool",
        "tests/test_runtime.py::test_child_profile_cannot_gain_parent_capability",
        "tests/test_security.py::test_request_cannot_supply_authority",
        "tests/test_adapters.py::test_path_injection_never_calls_vault",
    ),
    "permission-intersection": (
        "tests/test_security_regression_policy.py::test_both_privilege_pairings",
        "tests/test_security.py::test_child_cannot_write_even_with_privileged_user",
        "tests/test_broker.py::test_signed_chain_uses_distinct_exact_cleanup_grant",
    ),
    "approval-effects": (
        "tests/test_security_regression_approval.py::test_approval_states_prevent_privileged_effects",
        "tests/test_security.py::test_approval_consumption_is_atomic",
        "tests/test_verify.py::test_mismatched_push_result_denied",
        "tests/test_verify.py::test_denied_push_never_becomes_approved",
        "tests/test_verify.py::test_native_failure_is_unconfirmed_not_denied",
        "tests/test_verify.py::test_poll_deadline_terminalizes_pending_approval",
    ),
    "independent-revocation": (
        "tests/test_security_regression_revocation.py::test_revocation_paths_remain_independent",
        "tests/test_provider_database_proof.py::test_independent_old_new_and_held_session_outcomes",
        "tests/test_provider_database_proof.py::test_fresh_login_denial_needs_native_authentication_and_health",
        "tests/test_provider_database_proof.py::test_open_session_loss_needs_independent_server_signal",
        "tests/test_broker.py::test_failure_and_cancellation_revoke_lease",
        "tests/test_broker.py::test_cleanup_authorization_failure_cannot_report_success",
    ),
    "partial-incident": (
        "tests/test_security_regression_incident.py::test_partial_incident_preserves_holds_and_no_replay",
        "tests/test_provider_worker.py::test_lost_reply_no_automatic_replay",
        "tests/test_provider_worker.py::test_timeout_after_durable_submission_is_uncertain",
        "tests/test_provider_teams.py::test_safe_card_and_distinct_acceptance",
        "tests/test_provider_recovery.py::test_uncertain_without_review_cannot_retry",
    ),
    "confidentiality": (
        "tests/test_security_regression_privacy.py::test_unified_canaries",
        "tests/test_telemetry.py::test_instrumentation_omits_prompts_arguments_and_results",
        "tests/test_telemetry.py::test_native_nested_runtime_and_lifecycle_canaries",
        "tests/test_telemetry.py::test_native_denial_exception_cancellation_canaries",
        "tests/test_adapters.py::test_vault_never_echoes_secret_error_body",
        "tests/test_governance_privacy.py::test_raw_or_scalar_identity_token_is_private",
    ),
    "policy-delta": (
        "tests/test_security_regression_repeatability.py::test_policy_change_is_observed",
        "tests/test_security_regression_repeatability.py::test_authority_set_serialization_is_stable",
    ),
    "stable-identity": (
        "tests/test_security_regression_identity.py::test_hundred_runs_keep_identity_and_reject_remapping",
        "tests/test_runtime.py::test_parent_child_lineage_and_identity",
        "tests/test_runtime.py::test_reserved_context_is_fresh_and_prestart_containment_works",
        "tests/test_provider_ownership.py::test_verified_actor_capture_is_exact",
        "tests/test_provider_native.py::test_root_correlation_rejects_different_verified_actor",
    ),
    "svid-containment": (
        "tests/test_security_regression_containment.py::test_root_and_definition_containment_across_access_paths",
        "tests/test_governance_verifier.py::test_exact_signed_svid_and_negative_claims",
        "tests/test_governance_verifier.py::test_ambiguous_private_and_weak_keys_fail",
        "tests/test_governance_verifier.py::test_duplicate_signed_members_are_rejected",
        "tests/test_governance_negatives.py::test_all_local_negative_classes_are_rejected",
        "tests/test_governance_identity.py::test_unregistered_case_never_bootstraps_or_mints",
        "tests/test_response_guard.py::test_root_scope_and_sibling",
        "tests/test_response_guard.py::test_definition_blocks_new_root",
        "tests/test_response_guard.py::test_live_runtime_hold_precedes_model_dispatch",
        "tests/test_provider_recovery.py::test_release_needs_complete_hold_set_and_admits_only_fresh_roots",
    ),
}
REGRESSION_CASES = tuple(REGRESSION_SELECTORS)
REGRESSION_CATALOG_DIGEST = "8ac9224dd66e379fb129bb060abe2cbe3c6bd02f2b6e8a875a8f27d3d75e3b00"
REGRESSION_PROFILE_DIGESTS = {
    "baseline": "fe346ca7aef52211671fb80db4119b7f33557ccc3a70a93a5a7744030b907537",
    "restricted": "eeda23a74b727193045e4f727899e5f174042f05b037b6f2e338795645cc73a8",
}
REGRESSION_FULL_SELECTION_DIGEST = (
    "b3c8b33167dca5730cd9b565c967f74345248a1a8e72a9b2acaffadfe9dc72aa"
)


class RegressionFrame(Contract):
    """Closed installed counterpart of the contributor version-one protocol frame."""

    schema_version: Literal[1] = 1
    run_id: Id
    content_digest: Digest
    selection_digest: Digest
    seq: Annotated[int, Field(ge=1)]
    kind: Literal["collection", "item", "terminal", "error"]
    profile: Literal["baseline", "restricted"]
    selector: Annotated[str, Field(max_length=512)] | None = None
    node_digest: Digest | None = None
    ordinal: Annotated[int, Field(ge=1, le=10000)] | None = None
    started_at: str | None = None
    finished_at: str | None = None
    phases: Annotated[
        list[Literal["pass", "fail", "skip", "xfail", "xpass", "missing"]], Field(max_length=3)
    ] = []
    counters: dict[Literal["attempted", "issued", "completed", "forbidden"], Count] = {}
    count: Count = 0
    inventory_digest: Digest | None = None
    exit_code: Annotated[int, Field(ge=0, le=255)] | None = None
    reason: Annotated[str, Field(max_length=64)] | None = None


MANIFEST_FIELDS = {
    "schema_version",
    "run_id",
    "content_digest",
    "selection_digest",
    "state",
    "started_at",
    "deadline_at",
    "cases",
    "profiles",
    "complete_catalog",
    "catalog_digest",
    "profile_digests",
    "versions",
    "base_digest",
    "platform",
}
SEAL_FIELDS = {
    "schema_version",
    "run_id",
    "content_digest",
    "selection_digest",
    "artifacts",
    "profile_digests",
    "count",
    "state",
    "finished_at",
    "exit_code",
    "cleanup",
    "reason",
}
FRAME_FIELDS = {
    "schema_version",
    "run_id",
    "content_digest",
    "selection_digest",
    "seq",
    "kind",
    "profile",
    "selector",
    "node_digest",
    "ordinal",
    "started_at",
    "finished_at",
    "phases",
    "counters",
    "count",
    "inventory_digest",
    "exit_code",
    "reason",
}


def timestamp(value):
    """Require a real unambiguous UTC timestamp in the contributor string format."""
    require(isinstance(value, str))
    parsed = datetime.fromisoformat(value)
    require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0)
    return parsed


def identity(value, manifest=None):
    """Reject malformed versions/digests and cross-run frame or seal identities."""
    require(type(value.get("schema_version")) is int and value["schema_version"] == 1)
    for name in ("content_digest", "selection_digest"):
        require(isinstance(value.get(name), str) and re.fullmatch("[0-9a-f]{64}", value[name]))
    if manifest:
        require(
            all(
                value.get(k) == manifest[k]
                for k in ("run_id", "content_digest", "selection_digest")
            ),
            "integrity_failed",
        )


def evaluate(files, object_id):
    """Validate the complete sealed frame inventory and compute software-only disposition."""
    manifest, seal = decode(files["manifest.json"]), decode(files["seal.json"])
    require(set(manifest) == MANIFEST_FIELDS and set(seal) == SEAL_FIELDS, "source_unsupported")
    identity(manifest)
    identity(seal, manifest)
    require(manifest["run_id"] == str(object_id), "integrity_failed")
    require(manifest["state"] == "running" and type(manifest["complete_catalog"]) is bool)
    require(set(manifest["cases"]) <= set(REGRESSION_CASES), "source_unsupported")
    if manifest["complete_catalog"]:
        require(set(manifest["cases"]) == set(REGRESSION_CASES), "integrity_failed")
    require(
        0 < len(manifest["cases"]) <= 256 and len(set(manifest["cases"])) == len(manifest["cases"])
    )
    require(
        manifest["profiles"]
        and set(manifest["profiles"]) <= {"baseline", "restricted"}
        and len(set(manifest["profiles"])) == len(manifest["profiles"])
    )
    require(timestamp(manifest["started_at"]) < timestamp(manifest["deadline_at"]))
    require(timestamp(seal["finished_at"]) >= timestamp(manifest["started_at"]))
    require(seal["profile_digests"] == manifest["profile_digests"], "integrity_failed")
    catalog_verified = manifest["catalog_digest"] == REGRESSION_CATALOG_DIGEST and manifest[
        "profile_digests"
    ] == {p: REGRESSION_PROFILE_DIGESTS[p] for p in manifest["profiles"]}
    if manifest["complete_catalog"] and set(manifest["profiles"]) == {"baseline", "restricted"}:
        catalog_verified &= manifest["selection_digest"] == REGRESSION_FULL_SELECTION_DIGEST
    require(set(manifest["profile_digests"]) == set(manifest["profiles"]))
    for value in list(manifest["profile_digests"].values()) + [
        manifest["catalog_digest"],
        manifest["base_digest"],
    ]:
        require(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value))
    require(isinstance(seal["artifacts"], dict), "integrity_failed")
    expected = {"manifest.json", *[f"{profile}.json" for profile in manifest["profiles"]]}
    require(set(seal["artifacts"]) == expected, "integrity_failed")
    require(
        set(files) <= expected | {"seal.json", "integrity.json", "report.json", ".lock"},
        "integrity_failed",
    )
    for name, expected_digest in seal["artifacts"].items():
        require(name in files and byte_digest(files[name]) == expected_digest, "integrity_failed")
    require(
        seal["state"] in {"completed", "failed", "incomplete", "interrupted"}
        and seal["cleanup"] in {"drained", "unknown"}
    )
    require(type(seal["count"]) is int and 0 <= seal["count"] <= 10000)
    count = 0
    successful = (
        seal["state"] == "completed"
        and seal["cleanup"] == "drained"
        and seal["exit_code"] == 0
        and seal["reason"] is None
    )
    for profile in manifest["profiles"]:
        execution = decode(files[f"{profile}.json"])
        require(set(execution) == {"profile", "frames", "reason", "cleanup", "exit_code"})
        require(
            execution["profile"] == profile
            and isinstance(execution["frames"], list)
            and len(execution["frames"]) <= 20003
        )
        successful &= (
            execution["reason"] is None
            and execution["cleanup"] == "drained"
            and execution["exit_code"] == 0
        )
        selected = {
            selector for case in manifest["cases"] for selector in REGRESSION_SELECTORS[case]
        }
        inventory, nodes, seen = [], set(), set()
        collected, terminal = False, None
        for seq, raw in enumerate(execution["frames"], 1):
            frame = validate(RegressionFrame, raw).model_dump(mode="json")
            identity(frame, manifest)
            require(
                frame["seq"] == seq and frame["profile"] == profile and terminal is None,
                "integrity_failed",
            )
            if frame["kind"] == "collection":
                if frame["node_digest"]:
                    require(
                        not collected
                        and frame["selector"] in selected
                        and frame["ordinal"] == len(inventory) + 1
                        and frame["node_digest"] not in nodes,
                        "integrity_failed",
                    )
                    inventory.append([frame["selector"], frame["node_digest"], frame["ordinal"]])
                    nodes.add(frame["node_digest"])
                else:
                    require(
                        not collected
                        and frame["count"] == len(inventory)
                        and frame["inventory_digest"] == digest(inventory)
                        and {row[0] for row in inventory} == selected,
                        "integrity_failed",
                    )
                    collected = True
            elif frame["kind"] == "item":
                require(
                    collected
                    and frame["ordinal"] is not None
                    and frame["ordinal"] <= len(inventory)
                    and inventory[frame["ordinal"] - 1]
                    == [frame["selector"], frame["node_digest"], frame["ordinal"]]
                    and frame["node_digest"] not in seen,
                    "integrity_failed",
                )
                seen.add(frame["node_digest"])
                count += 1
                successful &= frame["phases"] == ["pass", "pass", "pass"]
            elif frame["kind"] == "terminal":
                terminal = frame
            else:
                successful = False
        require(terminal is not None, "integrity_failed")
        successful &= collected and terminal["count"] == len(seen) == len(inventory)
        successful &= (
            terminal["inventory_digest"] == digest(inventory)
            and terminal["exit_code"] == execution["exit_code"]
        )
    require(count == seal["count"], "integrity_failed")
    if "integrity.json" in files:
        integrity = decode(files["integrity.json"])
        require(
            set(integrity)
            == {"schema_version", "run_id", "content_digest", "selection_digest", "artifacts"}
        )
        identity(integrity, manifest)
        require(set(integrity["artifacts"]) == {"seal.json", "report.json"}, "integrity_failed")
        for name, expected_digest in integrity["artifacts"].items():
            require(
                name in files and byte_digest(files[name]) == expected_digest, "integrity_failed"
            )
    return {
        "software_outcome": "pass" if successful and count and catalog_verified else "fail",
        "catalog_verified": catalog_verified,
        "count": count,
        "complete_catalog": manifest["complete_catalog"],
        "profiles": manifest["profiles"],
    }
