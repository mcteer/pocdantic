"""Reviewed exact selectors, fixed synthetic policies and blocked native prerequisites."""

import ast
from pathlib import Path

from .models import BUILDS, GROUPS, Case, RegressionError, digest


def case(identifier, group, builds, selectors, boundary, owner, rationale, sensitive=False):
    """Compile one reviewed mapping; no runtime caller may supply a test expression."""
    return Case(
        case_id=identifier,
        groups=[f"F12-T{group}"],
        build_items=[f"F12.{b:02}" for b in builds],
        selectors=selectors,
        boundary=boundary,
        owner=owner,
        severity="high",
        configuration_applicability="profile-sensitive" if sensitive else "fixed",
        expectations=["positive-control", "reject-forbidden-effects"],
        rationale=rationale,
    )


CASES = [
    case(
        "signed-authority",
        1,
        [1, 2, 3, 11],
        [
            "tests/test_security_regression_identity.py::test_signed_authority_mutations",
            "tests/test_identity.py::test_wrong_identity_claims_rejected",
            "tests/test_identity.py::test_id_token_not_accepted_as_access_token",
            "tests/test_identity.py::test_forged_signature_rejected",
            "tests/test_broker.py::test_invalid_actor_rejected_before_exchange",
            "tests/test_broker.py::test_expanded_or_wrong_delegation_never_reaches_vault",
        ],
        "identity",
        "identity",
        (
            "Signed mutations must stop at the appropriate trusted boundary wi"
            "th no credential issuance."
        ),
    ),
    case(
        "four-source-escalation",
        2,
        [5],
        [
            (
                "tests/test_security_regression_escalation.py::test_four_content_s"
                "ources_cannot_escalate"
            ),
            "tests/test_runtime.py::test_injection_cannot_give_child_a_write_tool",
            "tests/test_runtime.py::test_child_profile_cannot_gain_parent_capability",
            "tests/test_security.py::test_request_cannot_supply_authority",
            "tests/test_adapters.py::test_path_injection_never_calls_vault",
        ],
        "model",
        "agent",
        (
            "Untrusted text cannot add child tools, alter trusted policy or di"
            "spatch forbidden effects."
        ),
        True,
    ),
    case(
        "permission-intersection",
        3,
        [4],
        [
            "tests/test_security_regression_policy.py::test_both_privilege_pairings",
            "tests/test_security.py::test_child_cannot_write_even_with_privileged_user",
            "tests/test_broker.py::test_signed_chain_uses_distinct_exact_cleanup_grant",
        ],
        "vault",
        "vault",
        (
            "Independent synthetic ACL intersection plus actual delegated adap"
            "ter checks; no native certification."
        ),
        True,
    ),
    case(
        "approval-effects",
        4,
        [6],
        [
            (
                "tests/test_security_regression_approval.py::test_approval_states_"
                "prevent_privileged_effects"
            ),
            "tests/test_security.py::test_approval_consumption_is_atomic",
            "tests/test_verify.py::test_mismatched_push_result_denied",
            "tests/test_verify.py::test_denied_push_never_becomes_approved",
            "tests/test_verify.py::test_native_failure_is_unconfirmed_not_denied",
            "tests/test_verify.py::test_poll_deadline_terminalizes_pending_approval",
        ],
        "approval",
        "identity",
        "Every invalid approval remains unusable at the trusted execution boundary.",
    ),
    case(
        "independent-revocation",
        5,
        [7],
        [
            (
                "tests/test_security_regression_revocation.py::test_revocation_pat"
                "hs_remain_independent"
            ),
            (
                "tests/test_provider_database_proof.py::test_independent_old_new_a"
                "nd_held_session_outcomes"
            ),
            (
                "tests/test_provider_database_proof.py::test_fresh_login_denial_ne"
                "eds_native_authentication_and_health"
            ),
            (
                "tests/test_provider_database_proof.py::test_open_session_loss_nee"
                "ds_independent_server_signal"
            ),
            "tests/test_broker.py::test_failure_and_cancellation_revoke_lease",
            "tests/test_broker.py::test_cleanup_authorization_failure_cannot_report_success",
        ],
        "database",
        "database",
        "Lease cleanup, JWT reuse, new login and held session require independent results.",
    ),
    case(
        "partial-incident",
        6,
        [8],
        [
            (
                "tests/test_security_regression_incident.py::test_partial_incident"
                "_preserves_holds_and_no_replay"
            ),
            "tests/test_provider_worker.py::test_lost_reply_no_automatic_replay",
            "tests/test_provider_worker.py::test_timeout_after_durable_submission_is_uncertain",
            "tests/test_provider_teams.py::test_safe_card_and_distinct_acceptance",
            "tests/test_provider_recovery.py::test_uncertain_without_review_cannot_retry",
        ],
        "incident",
        "integration",
        "Durable workers retain unknown outcomes and holds; acceptance is distinct from delivery.",
    ),
    case(
        "confidentiality",
        7,
        [9],
        [
            "tests/test_security_regression_privacy.py::test_unified_canaries",
            "tests/test_telemetry.py::test_instrumentation_omits_prompts_arguments_and_results",
            "tests/test_telemetry.py::test_native_nested_runtime_and_lifecycle_canaries",
            "tests/test_telemetry.py::test_native_denial_exception_cancellation_canaries",
            "tests/test_adapters.py::test_vault_never_echoes_secret_error_body",
            "tests/test_governance_privacy.py::test_raw_or_scalar_identity_token_is_private",
        ],
        "publication",
        "security",
        (
            "Injected secret canaries are discarded at adapter, telemetry, pub"
            "lication and report boundaries."
        ),
    ),
    case(
        "policy-delta",
        8,
        [10],
        [
            "tests/test_security_regression_repeatability.py::test_policy_change_is_observed",
            "tests/test_security_regression_repeatability.py::test_authority_set_serialization_is_stable",
        ],
        "tool",
        "security",
        "Actual compiled policy changes ALT permission while preserving the POC control.",
        True,
    ),
    case(
        "stable-identity",
        9,
        [12],
        [
            (
                "tests/test_security_regression_identity.py::test_hundred_runs_kee"
                "p_identity_and_reject_remapping"
            ),
            "tests/test_runtime.py::test_parent_child_lineage_and_identity",
            "tests/test_runtime.py::test_reserved_context_is_fresh_and_prestart_containment_works",
            "tests/test_provider_ownership.py::test_verified_actor_capture_is_exact",
            "tests/test_provider_native.py::test_root_correlation_rejects_different_verified_actor",
        ],
        "identity",
        "vault",
        (
            "One hundred real synthetic runs retain verified identity binding "
            "with distinct invocation IDs."
        ),
    ),
    case(
        "svid-containment",
        10,
        [13, 14],
        [
            (
                "tests/test_security_regression_containment.py::test_root_and_defi"
                "nition_containment_across_access_paths"
            ),
            "tests/test_governance_verifier.py::test_exact_signed_svid_and_negative_claims",
            "tests/test_governance_verifier.py::test_ambiguous_private_and_weak_keys_fail",
            "tests/test_governance_verifier.py::test_duplicate_signed_members_are_rejected",
            "tests/test_governance_negatives.py::test_all_local_negative_classes_are_rejected",
            "tests/test_governance_identity.py::test_unregistered_case_never_bootstraps_or_mints",
            "tests/test_response_guard.py::test_root_scope_and_sibling",
            "tests/test_response_guard.py::test_definition_blocks_new_root",
            "tests/test_response_guard.py::test_live_runtime_hold_precedes_model_dispatch",
            (
                "tests/test_provider_recovery.py::test_release_needs_complete_hold"
                "_set_and_admits_only_fresh_roots"
            ),
        ],
        "governance",
        "security",
        (
            "Independent signed SVID verification and durable holds deny cover"
            "ed ingress without restoring old roots."
        ),
    ),
]
EXCLUSIONS = {
    (
        "tests/test_governance_identity_flow.py::test_separate_process_ver"
        "ifies_once_without_mint_credentials"
    ): (
        "Uncontrolled child environment; use independent verifier negative"
        "s here; full pytest retains process coverage."
    ),
    "tests/browser": (
        "WebKit retained in full CI; no browser state enters contributor regression children."
    ),
    ("tests/test_publication.py::test_staged_credential_detected_after_worktree_cleaned"): (
        "Publication scanner invokes nested Python; full CI retains it; re"
        "gression privacy checks call the scanner in process."
    ),
}


def policies():
    """Hash the actual fixed Policy objects, including unchanged default resource ceilings."""
    from dataclasses import asdict

    from agent.security import Policy

    return {
        name: {key: sorted(value) for key, value in asdict(policy).items()}
        for name, policy in {
            "baseline": Policy(ticket_projects=frozenset({"POC", "ALT"})),
            "restricted": Policy(ticket_projects=frozenset({"POC"})),
        }.items()
    }


def validate(project, cases=None, complete=True):
    """Resolve selectors statically without collecting or executing arbitrary modules."""
    cases = CASES if cases is None else cases
    if not 1 <= len(cases) <= 256 or len({c.case_id for c in cases}) != len(cases):
        raise RegressionError("catalog_invalid")
    selectors = {s for c in cases for s in c.selectors}
    if len(selectors) > 512:
        raise RegressionError("limits_exceeded")
    if complete and (
        {g for c in cases for g in c.groups} != set(GROUPS)
        or {b for c in cases for b in c.build_items} != set(BUILDS)
    ):
        raise RegressionError("catalog_invalid")
    for selector in selectors:
        parts = selector.split("::")
        try:
            tree = ast.parse((Path(project) / parts[0]).read_bytes())
            body = tree.body
            for name in parts[1:]:
                node = next(
                    n
                    for n in body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    and n.name == name
                )
                body = node.body
        except (OSError, SyntaxError, StopIteration):
            raise RegressionError("catalog_invalid") from None
        if parts[0].startswith("tests/test_security_regression_") and parts[1] not in {
            "test_signed_authority_mutations",
            "test_four_content_sources_cannot_escalate",
            "test_both_privilege_pairings",
            "test_approval_states_prevent_privileged_effects",
            "test_revocation_paths_remain_independent",
            "test_partial_incident_preserves_holds_and_no_replay",
            "test_unified_canaries",
            "test_policy_change_is_observed",
            "test_authority_set_serialization_is_stable",
            "test_hundred_runs_keep_identity_and_reject_remapping",
            "test_root_and_definition_containment_across_access_paths",
        }:
            raise RegressionError("catalog_invalid")
    return sorted(selectors)


def select(groups=None, identifiers=None, profile=None):
    """Select only compiled IDs and reject duplicates before creating any state."""
    groups, identifiers = groups or [], identifiers or []
    if groups and identifiers:
        raise RegressionError("unknown_selection")
    for values, allowed in ((groups, GROUPS), (identifiers, [c.case_id for c in CASES])):
        if len(set(values)) != len(values) or any(v not in allowed for v in values):
            raise RegressionError("unknown_selection")
    if profile is not None and profile not in policies():
        raise RegressionError("unknown_selection")
    selected = [
        c
        for c in CASES
        if (not groups or set(groups).intersection(c.groups))
        and (not identifiers or c.case_id in identifiers)
    ]
    if not selected:
        raise RegressionError("empty_selection")
    return selected, [profile] if profile else ["baseline", "restricted"]


def selection_digest(cases, profiles):
    """Bind reviewed descriptors and actual policy bytes, not merely profile names."""
    return digest(
        {"cases": [c.model_dump() for c in cases], "profiles": {p: policies()[p] for p in profiles}}
    )
