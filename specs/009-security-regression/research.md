# Research: Security Regression Validation

**Date**: 2026-10-10. Baseline: merged 008, commit `3560bfbd49a19648c4e494bd6f4b791429f04aae`.
Research was read-only. No customer configuration, private runtime evidence or provider was
accessed. The supplied Function 12 design is the requirements source; this document contains
only a sanitized engineering mapping. Two plan research agents reviewed coverage and tooling.

## Decisions

### R1 — Contributor-only fixed test selection

**Decision**: Add `scripts/run_security_regression.py` and maintained helpers under
`scripts/security_regression/`; reuse pytest and current fixtures. A compiled catalog maps
Function 12 obligations to explicit test-function selectors, expanding all parameters.
The entry point has list, run and report operations; run defaults to a full two-profile selection.

**Rationale**: Existing `agent validate run` is an application-level nine-scenario workflow,
not a pytest execution catalog. Its native import/review contracts and runtime dependencies
need not change to validate software. Existing tests already cover many required boundaries.

**Alternatives**: A new production validation suite would duplicate test orchestration and
put pytest in runtime packaging; a document-only matrix cannot detect renamed/skipped tests;
a filename/collection check cannot establish executed assertions. All are rejected.

### R2 — Isolation before collection

**Decision**: Run selected tests in a temporary snapshot containing only eligible maintained
source/static files, tests, scripts, public configuration, pyproject.toml and uv.lock. Exclude
Git internals, dotenv, .local, design, caches and symlinks. Use snapshot source ahead of the
editable install; clear inherited settings/plugin variables, disable pytest plugin autoload,
and explicitly load the reporting plugin and pytest-asyncio. Install guards before collection:
no customer dotenv/default roots, no external sockets/DNS/HTTPX transports/native DB connects.
Owned temporary Unix sockets and in-process fake transports are permitted. No browser tests
or uncontrolled subprocess fixtures are selected; full repository CI retains WebKit coverage.

**Rationale**: Existing `provider_network_boundary` covers only provider/governance filenames;
`governance_isolation` covers only governance tests. Identity/runtime cases need the same
protections. Python socket patches alone do not stop a native database driver. Snapshot
isolation prevents ordinary fixture defaults from reading the real workspace.

**Alternatives**: Inheriting the user's environment, relying only on autouse fixtures or
turning off network after collection is too late. This is trusted contributor tooling,
not an OS sandbox against deliberately malicious Python. Nested Python test processes must
use the fixed guarded bootstrap; otherwise their selectors are excluded from this matrix.

### R3 — Record actual complete execution

**Decision**: A custom plugin captures the expanded pre-deselection collection and all
setup/call/teardown reports. Parent verifies exact selection, unique item identity, phase
ordering, clean exit and terminal seal. No `-k`, `-m`, last-failed, maxfail, xfail waiver,
arbitrary pytest options or extra plugins are accepted. Shared selectors run once per profile
and their outcomes fan out to every mapped security case/group.

**Rationale**: Exit zero or a passed call phase can conceal skipped parameters, teardown
failures and missing execution. Expected-failure and unexpected-pass statuses cannot pass
security coverage. Test exception text, captured logs and parameter values must not escape.

**Alternatives**: Parsing terminal text or retaining JUnit failure bodies exposes arbitrary
strings. Emit only strict normalized metadata; drain/discard raw stdout/stderr.

### R4 — Content identity and actual policy changes

**Decision**: Hash sorted relative paths plus bytes for the complete eligible runtime,
tests/helpers, scripts/catalog, both fixed policy fixtures, pyproject.toml and uv.lock.
Hash the snapshot before/after execution and current maintained content when reporting.
Record Python/platform and installed dependency versions. Use two compiled profiles:
`baseline` permits ticket projects POC and ALT; `restricted` permits POC only. The same
ALT-1 request has opposite expected authorization outcomes; POC-1 is the common control.
Both policies retain all other runtime restrictions and have no external target.

**Rationale**: `implementation_revision()` is cached and excludes test/config/lockfile
changes. Existing `test_two_synthetic_profile_configurations` changes instructions only,
which does not satisfy the Function 12 policy-change requirement.

**Alternatives**: A Git commit alone misses uncommitted bytes. An arbitrary user policy file
would expand scope and weaken reproducibility. The digest detects accidental drift; neither
it nor an owned local report is a cryptographic attestation against a malicious local owner.

### R5 — Private immutable reports and bounded failure

**Decision**: Reuse `PrivateStore`/`RunWriter` at fixed `.local/security-regression`, wrapped
by stricter ownership/mode/link/schema checks before creating or opening records. Do not
modify existing validation storage semantics. Unique run UUIDs, immutable manifests/results,
exclusive run locks and a terminal seal prevent accidental overwrites. Concurrent distinct
runs are allowed; a report for a locked active run is busy. An unlocked unsealed run is
incomplete, not resumed. Parent owns a process group; child has a wall-clock watchdog.

**Rationale**: Current `read_private` checks type/symlink/size but not uid/mode/link count,
and `private_dirs` chmods existing directories. The wrapper must reject unsafe existing
entries before calling those helpers. Existing source-level privacy gates should also reject
renamed reports, manifests, events and seals by schema, not filename alone.

**Alternatives**: Raw pytest logs, overwriting the last result, free output destinations or
reusing governance/response journals would add privacy and compatibility risks.

### R6 — Native disposition is explicit and read-only

**Decision**: Compile ten native prerequisite records with owner/action/recheck and report
them as blocked. New reports have no native import, acceptance promotion, reviewer override,
provider retry or administrative operation. Existing feature workflows remain available for
separately authorized native checks. Function 13 performs witnessed cross-use-case signoff.

**Rationale**: Local fixtures can prove application rejection, control attribution and safe
uncertainty, but cannot establish actual Vault/Verify/VIP/database enforcement. Existing
demo-tier audit absence cannot be repaired by a software regression harness.

## Coverage inventory and verified gaps

Selectors below are existing file/function pairs; `::name` following a path is another
function in that file. The implementation catalog must contain exact complete selectors.
New gap tests exercise real trusted application adapters with injected synthetic providers;
an independent policy/identity fixture is labeled simulation, never native enforcement.

| F12 test | Existing anchors | Required addition |
| --- | --- | --- |
| T1 identity | tests/test_identity.py::test_wrong_identity_claims_rejected, test_id_token_not_accepted_as_access_token, test_forged_signature_rejected; tests/test_broker.py::test_invalid_user_rejected_before_exchange, test_invalid_actor_rejected_before_exchange, test_expanded_or_wrong_delegation_never_reaches_vault; tests/test_governance_bootstrap.py::test_signed_bootstrap_claims_are_exact | Combined signed-token/actor/RAR mutation matrix asserts zero downstream exchange, issuance and effect; retain valid control. |
| T2 escalation | tests/test_runtime.py::test_injection_cannot_give_child_a_write_tool, test_child_profile_cannot_gain_parent_capability; tests/test_security.py::test_request_cannot_supply_authority; tests/test_adapters.py::test_path_injection_never_calls_vault | Four explicit sources: user prompt, Jira result, child output, changed tool parameters; assert authority/tool/credential boundary, not model prose. |
| T3 policy | tests/test_security.py::test_child_cannot_write_even_with_privileged_user; tests/test_broker.py::test_signed_chain_uses_distinct_exact_cleanup_grant; tests/test_governance_permissions.py::test_ceiling_attribution_requires_all_controls, test_four_paths_require_actual_human_baseline_and_distinct_control | Both human/agent privilege pairings, independent synthetic ACL/ceiling/RAR evaluator, path/capability/parameter negatives and distinct healthy controls. Existing path-based status doubles are not an intersection oracle. |
| T4 approval | tests/test_security.py::test_approval_mutation_replay_expiry_and_wrong_user, test_approval_consumption_is_atomic, test_terminal_approval_cannot_accept_late_success; tests/test_verify.py::test_mismatched_push_result_denied, test_denied_push_never_becomes_approved, test_native_failure_is_unconfirmed_not_denied, test_poll_deadline_terminalizes_pending_approval; tests/test_runtime.py::test_simulated_write_requires_trusted_bound_backend | Join denied/pending/timeout/expiry/replay/action-resource-parameter mutation to zero issuance and execution plus exact-action positive control. |
| T5 reuse | tests/test_provider_database_proof.py::test_independent_old_new_and_held_session_outcomes, test_fresh_login_denial_needs_native_authentication_and_health, test_open_session_loss_needs_independent_server_signal; tests/test_broker.py::test_failure_and_cancellation_revoke_lease, test_cleanup_authorization_failure_cannot_report_success | Joined independent lease/JWT/new-login/held-session/next-issuance outcomes; successful revoke with still-usable JWT/session cannot pass those separate checks. |
| T6 partial failure | tests/test_provider_native.py::test_projection_replay_and_changed_security_conflict; tests/test_provider_worker.py::test_lost_reply_no_automatic_replay, test_timeout_after_durable_submission_is_uncertain; tests/test_provider_teams.py::test_safe_card_and_distinct_acceptance; tests/test_provider_recovery.py::test_uncertain_without_review_cannot_retry | One incident with success plus unknown/failure and visible notification/report outcome, exact dispatch counts and retained holds under duplicate/lost responses. |
| T7 secrecy | tests/test_telemetry.py::test_instrumentation_omits_prompts_arguments_and_results, test_native_nested_runtime_and_lifecycle_canaries, test_native_denial_exception_cancellation_canaries; tests/test_adapters.py::test_vault_never_echoes_secret_error_body; tests/test_publication.py::test_staged_credential_detected_after_worktree_cleaned; tests/test_governance_privacy.py::test_raw_or_scalar_identity_token_is_private | Unified model/context/source/output/error/log/export canary case; new runner streams, manifests, summaries and scanner diagnostics. Never scan host secrets. |
| T8 policy change | tests/test_validation_runner.py::test_ten_repeatable_runs_under_budget, test_two_synthetic_profile_configurations | Real permission delta, two repeats of both profiles, source/test/policy drift and historical report checks. |
| T9 stable identity | tests/test_runtime.py::test_parent_child_lineage_and_identity, test_reserved_context_is_fresh_and_prestart_containment_works; tests/test_provider_ownership.py::test_verified_actor_capture_is_exact; tests/test_provider_native.py::test_root_correlation_rejects_different_verified_actor | 100 actual synthetic executions, distinct request/run/token references, one stable fixture mapping; second-workload alias spoof/remap denied. No native cardinality claim. |
| T10 SVID/containment | tests/test_governance_verifier.py::test_exact_signed_svid_and_negative_claims, test_ambiguous_private_and_weak_keys_fail, test_duplicate_signed_members_are_rejected; tests/test_governance_negatives.py::test_all_local_negative_classes_are_rejected; tests/test_governance_identity.py::test_unregistered_case_never_bootstraps_or_mints; tests/test_response_guard.py::test_root_scope_and_sibling, test_definition_blocks_new_root, test_live_runtime_hold_precedes_model_dispatch; tests/test_provider_recovery.py::test_release_needs_complete_hold_set_and_admits_only_fresh_roots | Joined root/definition scope over model/tool/new invocations, JWT, leases and held sessions; recovery admits fresh roots without restoring old authority. Existing separate-process relying tests remain in full CI. |

Build mapping: F12.01 inventory; .02 schema/auth/TTL/context/approval controls; .03 T1;
.04 T3; .05 T2; .06 T4; .07 T5; .08 T6; .09 T7; .10 T8; .11 severity/owner;
.12 T9; .13 T10 containment; .14 T10 SVID/bootstrap. Each is a first-class catalog mapping.

## Resolved research status

No unresolved technical questions. Existing Python/pytest/Pydantic dependencies suffice.
No runtime package addition or provider API extension is planned. Framework hook references
and lifecycle details are recorded in the runtime contract.
