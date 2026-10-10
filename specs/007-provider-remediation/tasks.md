# Tasks: Provider detection and remediation

**Input**: `specs/007-provider-remediation/` specification, plan, research, data model,
contracts and quickstart. Requirements/security review precedes implementation.
**Tests**: Explicitly required by FR-021. Write the relevant behavioral tests before
implementation; use network-denied synthetic fixtures. Live acceptance is independent.
**Format**: `[P]` marks only independent file work after prerequisites; `[USn]` identifies
its independently testable story. Every checkbox is implementation work, not planning progress.

## Phase 1: Setup

Purpose: Establish adapter interfaces, documentation and isolated test support using existing dependencies.

- [X] T001 Record the selected boundaries, rejected alternatives and module/function documentation expectations in docs/adr/0009-provider-remediation.md and add the focused package skeleton in src/agent/response/providers/__init__.py (FR-021, FR-022).

- [X] T002 [P] Create synthetic provider transport/clock/process fixtures with network denied and no local credential loading in tests/provider_support.py (FR-021).


## Phase 2: Foundational contracts and state

Blocks all stories. Preserve 006 ownership, existing recovery receipts and the short cancellation path.

- [X] T003 [P] Add strict-model, scope-widening, unknown-field, capacity and secret-projection regression cases in tests/test_provider_models.py (FR-005, FR-006, FR-018, FR-020, FR-021).

- [X] T004 [P] Add interrupted v1→v2 migration, old-binary rejection, preserved legacy holds and no retrospective dispatch cases in tests/test_provider_migration.py (FR-019, FR-021).

- [X] T005 Implement private enrollment/binding/acquisition/action/observation contracts and closed reason enums in src/agent/response/providers/models.py and response schema variants in src/agent/response/models.py Constraints: "ResponseJournalV2.schema_version = 2; response anchor and source policy stay at 1; recovery journal/attempt stay at 2 and recovery anchor/receipt stay at 1." "UUIDs identify incidents, actions, observations and bindings; revisions and resource generations are strict positive integers; digests are 64 lowercase hexadecimal characters; timestamps are timezone-aware UTC." "Enrollment allows at most 16 source profiles, 32 rules and 64 resource bindings; aliases match ^[a-z][a-z0-9-]{1,31}$; native identifiers are nonempty strings of at most 256 characters." "Provider action kind is block_registration, revoke_native_token, suspend_user, revoke_user_sessions, rotate_static, terminate_static_sessions or notify_teams; each action pins one binding generation and enrollment digest." "Action state is planned, submitted, acknowledged, denied, failed, uncertain or reconciled; a submitted action is never automatically resubmitted; restart converts unfinished submitted actions to uncertain." "Proof state is not_run, proven, disproven, inconclusive, unsupported or not_applicable; HTTP acceptance, timeout, disappearance and token expiry alone never prove enforcement." (FR-001, FR-005, FR-013, FR-019).

- [X] T006 Extend snapshot transactions, provider-policy embedding, reservation, retention pins and actual serialized-size checks in src/agent/response/store.py Constraints: "The snapshot limit is 16 MiB; retain at most 1000 roots, 1000 incidents and 16 non-settled incidents; allow 101 legacy/local actions plus 16 provider-action references per incident and 16 observations per provider action." "Retain resolved provider records for 30 days; pin unresolved actions, holds, observation references and resource generations without age-based deletion; capacity exhaustion rejects new intake before effects." (FR-013, FR-018, FR-019, FR-020).

- [X] T007 Implement offline idempotent migration preserving legacy local-only incidents, original source policy/anchor/recovery bytes and safe lock order in src/agent/response/store.py and src/agent/response/commands.py (FR-019, FR-020).

- [X] T008 Implement owner-only prepare/enrollment, fixed secret references, digest validation, quiescence checks and atomic activation in src/agent/response/providers/enrollment.py; add enrollment tests in tests/test_provider_enrollment.py Constraints: "Private drafts, secrets and state use owner-only files beneath .local/response; secrets never enter command arguments, journal observations, browser output, logs or telemetry; URLs must be fixed enrolled HTTPS origins with redirects disabled." Constraint: "Enrollment rejects duplicate canonical resources keyed by pinned origin, namespace, resource type and native ID, even when binding UUIDs or aliases differ." (FR-001, FR-005, FR-017, FR-018, FR-019).

- [X] T009 Implement deterministic rule-to-action planning, resource generation fences, action dependencies and cross-incident joins in src/agent/response/providers/planner.py; reject shared root targets and preserve legacy lifecycle ownership Constraints: "Target scope is root_run or definition; root_run permits cancel_local, revoke_exact and revoke_native_token with exclusive trusted ownership plus advisory notify_teams; shared security controls never widen scope." "Security-action deduplication uses canonical provider resource, resource generation and action kind; notices use incident UUID, notice revision and destination generation; unresolved predecessors and bindings cannot be pruned or superseded." (FR-004, FR-005, FR-006, FR-008, FR-013).

- [X] T010 Implement one bounded provider worker using inherited worker/effect descriptors, durable submitted intent, restart uncertainty and no mutation replay in src/agent/response/providers/worker.py; test budgets and boundaries in tests/test_provider_worker.py Constraints: "Provider workers have a 120-second total attempt budget including owner drain; each network call has a 10-second deadline and 256-KiB response cap; read-only reconciliation makes at most 3 calls per action per invocation; mutation attempts never auto-retry." (FR-004, FR-013, FR-020, SC-004).

- [X] T011 Wire migrate/providers prepare/enroll/status command hierarchy and documented exit codes in src/agent/response/commands.py and src/agent/cli.py; cover v1 instructions and no-call status in tests/test_provider_cli.py (FR-001, FR-017, FR-019).


## Phase 3: User Story 1 — Attributable native events (P1)

Goal: A verified enrolled event automatically commits one hold and immutable plan. Independent test: native-shaped synthetic delivery, replay/restart and invalid mapping yield the expected incident or zero effects. This is the MVP checkpoint, not completion of 007.

- [X] T012 [P] [US1] Add auth/projection/depth/size/rule/target/secret rejection tests in tests/test_provider_native.py (FR-002, FR-003, FR-021, SC-001).

- [X] T013 [P] [US1] Add canonical duplicate/conflict, revision races, hold-before-acknowledgment and plan-scope tests in tests/test_provider_planner.py (FR-003, FR-004, FR-005, FR-021, SC-001, SC-002).

- [X] T014 [US1] Implement bounded scalar projection, canonical content and source/event replay identity in src/agent/response/native.py Constraints: "Native bodies are at most 65536 bytes, depth 8 and 128 scalar fields; profiles allow at most 8 scalar JSON pointers of at most 256 characters and 8 equality predicates; no scripts, recursive selectors or URL fetching." "Event IDs match ^[A-Za-z0-9_-]{1,128}$; events may be at most 300 seconds old or 30 seconds in the future; duplicate identity is source alias plus event ID; changed canonical security content conflicts." (FR-002, FR-003).

- [X] T015 [US1] Extend src/agent/response/auth.py with native profile authority using the pinned issuer, distinct audience/source namespace, exact subject, access-token purpose, freshness and submit scope; preserve 006 normalized-source permissions Constraint: "Each native profile has at most 64 object mappings, a distinct audience/source namespace and an exact pinned issuer/subject; root correlation must match one host-registered request and its verified binding." (FR-001, FR-002, FR-005).

- [X] T016 [US1] Add authenticated POST /response/native/{profile_alias}, bounded streaming parsing and closed status responses in src/agent/response/api.py; do not expose browser/admin authority (FR-002, FR-003, FR-018, FR-020).

- [X] T017 [US1] Implement source schema/fixture/collector evidence enrollment and explicit missing-route instructions in src/agent/response/providers/enrollment.py; add synthetic-only mappings to config/providers.example.json (FR-001, FR-017, FR-022, SC-005).

- [X] T018 [US1] Integrate native/local source provenance, atomic hold/plan/reservation, worker activation and 2s intake/cancel assertions in src/agent/response/coordinator.py and tests/test_provider_native.py (FR-003, FR-004, FR-013, SC-001, SC-002).


## Phase 4: User Story 2 — Agent and user enforcement (P1)

Goal: Apply exact enrolled identity controls and report limitations independently. Independent test: exercise provider doubles with root/definition/user plans; verify healthy peer preservation, same-JWT denial classification and local subject holds.

- [X] T019 [P] [US2] Add registration/native-token contracts, installed-capability failure, shared/batch-token rejection, duplicate canonical resource aliases and exact readback tests in tests/test_provider_vault.py (FR-006, FR-007, FR-008, FR-021).

- [X] T020 [P] [US2] Add tenant user/session permission, federation scope, partial outcomes and no-automatic-repeat tests in tests/test_provider_verify.py (FR-010, FR-013, FR-021).

- [X] T021 [P] [US2] Add actor-vs-human binding, prospective accessor ownership, unknown acquisition and healthy-peer tests in tests/test_provider_ownership.py (FR-005, FR-006, FR-008, FR-021, SC-003).

- [X] T022 [US2] Capture verified actor identity and enforce exact enrolled definition registration mapping before privileged effects in src/agent/broker.py and src/agent/response/guard.py (FR-005, FR-007, FR-008).

- [X] T023 [US2] Persist NativeTokenAcquisition intent before native login and capture trusted native-service accessor/type/descendant ownership before workload-login result exposure in src/agent/vault.py and src/agent/response/providers/enrollment.py; lost or incomplete acquisitions stay uncertain and block release, enabled paths require trusted ownership, and ordinary OBO remains not_applicable; add a successful-provider/lost-reply crash case Constraint: "Native token acquisition intent is durable before login; states are intent, submitted, bound, denied or uncertain; at most 64 unresolved acquisitions are retained; unknown accessors prevent complete inventory and release." (FR-006, FR-008, FR-013).

- [X] T024 [US2] Implement exact registration deletion, service-accessor revocation and bounded capability/metadata readbacks in src/agent/response/providers/vault.py; no entity-disable substitution or broad token listing (FR-007, FR-008, FR-017).

- [X] T025 [US2] Implement exact Verify user PATCH active=false, session DELETE/GET and safe entitlement/federation readbacks in src/agent/response/providers/verify.py (FR-010, FR-017).

- [X] T026 [US2] Persist subject holds atomically with definition incidents and enforce them at every live root admission/guard in src/agent/response/models.py, src/agent/response/store.py and src/agent/response/guard.py (FR-004, FR-010, FR-013).

- [X] T027 [US2] Close matching workspace sessions on subject holds, cancel/drain before credential disposal and preserve other sessions in src/agent/workspace/sessions.py and src/agent/workspace/runs.py (FR-010, FR-018).

- [X] T028 [US2] Integrate registration/user-first action dependencies, native-token cascade reconciliation and exact lease receipt joins in src/agent/response/providers/planner.py, src/agent/response/providers/worker.py and src/agent/response/coordinator.py (FR-004, FR-007, FR-008, FR-013).

- [X] T029 [US2] Add same-unexpired-JWT, fresh issuance, healthy-provider control, expiry/outage and unexpected-acquisition cleanup, successful-probe adoption crash and definitive-denial sequencing tests in tests/test_provider_identity_proof.py (FR-009, FR-021, FR-022, SC-003).

- [X] T030 [US2] Implement fixed identity proof scenarios and pre-event ephemeral probe session handoff in src/agent/response/providers/proof.py and src/agent/validation/scenarios.py; confine guard bypass to authorized validation and persist separate ProbeAcquisition intent for every possible issuance, close definitive authenticated denial without altering 005 rules, and add idempotent trusted successful-probe adoption in src/agent/recovery/store.py with original ownership/times and crash-safe receipt linkage Constraint: "Probe acquisition intent precedes dispatch; at most 16 active probes exist; authenticated definitive 401/403 without credential material closes as denied_no_issuance, while timeout, malformed reply or missing handle remains uncertain and blocks release." (FR-007, FR-009, FR-010, FR-013, SC-003).


## Phase 5: User Story 3 — Secret and database response (P2)

Goal: Rotate only isolated static roles and observe fresh/open database loss independently. Independent test: exact synthetic role/session fixtures, uncertain rotation and healthy controls; dynamic cleanup remains in existing recovery.

- [X] T031 [P] [US3] Add exact static-role rotation, scheduled-rotation attribution and no-root-rotation tests in tests/test_provider_static.py (FR-011, FR-013, FR-021).

- [X] T032 [P] [US3] Add fixed-SQL, isolated-role ownership, PID/backend_start reuse, privilege, enumeration overflow and pool/shared-role rejection cases in tests/test_provider_database.py (FR-012, FR-020, FR-021).

- [X] T033 [P] [US3] Add old/new-password, independent held-session, outage/network-ban and probe-process-loss tests in tests/test_provider_database_proof.py (FR-011, FR-012, FR-021, SC-003).

- [X] T034 [US3] Implement static-role metadata/capability readiness and exact rotate-role action in src/agent/response/providers/vault.py; only the authorized proof path may read static-creds into memory (FR-011, FR-017).

- [X] T035 [US3] Implement fixed parameterized isolated-static-role enumeration/recheck/termination and read-only privilege diagnostics in src/agent/response/providers/database.py; keep dynamic termination delegated to existing Vault revocation configuration Constraints: "Database session selection requires an enrolled isolated role, database, PID and backend_start; at most 32 sessions may be selected and each termination uses a positive timeout of at most 5000 milliseconds." (FR-012, FR-017, FR-020).

- [X] T036 [US3] Implement dynamic/static before-and-after probes with independent old connections, healthy controls and ephemeral credentials in src/agent/response/providers/proof.py; release effect ownership before waiting for an event and reacquire it for active privileged operations (FR-011, FR-012, FR-013, SC-003).

- [X] T037 [US3] Integrate rotation/session dependencies and joined dynamic cleanup outcomes in src/agent/response/providers/planner.py and src/agent/response/providers/worker.py without inventing legacy DB attribution (FR-008, FR-011, FR-012, FR-013).

- [X] T038 [US3] Add installed revocation-SQL metadata review and isolated-role/healthy-proof setup diagnostics in src/agent/response/providers/enrollment.py; never silently reprovision provider resources (FR-011, FR-012, FR-017, SC-005).


## Phase 6: User Story 4 — Reporting, notification and recovery (P2)

Goal: Make each effect/proof visible, notify Teams and recover deliberately. Independent test: synthetic partial results, imported receipts, clock skew and release/retry races; no live providers required.

- [X] T039 [P] [US4] Add Teams URL secrecy, allowlisted card, accepted-vs-delivered, separate incidents sharing a workflow, root-only advisory notices, timeout and no-auto-resend tests in tests/test_provider_teams.py (FR-015, FR-018, FR-021, SC-007).

- [X] T040 [P] [US4] Add evidence digest/correlation, source classification, stale review, timing and unsupported/partial closeout tests in tests/test_provider_proof.py (FR-016, FR-022, FR-021, SC-005, SC-006).

- [X] T041 [P] [US4] Add revision-bound retry, newer-session risk, old-JWT lifetime restoration, unsupported actor-configuration changes, concurrent-hold and fresh-root-only release tests in tests/test_provider_recovery.py (FR-013, FR-014, FR-021, SC-004, SC-007).

- [X] T042 [US4] Implement Teams Workflows URL-only adapter and distinct accepted/delivery observations in src/agent/response/providers/teams.py; explicit resend creates a linked notice revision Constraints: "Teams cards are at most 8192 bytes and contain only notice UUID, incident UUID, coarse scope, closed outcome codes and valid durations; links, mentions, images, actions and source text are forbidden." (FR-015, FR-018, SC-007).

- [X] T043 [US4] Implement strict 1-MiB private observation import/review, exact source/resource/revision binding and independent outcome aggregation in src/agent/response/providers/proof.py and src/agent/validation/importers.py; preserve existing recovery proof predicates Constraint: "Observation imports are at most 1 MiB; identical observation IDs require identical digests; release observations are at most 300 seconds old unless an immutable event and finite credential-lifetime bound establish safety." (FR-009, FR-016, FR-022).

- [X] T044 [US4] Implement per-control safe reports, bounded timing uncertainty and concrete owner/action/rerun instructions in src/agent/response/providers/report.py and src/agent/validation/report.py Constraints: "Local durations use monotonic time within one process; cross-system intervals require recorded UTC clock bounds of at most 5 seconds per source; negative, expired-proof or cross-restart unbounded intervals are unavailable." (FR-016, FR-017, FR-018, SC-005, SC-006).

- [X] T045 [US4] Implement read-only reconciliation, reviewed uncertainty dispositions and explicit linked retry in src/agent/response/providers/worker.py and src/agent/response/commands.py; never read credentials or send notifications from status/readiness/reconcile (FR-013, FR-014, FR-017, SC-004).

- [X] T046 [US4] Extend local release to provider/subject holds, old-credential safety, fresh evidence and complete-revision checks in src/agent/response/store.py and src/agent/response/commands.py; provider restoration stays guided/manual Constraints: "Release requires the current enrollment and journal revisions, complete hold set, drained owners, resolved required actions, no unresolved attributable recovery and reviewed old-credential safety; old roots remain terminal." (FR-014, FR-019, SC-007).

- [X] T047 [US4] Wire providers readiness/reconcile/retry/import/probe CLI contracts, private stdin proof input and per-scenario authorization in src/agent/response/commands.py; extend tests/test_provider_cli.py for exact commands, exit codes and secret-free errors (FR-009, FR-014, FR-017, FR-018, FR-020).

- [X] T048 [US4] Add session-owned additive provider summaries to src/agent/workspace/models.py, src/agent/workspace/app.py and src/agent/workspace/static/app.js with accessible labels/styles in src/agent/workspace/static/index.html and src/agent/workspace/static/style.css (FR-018, SC-005).

- [X] T049 [US4] Add WebKit tests for subject suspension, other-user isolation, partial/unknown provider state and sign-out/recovery in tests/browser/test_workspace_provider_response.py (FR-010, FR-018, FR-021, SC-005, SC-007).

- [X] T050 [US4] Add closed provider action/outcome telemetry in src/agent/observability.py and src/agent/telemetry.py; no native identity, destination, secret or provider-message attributes (FR-016, FR-018).

- [X] T051 [US4] Extend native evidence closeout with separate F10-T1 through F10-T9 proof predicates and per-path limitations in src/agent/validation/closeout.py; add no automatic acceptance.json promotion (FR-016, FR-022, SC-003, SC-006).


## Phase 7: Cross-cutting validation and documentation

All stories are required. Finish software checks and record live dispositions honestly; a blocked live exercise does not excuse an unbuilt adapter or unchecked software task.

- [X] T052 [P] Add process-death/persistence-failure/timeout/unknown-submission tests across provider operations in tests/test_provider_crash.py (FR-013, FR-020, FR-021, SC-004).

- [X] T053 [P] Add concurrency, retention/capacity, duplicate-resource, lock-order, migration/enrollment/release races and timing-budget regression tests in tests/test_provider_concurrency.py (FR-003, FR-004, FR-013, FR-019, FR-020, FR-021, SC-001, SC-002, SC-004).

- [X] T054 Extend renamed-private-artifact detection for provider enrollment, secret maps, actions, observations, probes and receipts in scripts/publish_policy.py and regression tests in tests/test_provider_privacy.py; verify scripts/check_privacy.py and scripts/check_distribution.py cover staged/build outputs (FR-018, FR-021, SC-005).

- [X] T055 Add network-denied synthetic Function 10 proof matrix and unsupported/live-blocked assertions in tests/test_provider_acceptance.py; cover every story end to end without certifying providers (FR-021, FR-022, SC-001, SC-002, SC-003, SC-004, SC-005, SC-006, SC-007).

- [X] T056 Update README.md concisely and document configuration/migration/commands/repair steps in docs/configuration.md and docs/usage.md; reconcile config/providers.example.json and docs/adr/0009-provider-remediation.md with final implementation (FR-001, FR-014, FR-017, FR-019, FR-021).

- [X] T057 Review all touched modules/functions for purpose, effects, failure and security-ordering comments per AGENTS.md; record threat/compatibility review in specs/007-provider-remediation/validation.md (FR-021, FR-022).

- [X] T058 Run the full applicable software gates and quickstart scenarios from specs/007-provider-remediation/quickstart.md; record exact results and any remaining blockers in specs/007-provider-remediation/validation.md (FR-021, FR-022).

- [X] T059 For each authorized live F10 scenario, run the concrete private probe/evidence workflow or record the exact unavailable prerequisite and operator step in specs/007-provider-remediation/validation.md; update specs/007-provider-remediation/acceptance.json only from reviewed qualifying native evidence (FR-017, FR-022, SC-003, SC-006, SC-007).


## Dependencies and execution order

- T001–T002 establish interfaces/test support; T003–T004 may proceed together afterward.
- T005 → T006 → T007 establishes compatible state; T008 enrollment and T009 plans depend
  on that state. T010 depends on T009; T011 integrates the foundation.
- Every story depends on T001–T011. Inside a story, its test files may be written in
  parallel, then implement in listed order. Test scaffolds may reference planned interfaces;
  passing those tests requires their associated implementation, not stubbing out assertions.
- US1 integrates intake; US2/US3/US4 can use synthetic accepted incidents independently.
  Cross-story edits to planner.py, worker.py, proof.py and commands.py MUST be serialized.
  US2 actor attribution is required before live identity proof; US3 is required before
  full DB proof; US4 integrates their reporting and final release conditions.
- T052–T053 can run concurrently after story implementations. Privacy changes and end-to-end
  acceptance tests follow, then final docs/review/gates/live disposition.
- Source route/auth fixture enrollment, provider capabilities and isolated resources are
  deployment prerequisites, not reasons to omit software tasks.

## Parallel examples per story

| Story | Independent file work after foundation |
| --- | --- |
| US1 | T012 native parsing/auth tests alongside T013 immutable plan/replay tests |
| US2 | T019 Vault tests, T020 Verify tests and T021 ownership tests |
| US3 | T031 static rotation tests, T032 DB targeting tests and T033 proof tests |
| US4 | T039 Teams tests, T040 evidence/timing tests and T041 recovery tests |

Only tasks explicitly marked [P] promise concurrent file independence. Final integration
and shared-file mutations are sequential; this list does not request additional agents.

## Implementation strategy and checkpoints

MVP = foundation plus US1: trusted source delivery automatically commits local containment
and an immutable provider plan with honest provenance. Validate that checkpoint, then
complete US2, US3 and US4; do not report 007 complete at the MVP checkpoint. Provider tests
use fixtures until explicit live authorization and exact resource enrollment are available.
Every implementation task includes module/function documentation of meaningful effects
and failure behavior; avoid changing model-facing tool instructions incidentally.

The last task completes when all native scenarios have a truthful reviewed disposition,
including concrete blocked steps where unavailable. That administrative completion does
not mark the corresponding native acceptance criterion passed. Audit-specific evidence
remains unavailable on the recorded Development tier.

## Requirement coverage

Every task above names its requirement or success-criterion IDs. The table below is an
index for consistency analysis, not a substitute for meaningful tests.

| Requirement / criterion | Tasks |
| --- | --- |

| FR-001 | T005, T008, T011, T015, T017, T056 |

| FR-002 | T012, T014, T015, T016 |

| FR-003 | T012, T013, T014, T016, T018, T053 |

| FR-004 | T009, T010, T013, T018, T026, T028, T053 |

| FR-005 | T003, T005, T008, T009, T013, T015, T021, T022 |

| FR-006 | T003, T009, T019, T021, T023 |

| FR-007 | T019, T022, T024, T028, T030 |

| FR-008 | T009, T019, T021, T022, T023, T024, T028, T037 |

| FR-009 | T029, T030, T043, T047 |

| FR-010 | T020, T025, T026, T027, T030, T049 |

| FR-011 | T031, T033, T034, T036, T037, T038 |

| FR-012 | T032, T033, T035, T036, T037, T038 |

| FR-013 | T005, T006, T009, T010, T018, T020, T023, T026, T028, T030, T031, T036, T037, T041, T045, T052, T053 |

| FR-014 | T041, T045, T046, T047, T056 |

| FR-015 | T039, T042 |

| FR-016 | T040, T043, T044, T050, T051 |

| FR-017 | T008, T011, T017, T024, T025, T034, T035, T038, T044, T045, T047, T056, T059 |

| FR-018 | T003, T006, T008, T016, T027, T039, T042, T044, T047, T048, T049, T050, T054 |

| FR-019 | T004, T005, T006, T007, T008, T011, T046, T053, T056 |

| FR-020 | T003, T006, T007, T010, T016, T032, T035, T047, T052, T053 |

| FR-021 | T001, T002, T003, T004, T012, T013, T019, T020, T021, T029, T031, T032, T033, T039, T040, T041, T049, T052, T053, T054, T055, T056, T057, T058 |

| FR-022 | T001, T017, T029, T040, T043, T051, T055, T057, T058, T059 |

| SC-001 | T012, T013, T018, T053, T055 |

| SC-002 | T013, T018, T053, T055 |

| SC-003 | T021, T029, T030, T033, T036, T051, T055, T059 |

| SC-004 | T010, T041, T045, T052, T053, T055 |

| SC-005 | T017, T038, T040, T044, T048, T049, T054, T055 |

| SC-006 | T040, T044, T051, T055, T059 |

| SC-007 | T039, T041, T042, T046, T049, T055, T059 |
