# Tasks: Operational reliability

**Input**: Design documents in `specs/005-operational-reliability/`.
**Prerequisites**: spec.md, plan.md, research.md, data-model.md, contracts/runtime.md,
quickstart.md, reviewed requirements checklist, and constitution 1.2.0.
**Tests**: Required by FR-015 and the constitution; write focused regressions before
behavior changes and confirm they fail for the intended reason.
**Organization**: Foundation, independently testable user stories, then cross-cutting validation.
**Format**: `- [ ] Tnnn [P] [USn] action with exact file paths`. `[P]` denotes independent
files/tasks at the stated checkpoint, not permission to skip dependencies.

Root AGENTS.md, its contributor link, and the exact publication-rule change are companion
work already performed during planning. These tasks describe the unimplemented runtime.
A broad commenting pass is a separate future branch after the user's model switch.

## Phase 1: Setup

- [ ] T001 Record the prospective-only migration, three-lock design, evidence trust boundary, synchronous cleanup, and owner-review checklist in docs/adr/0007-operational-recovery.md; update docs/adr/README.md and reference plan.md's threat analysis. Include the module/function documentation convention from AGENTS.md. (FR-005, FR-011, FR-014, FR-016)
- [ ] T002 Create isolated recovery fixtures and subprocess fault hooks in tests/conftest.py and tests/recovery_support.py using synthetic settings/providers and private temporary roots; deny unintended network and local customer configuration. (FR-015)

## Phase 2: Foundation — required before stories

- [ ] T003 Add boundary-model regressions in tests/test_recovery_models.py for strict versions, enums, IDs, limits, secret-free projections, and unknown/duplicate fields. (FR-011, FR-013, FR-014, SC-006)
- [ ] T004 Implement private journal/attempt/receipt models and sanitized projection models in src/agent/recovery/__init__.py and src/agent/recovery/models.py. Enforce: `schema_version is strict integer 1; generated identifiers are UUIDs; timestamps are UTC-aware; unknown fields and duplicate JSON keys are rejected.` Enforce: `environment_digest and evidence digests are 64 lowercase hexadecimal characters; revision is a strict positive integer; every update compares the expected revision.` Enforce: `credential_path is a validated database/creds/ path of at most 256 characters; native request IDs and lease handles are private nonempty strings of at most 1024 characters; a lease handle must match the configured credential path and existing lease-suffix grammar.` Enforce: `attempt state is intent, acquired, cleanup_pending, unresolved, or resolved; resolution is null, revoked, or not_issued; resolved requires a non-null resolution and receipt, and every other state requires null resolution.` Enforce: `public projections exclude native handles, provider request IDs, environment digests, provider addresses, usernames, tokens, passwords, source paths, raw responses, prompts, and task results.` Enforce: `connection is unchecked, observed, blocked, or inconclusive; recovery is not_configured, uninitialized, clear, blocked, or storage_error; active_work is boolean; blocked_count is a nonnegative integer; checked_at is null or UTC-aware; reason_code and next_action use the closed contract mappings.` (FR-005, FR-006, FR-011, FR-013, FR-014)
- [ ] T005 Add private-store tests in tests/test_recovery_store.py for durable intent, missing/partial initialization, damaged/unsupported state, unsafe paths, stale revisions, and disk/fsync failures; assert zero provider calls on failed admission. (FR-005, FR-012, SC-003, SC-007)
- [ ] T006 Implement fixed project-root resolution, environment fingerprint, anchor validation, atomic/fsynced snapshot updates, effect/journal/workspace lock primitives, capacity reservation, and bounded pruning in src/agent/recovery/store.py; reuse reviewed primitives from src/agent/validation/store.py where suitable. Enforce: `a journal contains at most 1000 attempts and 100 unresolved attempts, encodes to at most 2 MiB, retains resolved attempts for at most 7 days, and never prunes an unresolved attempt.` Enforce: `state directories are owner-only 0700 and files are owner-only 0600; symlinks, hardlinks, nonregular files, wrong owners, unsupported versions, and unsafe permissions are rejected.` (FR-005, FR-011, FR-012, FR-013)
- [ ] T007 Add acquisition/cleanup-boundary and shared-entrypoint tests in tests/test_recovery_lifecycle.py, tests/test_broker.py, and tests/test_api.py: intent-before-send, handle-before-SQL, malformed response with handle, cancellation, nested concurrent calls, and no automatic retry. (FR-005, FR-007, FR-009, FR-015, SC-003)
- [ ] T008 Implement journal lifecycle and owner-bound effect-lock handoff in src/agent/recovery/lifecycle.py; integrate src/agent/broker.py, src/agent/vault.py, src/agent/workspace/runs.py, src/agent/cli.py, and src/agent/api.py so every live database entrypoint shares the gate. Reuse one acquisition correlation UUID with existing observers, preserve cleanup despite storage failure, and never journal offline synthetic runs. (FR-005, FR-007, FR-009, FR-012)
- [ ] T009 Add exact synchronous-cleanup and delegated-claim type regressions in tests/test_adapters.py and tests/test_broker.py, rejecting queued completion, wrong lease, omitted/false/string/numeric sync, widened arrays, and extra authority. (FR-006, FR-014, FR-015, SC-004)
- [ ] T010 Implement synchronous revoke and type-aware signed-detail comparison in src/agent/vault.py and src/agent/broker.py; narrowly update config/vault-path-access.schema.json and the example ACL in scripts/provision_database.py without running provisioning or mutating installed policy. Enforce: `cleanup sends sync as strict boolean true and binds required_parameters to lease_id and sync, allowed_parameters.lease_id to the single exact handle, and allowed_parameters.sync to [true]; numeric, string, false, missing, or widened alternatives are rejected.` (FR-006, FR-007, FR-014)
- [ ] T011 Add tested initial enrollment and sanitized status CLI in src/agent/recovery/commands.py, src/agent/cli.py, and tests/test_recovery_cli.py, including exit codes, unchanged repeat-init, partial-state rejection, environment mismatch, and no reset option. Expose missing-state instructions to live entrypoints; do not auto-initialize or claim legacy closure. (FR-001, FR-008, FR-012)

**Checkpoint**: Live acquisition is contained at the shared boundary; explicit initialization
and status work without provider access. Synthetic fixtures remain usable. US1/US2 can
now be implemented with the common storage and contract models.

## Phase 3: US1 — Understand a blocked workspace (P1; MVP)

**Goal**: Show facts, distinct blocks, and exact repair instructions without new credentials.
**Independent test**: Six controlled failure categories give correct actions; checks meet
bounds and perform zero acquisition, SQL, or provider mutation.

- [ ] T012 [P] [US1] Add classification, timeout, cancellation/drain, response-size, fixed-target, and no-side-effect tests in tests/test_workspace_diagnostics.py. (FR-002, FR-003, FR-004, SC-001, SC-002)
- [ ] T013 [P] [US1] Add operational/diagnostic route and ownership regressions in tests/test_workspace_app.py and tests/test_workspace_security.py for cookie, Origin, CSRF, aggregate anonymous status, same-session incident access, and no provider URL inputs. (FR-001, FR-014, SC-006)
- [ ] T014 [US1] Implement fixed configuration/identity/Vault/database checks, sanitized past-failure facts, bounded streaming and worker containment, stale-report handling, and closed reason/action mappings in src/agent/workspace/diagnostics.py and src/agent/workspace/models.py. Enforce: `diagnostic state is observed, failed, unavailable, or inconclusive; category is configuration, reachability, timeout, authorization, sign_in, or recovery; a report contains at most 8 checks and becomes stale after 60 seconds.` Enforce: `diagnostics use at most 10 seconds per check and 30 seconds per request, have one active request per workspace, keep only the latest in-memory report, and acquire no credentials.` (FR-001, FR-002, FR-003, FR-004)
- [ ] T015 [US1] Add operational/diagnostic routes in src/agent/workspace/app.py and accessible status controls in src/agent/workspace/static/index.html, src/agent/workspace/static/app.js, and src/agent/workspace/static/style.css; separate active work from recovery quarantine so diagnosis/login remain usable, preserve session idle/expiry semantics, and retain initial bootstrap gating. (FR-001, FR-004, FR-010, FR-014, SC-001, SC-005)
- [ ] T016 [US1] Add and pass WebKit scenarios in tests/browser/test_workspace_diagnostics.py for all six categories, keyboard controls/live announcements, stale status, simultaneous authentication/recovery blocks, and delayed bootstrap; assert exact observed facts with no unsupported root-cause text. (FR-001, FR-002, FR-003, FR-015, SC-001, SC-002)
- [ ] T017 [US1] Document concrete provider repair paths, required access, expected results, and transport-only check limitations in docs/usage.md and docs/configuration.md; link supported official Supabase Database Settings guidance without private project identifiers or invented provider audit menus. (FR-004, FR-016)

## Phase 4: US2 — Recover safely and continue (P1)

**Goal**: Reconcile only sufficient exact proof, preserve valid sessions, and require new submission.
**Independent test**: Known-lease and correlated-denial cases resolve; unknown/invalid proof
stays blocked; repeated commands are safe and original tasks are never replayed.

- [ ] T018 [P] [US2] Add strict native-proof tests in tests/test_recovery_proof.py for exact policy denial, acquired handle, sync cleanup, missing/HMAC/conflicting IDs, path/namespace/environment mismatch, generic errors, stale revisions/digests, duplicate/ambiguous records, and cross-incident reuse. (FR-006, FR-007, FR-015, SC-004)
- [ ] T019 [P] [US2] Extend operator command tests in tests/test_recovery_cli.py for safe file import/review, exact revoke, missing/denied authority, bounded timeouts, active-effect lock contention, no issuance, and repeat-safe completed commands. (FR-008, FR-009, FR-014, SC-004)
- [ ] T020 [US2] Implement the dedicated native-proof verifier in src/agent/recovery/proof.py and derived proof models in src/agent/recovery/models.py, reusing strict decode/private-file mechanics but not permissive validation correlation or generic error-to-denial mapping. Enforce: `an evidence import is at most 2 files, 2 MiB per file, 200 records total, and nesting depth 16; raw artifacts remain outside the journal and are never copied by recovery.` Enforce: `an imported proof outcome is lease_identified, revoked, or not_issued; it binds one incident revision, environment, operation UUID, native request/response pair, source digests, verifier version 1, review timestamp, and a nonempty reviewer label of at most 64 characters.` (FR-006, FR-007, FR-011, FR-013, SC-004)
- [ ] T021 [US2] Implement import/review and exact revoke commands in src/agent/recovery/commands.py with effect-lock ownership, configured targets only, process-local VAULT_TOKEN, durable derived receipts, and no raw artifact copying, broad revocation, automatic retry, or acceptance promotion. (FR-006, FR-007, FR-008, FR-009, FR-011, FR-014)
- [ ] T022 [US2] Add valid-session/expired-session/sign-out recovery races in tests/test_workspace_runs.py and tests/test_workspace_auth.py, asserting zero automatic jobs, preserved old results, and zero restored authority; verify another session cannot view incident details. (FR-009, FR-010, FR-014, SC-005)
- [ ] T023 [US2] Implement the read-only recovery-check route and current-state admission projection in src/agent/workspace/app.py and src/agent/workspace/runs.py; add Check recovery and safe operator-next-step UI in src/agent/workspace/static/index.html and src/agent/workspace/static/app.js. Apply verified journal updates without restarting or altering valid sessions. (FR-001, FR-008, FR-009, FR-010, FR-014)
- [ ] T024 [US2] Add and pass WebKit recovery scenarios in tests/browser/test_workspace_recovery.py: an idle operator CLI resolves a known incident, Check recovery observes it, a new submission succeeds without new login, and expired/signed-out sessions stay unable to act. (FR-008, FR-009, FR-010, FR-015, SC-004, SC-005)

## Phase 5: US3 — Preserve the safety decision through interruption (P2)

**Goal**: Verify durable containment through process death, restart, storage damage, and contention.
**Independent test**: Kill controlled processes at issuance/cleanup boundaries; restart
never clears uncertainty, restores authority, or silently discards an incident.

- [ ] T025 [P] [US3] Add subprocess kill/restart matrix in tests/test_recovery_crash.py using tests/recovery_support.py, covering before-send, lost response, handle persistence, cleanup intent, completed response before receipt, and durable terminal receipt. (FR-005, FR-007, FR-015, SC-003)
- [ ] T026 [P] [US3] Extend storage/concurrency tests in tests/test_recovery_store.py for root/anchor/snapshot deletion, hardlinks/symlinks, full/oversized state, capacity reservation, pruning, config removal/change, and competing workspace/CLI/API processes. (FR-012, FR-013, FR-015, SC-007)
- [ ] T027 [US3] Integrate workspace lifetime ownership and effect-lock-protected startup conversion of abandoned unfinished attempts to unresolved in src/agent/workspace/app.py and src/agent/recovery/store.py; validate state on every effect admission and report damaged/uninitialized/mismatched storage without auto-creation. (FR-005, FR-007, FR-012, SC-003, SC-007)
- [ ] T028 [US3] Complete and verify capacity/pruning, durability-error containment, and lock retention across canceled or delayed cleanup workers in src/agent/recovery/store.py and src/agent/recovery/lifecycle.py against T025–T026; preserve in-memory exact cleanup when persistence fails and never silently evict unresolved records. (FR-005, FR-012, FR-013, SC-003, SC-007)
- [ ] T029 [US3] Verify legacy entrypoint and migration behavior in tests/test_recovery_cli.py and tests/test_api.py: initial enrollment required only for configured live DB use, existing unresolved state cannot be bypassed by removing configuration, old command/route shapes persist, offline scenarios stay independent, and no historical incident is fabricated or resolved. (FR-005, FR-007, FR-012, FR-016)
- [ ] T030 [US3] Extend tests/browser/test_workspace_recovery.py with process restart, second-workspace rejection, anonymous aggregate status, missing-state errors, and ephemeral session/job history assertions; record the restart matrix in specs/005-operational-reliability/validation.md. (FR-005, FR-010, FR-012, FR-015, SC-003, SC-007)

## Phase 6: Polish and cross-cutting validation

- [ ] T031 Add and run seeded privacy tests in tests/test_recovery_privacy.py and tests/test_publication.py for journal, import errors, browser/CLI projections, captured logs/traces, and forced staging/distribution of recovery files; tighten scripts/publish_policy.py and scripts/check_distribution.py only if a demonstrated gap requires it. (FR-011, FR-014, FR-015, SC-006)
- [ ] T032 Finish docs/usage.md, docs/configuration.md, README.md, and docs/adr/0007-operational-recovery.md with concise entrypoints, exact sync RAR/ACL migration, prospective enrollment limits, no-reset guidance, unsupported native evidence cases, and zero added environment variables; keep AGENTS.md guidance consistent. (FR-004, FR-008, FR-010, FR-012, FR-016)
- [ ] T033 Run the implementation checks in specs/005-operational-reliability/quickstart.md and the applicable .github/workflows/ci.yml gates; inspect the prospective index and distributions, and record actual software results/counts in specs/005-operational-reliability/validation.md. (FR-015, FR-016, SC-001, SC-002, SC-003, SC-004, SC-005, SC-006, SC-007)
- [ ] T034 Record each optional live case from quickstart.md as passed, failed, or blocked with concrete missing access/evidence and review status in specs/005-operational-reliability/validation.md; collect private evidence only for authorized safe checks. Preserve specs/005-operational-reliability/acceptance.json as blocked unless each criterion's actual native evidence/review warrants a change; preserve historical 003/004 gaps. Completion means honest disposition, not manufactured live success. (FR-016, SC-008)
- [ ] T035 Prepare a sanitized security/owner-review and delivery-readiness record in specs/005-operational-reliability/validation.md; verify the required server-side protections and maintainer review before any later merge. Record missing controls as a delivery block, not a waiver or unfinished runtime implementation, and do not push/merge without current user scope. (FR-016, SC-008)

## Dependencies and execution order

- T001–T002 precede foundation. Foundation executes T003→T004→T005→T006→T007→T008→T009→T010→T011.
- All stories depend on foundation. US1 tests T012/T013 can be authored concurrently;
  T014→T015→T016→T017 completes US1. US2 proof/CLI work can start independently of US1
  after foundation, but T023 requires T015's routes/UI and T020–T022. T024 follows T023.
- US3 tests T025/T026 use foundation and can be authored independently of US2. T027/T028
  require those tests and T023's final admission wiring; T029/T030 then validate the final system.
- T031–T035 follow the story checkpoints. T034 can finish with explicitly blocked native
  acceptance; T035 can finish recording a delivery block. Neither authorizes a merge.
- Shared files must be edited sequentially. `[P]` applies only within the explicit pairs
  below, after common fixtures are ready; no concurrent edits to tests/conftest.py.

## Parallel examples

- US1: T012 tests/test_workspace_diagnostics.py alongside T013 route/security test files.
- US2: T018 tests/test_recovery_proof.py alongside T019 tests/test_recovery_cli.py.
- US3: T025 tests/test_recovery_crash.py alongside T026 tests/test_recovery_store.py.

## Implementation strategy

Deliver the foundation and US1 first for an independently demonstrable diagnostic MVP.
Then add US2 proof/recovery and US3 process-interruption validation; completion of US1
alone does not complete 005. Maintain focused test-first increments, documented function
contracts, and no secret-bearing debug output. Use synthetic fault injection for the
complete matrix; live evidence is a separately reviewed disposition.

## Requirement and success-criterion coverage

| Requirement | Task IDs |
|---|---|
| FR-001 | T011, T013, T014, T015, T016, T023 |
| FR-002 | T012, T014, T016 |
| FR-003 | T012, T014, T016 |
| FR-004 | T012, T014, T015, T017, T032 |
| FR-005 | T001, T004, T005, T006, T007, T008, T025, T027, T028, T029, T030 |
| FR-006 | T004, T009, T010, T018, T020, T021 |
| FR-007 | T007, T008, T010, T018, T020, T021, T025, T027, T029 |
| FR-008 | T011, T019, T021, T023, T024, T032 |
| FR-009 | T007, T008, T019, T021, T022, T023, T024 |
| FR-010 | T015, T022, T023, T024, T030, T032 |
| FR-011 | T001, T003, T004, T006, T020, T021, T031 |
| FR-012 | T005, T006, T008, T011, T026, T027, T028, T029, T030, T032 |
| FR-013 | T003, T004, T006, T020, T026, T028 |
| FR-014 | T001, T003, T004, T009, T010, T013, T015, T019, T021, T022, T023, T031 |
| FR-015 | T002, T007, T009, T016, T018, T024, T025, T026, T030, T031, T033 |
| FR-016 | T001, T017, T029, T032, T033, T034, T035 |
| SC-001 | T012, T015, T016, T033 |
| SC-002 | T012, T016, T033 |
| SC-003 | T005, T007, T025, T027, T028, T030, T033 |
| SC-004 | T009, T018, T019, T020, T024, T033 |
| SC-005 | T015, T022, T024, T033 |
| SC-006 | T003, T013, T031, T033 |
| SC-007 | T005, T026, T027, T028, T030, T033 |
| SC-008 | T034, T035 |

35 tasks: setup 2, foundation 9, US1 6, US2 7, US3 6, polish 5. All are
unimplemented checklist items. Three disjoint test-authoring pairs provide parallel
opportunities. All 16 functional requirements and 8 success criteria have task coverage.
