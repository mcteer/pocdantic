# Tasks: Security Regression Validation

**Input**: spec.md, plan.md, research.md, data-model.md and contracts/runtime.md.
**Tests**: Required by this testing feature and the constitution; test boundaries before implementing them.
**Status**: All forty software tasks complete; native acceptance remains blocked. `[P]` permits independent file work only after prerequisites.

## Phase 1: Setup

Create documented contributor tooling boundaries and synthetic helpers; no provider effects.

- [X] T001 Create documented script entry/package boundaries in scripts/run_security_regression.py and scripts/security_regression/__init__.py; keep installed agent commands and packaging unchanged. (FR-015, FR-016).

- [X] T002 [P] Create shared fixed policies, effect counters and isolated injected-service support in tests/security_regression_support.py and extend tests/conftest.py isolation for the new test family under ordinary pytest; baseline allows POC/ALT and restricted allows POC, with no ambient configuration. (FR-004, FR-011, SC-003).

## Phase 2: Foundation

Strict records, immutable private storage, isolated snapshot and bounded execution precede all story integration.

- [X] T003 [P] Add invalid identifiers/enums/coercion/duplicate JSON/depth/capacity tests in tests/test_security_regression_models.py before model implementation. (FR-010, FR-012, FR-013).

- [X] T004 Implement strict catalog/run/collection/item/seal/report records in scripts/security_regression/models.py, including all fields and relations in data-model.md and the closed reason list. Constraint C01: "Schema version is the integer 1; run IDs are canonical UUIDs, content/selection/node/artifact digests are 64 lowercase hexadecimal characters, and timestamps are timezone-aware UTC." Constraint C02: "Case IDs match `[a-z][a-z0-9-]{0,47}`; test groups are exactly F12-T1 through F12-T10; build items are exactly F12.01 through F12.14; profiles are exactly baseline or restricted." Constraint C04: "Boundary is one of model, tool, identity, approval, vault, database, incident, governance, publication or reporting; severity is critical, high, medium or low; owner is agent, identity, vault, database, security or integration; configuration applicability is fixed or profile-sensitive." Constraint C05: "Case expectations are 1–16 compiled assertion codes of at most 48 lowercase alphanumeric/hyphen characters; optional effect counters are strict integers from 0 to 10,000 and accept only attempted, issued, completed and forbidden keys." Constraint C06: "Run state is running, completed, failed, interrupted or incomplete; item/case/group outcome is pass, fail, blocked or incomplete; freshness is current, historical or unknown; all native dispositions are blocked." Constraint C13: "Native prerequisite/action/recheck text is compiled, each 1–512 characters; software/version labels are 1–128 ASCII alphanumeric or .+!_- characters from an allowlisted package-name set, with at most 32 version entries and no filesystem paths." Constraint C15: "Item ordinals are strict integers from 1 to 10,000; result counts are strict integers from 0 to 10,000; exit code is absent or a strict integer from 0 to 255; cleanup outcome is drained or unknown; full-selection flags are strict booleans." Constraint C16: "JSON nesting is at most 8 levels; protocol event kinds are collection, item, terminal or error; phase states are pass, fail, skip, xfail, xpass or missing; unsupported fields and duplicate JSON keys are rejected." (FR-001, FR-010, FR-012, FR-013, FR-014).

- [X] T005 [P] Add unsafe-root/file, copied-run, immutable-write, lock, inode and corrupt-seal tests in tests/test_security_regression_store.py before storage integration. (FR-010, FR-012, SC-005).

- [X] T006 Implement strict preflight wrapper around existing PrivateStore/RunWriter in scripts/security_regression/store.py at fixed .local/security-regression; check modes before inherited helpers can chmod and retain unsealed runs without resume. Constraint C09: "Metadata frames are at most 16 KiB and carry a strict positive sequence number; manifests and final reports are each at most 8 MiB, artifacts at most 10 MiB each, and the run at most 100 MiB with at most 100 artifacts." Constraint C10: "Private directories are owned mode 0700; files are owned mode 0600 regular single-link entries; symlinks, path traversal, unsafe existing modes, inode replacement and overwrite of immutable records are rejected." Constraint C14: "Records are immutable after writing; an active run is exclusively locked, an unlocked run lacking a valid terminal seal is incomplete, and report inspection never resumes execution, prunes prior runs or changes acceptance." (FR-010, FR-012, FR-013).

- [X] T007 [P] Add pre-collection poisoned-env/dotenv/private-state/network/native-driver/subprocess/unsafe-copy/import-origin tests in tests/test_security_regression_isolation.py, including a caught connection denial that still fails isolation. (FR-011, SC-005).

- [X] T008 Implement eligible maintained-file snapshot, fresh content digest, minimal environment, explicit plugin loading and pre-collection guards in scripts/security_regression/isolation.py; include new maintained files and reject symlink/private artifacts; use fixed Git/guarded-Python subprocess allowlists. (FR-010, FR-011, SC-005).

- [X] T009 [P] Add process-group deadline, parent-death watchdog, partial-output, malformed/oversized metadata and drain tests in tests/test_security_regression_execution.py with disposable child fixtures. (FR-012, FR-013, SC-004, SC-005).

- [X] T010 Implement owned sequential profile children, dedicated normalized channel, raw-stream discard, child watchdog, TERM/KILL/reap and terminal sealing in scripts/security_regression/runner.py; no completion while owned work remains. Constraint C07: "A run selects 1–256 distinct cases and 1–2 distinct profiles; at most 10,000 expanded item results exist across the run, and shared selectors execute once per profile." Constraint C08: "Execution has a fixed 600-second total deadline including collection and both profiles, followed by at most 10 seconds to terminate, kill and drain the owned process group; no user option increases either bound." Constraint C09: "Metadata frames are at most 16 KiB and carry a strict positive sequence number; manifests and final reports are each at most 8 MiB, artifacts at most 10 MiB each, and the run at most 100 MiB with at most 100 artifacts." (FR-010, FR-011, FR-012, FR-013).

## Phase 3: US1 — Complete executable coverage

Independent checkpoint: fixture catalogs and phase streams reject missing, skipped, duplicate or incomplete execution. Full real catalog validation follows the gap tests in US2/US3.

- [X] T011 [P] [US1] Add catalog completeness, renamed selector, shared-selector deduplication, recursive meta-test exclusion and parameter expansion tests in tests/test_security_regression_catalog.py. (FR-001, FR-002, SC-001).

- [X] T012 [US1] Implement compiled fourteen-build/ten-group inventory in scripts/security_regression/catalog.py with reviewed existing selectors, named gap selectors, rationale, owner/severity and fixed/profile-sensitive applicability. Unimplemented selectors must fail coverage, never use placeholders that pass. Constraint C03: "The catalog contains 1–256 unique cases and at most 512 unique selectors; each case has 1–32 selectors, 1–10 distinct groups and 1–14 distinct build items; selectors are repository-relative test file/function names of at most 256 characters with no parameter expressions or command options." (FR-001, FR-002, FR-013, SC-001).

- [X] T013 [US1] Extend tests/test_security_regression_execution.py with collection-only, empty/deselected/missing parameter, skipped/xfail/xpass, setup/call/teardown, repeated/foreign item and missing terminal seal cases. (FR-002, FR-012, FR-013, SC-001).

- [X] T014 [US1] Implement pre/post-collection and normalized pytest result hooks in scripts/security_regression/plugin.py; map shared items to cases, retain raw node IDs only in memory and validate all selected phases before pass. Constraint C11: "A passing expanded item has exactly one setup, call and teardown phase in order, all passing without skip, xfail or xpass; passing also requires unchanged selection/content, zero process exit and a matching terminal seal." Constraint C12: "Failure reasons are selected from the closed contract list; public results contain only run/case/group/profile identifiers, digests, UTC times, bounded counts, outcomes, freshness, severity, owner and compiled next actions, never raw test text or parameter values." (FR-002, FR-009, FR-013).

- [X] T015 [US1] Add list/run argument, default two-profile selection, partial label, closed exit and forbidden arbitrary pytest/secret/path flag tests in tests/test_security_regression_catalog.py. (FR-002, FR-011, FR-013, FR-015).

- [X] T016 [US1] Wire list/run commands and safe errors in scripts/run_security_regression.py using scripts/security_regression/catalog.py and runner.py; emit fixed reproduction commands from known IDs only. (FR-001, FR-002, FR-012, FR-013, FR-015).

## Phase 4: US2 — Authority and escalation

Independent checkpoint: real trusted application paths with injected providers assert valid controls and zero forbidden dispatch; no report or live environment required.

- [X] T017 [P] [US2] Add signed identity/actor/purpose/expiry/RAR mutation integration cases in tests/test_security_regression_identity.py; reuse existing verifier/broker fixtures and assert rejection plus zero downstream exchange/issuance/effects for each mutation. (FR-003, SC-002).

- [X] T018 [P] [US2] Add test_four_content_sources_cannot_escalate in tests/test_security_regression_escalation.py using actual parent/child tool paths for prompt, Jira result, child output and changed tool parameters; assert forbidden tool/credential/effect counters and permitted read control. (FR-004, SC-002).

- [X] T019 [P] [US2] Add independent synthetic ACL/ceiling/RAR oracle and test_both_privilege_pairings in tests/test_security_regression_policy.py; high-human/narrow-agent and inverse pairing must each cover path/capability/parameter negatives and healthy controls without claiming native enforcement. (FR-004, SC-002).

- [X] T020 [P] [US2] Add test_approval_states_prevent_privileged_effects in tests/test_security_regression_approval.py; exercise denied/pending/timeout/expired/replayed/action-resource-parameter mutations through trusted approval-to-issuance/effect boundary and exact-action positive control. (FR-005, SC-002).

- [X] T021 [US2] Add test_hundred_runs_keep_identity_and_reject_remapping in tests/test_security_regression_identity.py: execute100 real synthetic runtime invocations with distinct request/run/token references, one stable approved fixture mapping and second-workload spoof/remap rejection. (FR-008, SC-003).

- [X] T022 [US2] Finalize US2 selectors and assertion rationale in scripts/security_regression/catalog.py; map approval-effects to the complete approval matrix and verify all expanded parameters execute under both profiles. (FR-001, FR-002, FR-003, FR-004, FR-005, FR-008, SC-001, SC-002).

## Phase 5: US3 — Failure containment and confidentiality

Independent checkpoint: compose existing worker/guard/proof/report functions with synthetic provider failures; assert independent path outcomes, exact effects and no canary leakage.

- [X] T023 [P] [US3] Add test_revocation_paths_remain_independent in tests/test_security_regression_revocation.py; combine exact lease cleanup, new-login denial, held-session state, still-valid JWT and next-issuance control, including missing healthy signal and unknown cleanup. (FR-006, SC-002).

- [X] T024 [P] [US3] Add test_partial_incident_preserves_holds_and_no_replay in tests/test_security_regression_incident.py; compose actual incident/worker/report flow with one success, one unknown/failure, duplicate events/lost reply and separately classified notification acceptance/delivery. (FR-007, SC-002).

- [X] T025 [P] [US3] Add test_root_and_definition_containment_across_access_paths in tests/test_security_regression_containment.py; cover model/tool/new runs/JWT/lease/held-session paths, unaffected sibling for root scope, all covered ingress for definition scope and deliberate fresh-root-only recovery. (FR-006, FR-007, FR-008, SC-002).

- [X] T026 [P] [US3] Add unified source/model-context/output/exception/log/telemetry/report canaries and scanner-output checks in tests/test_security_regression_privacy.py, reusing existing privacy helpers without reading real secrets or private application state. (FR-009, FR-011, SC-005).

- [X] T027 [US3] Finalize US3 and independent SVID/bootstrap selectors in scripts/security_regression/catalog.py; reuse actual verifier negatives and record excluded browser/uncontrolled subprocess checks with safe selected substitutes and full-CI references. (FR-001, FR-002, FR-006, FR-007, FR-008, FR-009, SC-001, SC-002).

## Phase 6: US4 — Repeatable reporting and honest handoff

Independent checkpoint: fixture manifests/results verify per-case/group aggregation, drift, safe failure ownership and ten blocked native rows before full execution integration.

- [X] T028 [P] [US4] Add report aggregation, latest-run independence, missing/extra/corrupt/copied artifacts, historical/unknown content and partial-selection tests in tests/test_security_regression_report.py; test all ten groups independently and no native promotion. (FR-010, FR-013, FR-014, SC-006).

- [X] T029 [US4] Implement verified report reconstruction, full/partial scope, current/historical/unknown freshness, severity/owner/reproduction and compiled ten-row native prerequisites in scripts/security_regression/report.py; apply fail > incomplete > blocked > pass group precedence. Constraint C12: "Failure reasons are selected from the closed contract list; public results contain only run/case/group/profile identifiers, digests, UTC times, bounded counts, outcomes, freshness, severity, owner and compiled next actions, never raw test text or parameter values." Constraint C13: "Native prerequisite/action/recheck text is compiled, each 1–512 characters; software/version labels are 1–128 ASCII alphanumeric or .+!_- characters from an allowlisted package-name set, with at most 32 version entries and no filesystem paths." Constraint C14: "Records are immutable after writing; an active run is exclusively locked, an unlocked run lacking a valid terminal seal is incomplete, and report inspection never resumes execution, prunes prior runs or changes acceptance." (FR-010, FR-013, FR-014, SC-006).

- [X] T030 [P] [US4] Add test_policy_change_is_observed and repeatability contract tests in tests/test_security_regression_repeatability.py; consume baseline/restricted policy objects, prove ALT-1 decision changes and POC-1 stays allowed, detect source/test/policy/lock drift, and repeat bounded fixture selections with distinct IDs. (FR-010, FR-015, SC-003, SC-006).

- [X] T031 [US4] Extend tests/test_security_regression_report.py with list/run/report end-to-end CLI outcomes, active-lock and parent-death inspection, safe counters, native blockers and immutable prior failed runs. (FR-012, FR-013, FR-014, FR-015).

- [X] T032 [US4] Wire report --run and final run summary in scripts/run_security_regression.py, preserving the closed command/exit contract and deriving incomplete abandoned runs without executing them. (FR-010, FR-013, FR-014, FR-015).

- [X] T033 [US4] Extend scripts/publish_policy.py and tests/test_security_regression_privacy.py to reject regression manifests, results, frames and seals after renaming; include canary/malformed-record cases and no allowlist expansion. (FR-009, FR-016, SC-005).

- [X] T034 [US4] Add the full two-profile command to .github/workflows/ci.yml and verify scripts/security_regression/catalog.py resolves every required selector; retain existing full WebKit and publication/runtime/distribution gates. (FR-001, FR-002, FR-015, FR-016, SC-001).

## Phase 7: Polish and validation

All stories and native dispositions are required; no live operation is necessary to complete software work.

- [X] T035 Document contributor setup, listing/running/reproduction/reporting, partial/historical status and concrete blocked rechecks in CONTRIBUTING.md and docs/usage.md; keep README.md change brief and record no new runtime API/dependencies. (FR-014, FR-015, FR-016, SC-006).

- [X] T036 [P] Add10,000-result/report-under-five-seconds, metadata/artifact/quota limits and before/after-dispatch overflow tests in tests/test_security_regression_bounds.py; verify bounded safe summaries and nonpassing incomplete results. (FR-012, SC-004, SC-005).

- [X] T037 Review every new module/function and any exposed contract bug in scripts/security_regression/, tests/test_security_regression_*.py and applicable src/agent/{runtime,security,approval,broker,oauth}.py or response/governance adapters; record threat/compatibility findings in specs/009-security-regression/validation.md. Apply only minimal original-contract fixes with failing regressions; substantial redesign requires follow-up scope. (FR-003, FR-004, FR-005, FR-006, FR-007, FR-008, FR-009, FR-016, SC-002).

- [X] T038 Run all CI and quickstart commands including two full runs of both profiles; record exact counts, durations, content/profile digests, versions,100-run identity result and privacy/build checks in specs/009-security-regression/validation.md. (FR-015, FR-016, SC-001, SC-002, SC-003, SC-004, SC-005, SC-006).

- [X] T039 Record final F12-T1 through F12-T10 native prerequisites, owner/action/recheck and unchanged15-criterion acceptance status in specs/009-security-regression/validation.md and acceptance.json; no synthetic or local-review promotion and no live effects without separate authorization. (FR-014, FR-016, SC-006).

- [X] T040 Verify task-to-requirement and fourteen-build/ten-test coverage, documentation links, read-only checklist state and post-execution hooks; update only completed task markers in specs/009-security-regression/tasks.md and final software disposition in validation.md. (FR-001, FR-016, SC-001).

## Dependencies and independent delivery

Setup → Foundation → US1 → US2 → US3 → US4 → Polish. Tests precede implementations;
shared catalog, entry point, models and report edits are sequential. US1 validates fixture
catalogs until new US2/US3 selectors exist; the final real catalog must resolve every selector.
No missing test may be replaced by a passing stub. US2/US3 focused tests exercise trusted
runtime functions independently of the reporting tool. US4 uses seeded normalized records.

MVP is US1’s trustworthy coverage/execution accounting. It is an intermediate checkpoint;
complete 009 includes every story, required gap test, privacy check and native disposition.

Parallel examples after prerequisites: US1 catalog tests can be prepared alongside independent
fixture stream cases, then merge shared execution-test edits sequentially; US2 escalation,
policy and approval files are independent; identity mutations and 100-run lifecycle share a
file and run sequentially. US3 revocation/incident/containment/privacy files are independent.
US4 repeatability tests can be prepared alongside report tests; shared report and CLI edits
remain ordered. Bounds tests can run alongside documentation after all data contracts settle.

## Requirement coverage

| Requirement | Task IDs |
| --- | --- |
| FR-001 | T004, T011, T012, T016, T022, T027, T034, T040 |
| FR-002 | T011, T012, T013, T014, T015, T016, T022, T027, T034 |
| FR-003 | T017, T022, T037 |
| FR-004 | T002, T018, T019, T022, T037 |
| FR-005 | T020, T022, T037 |
| FR-006 | T023, T025, T027, T037 |
| FR-007 | T024, T025, T027, T037 |
| FR-008 | T021, T022, T025, T027, T037 |
| FR-009 | T014, T026, T027, T033, T037 |
| FR-010 | T003, T004, T005, T006, T008, T010, T028, T029, T030, T032 |
| FR-011 | T002, T007, T008, T010, T015, T026 |
| FR-012 | T003, T004, T005, T006, T009, T010, T013, T016, T031, T036 |
| FR-013 | T003, T004, T006, T009, T010, T012, T013, T014, T015, T016, T028, T029, T031, T032 |
| FR-014 | T004, T028, T029, T031, T032, T035, T039 |
| FR-015 | T001, T015, T016, T030, T031, T032, T034, T035, T038 |
| FR-016 | T001, T033, T034, T035, T037, T038, T039, T040 |
| SC-001 | T011, T012, T013, T022, T027, T034, T038, T040 |
| SC-002 | T017, T018, T019, T020, T022, T023, T024, T025, T027, T037, T038 |
| SC-003 | T002, T021, T030, T038 |
| SC-004 | T009, T036, T038 |
| SC-005 | T005, T007, T008, T009, T026, T033, T036, T038 |
| SC-006 | T028, T029, T030, T035, T038, T039 |

**Total**: 40 tasks. Setup: 2; Foundation: 8; US1 — Complete executable coverage: 6; US2 — Authority and escalation: 6; US3 — Failure containment and confidentiality: 5; US4 — Repeatable reporting and honest handoff: 7; Polish and validation: 6.
