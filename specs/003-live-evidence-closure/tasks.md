# Tasks: Live readiness and evidence closure

**Input**: specs/003-live-evidence-closure/spec.md, plan.md, research.md, data-model.md and contracts/runtime.md.
**Status**: Software implementation complete; T022–T024 live proof and T028 delivery remain open.
**Tests**: Explicitly required by FR-014/FR-016. Write meaningful boundary tests and observe failure before implementation.
**Format**: [P] means independent files after listed prerequisites, not permission to run live work concurrently.

## Phase 1: Setup

Confirm boundaries and traceability before code.

- [X] T001 Record the locked dependency/license baseline, threat analysis, 002 T036/T037 reuse and separate delivery blocker in specs/003-live-evidence-closure/validation.md; no new dependency unless separately justified. (FR-003, FR-013, FR-014, FR-015)
- [X] T002 Record the documented export examples and unsupported-mapping matrix from research.md in docs/adr/0005-live-evidence-closure.md; fixtures must use synthetic values and exact native field shapes. (FR-004, FR-005, FR-006, FR-015)

## Phase 2: Foundation

Complete shared contracts, context and private persistence before story work.

- [X] T003 [P] Write boundary/context tests in tests/test_validation_context.py and tests/test_validation_models.py covering C01: "New records use schema_version exactly 1, reject unknown fields, use generated UUIDs and 64-character lowercase SHA-256 digests, and require timezone-aware UTC timestamps." C04: "A deployment context is sealed before live effects, contains no credential values, excludes suite and timeout choices, and compares by a private digest; missing or unequal contexts block combined closeout without preventing legacy per-run reports." Test secret exclusion, credential rotation, target/profile/CA changes, legacy runs and context tampering. (FR-007, FR-011, FR-014)
- [X] T004 Add shared models in src/agent/validation/models.py and context capture in src/agent/validation/context.py using C01/C04; enumerate every context selector from data-model.md, exclude all credential values, and persist context.json before effects via runner.py and seal_execution in report.py. Include new modules in implementation_revision(). (FR-003, FR-007, FR-009, FR-011)
- [X] T005 [P] Write snapshot storage/lock/atomicity tests in tests/test_validation_store.py for C10: "Run locks are acquired in sorted UUID order without blocking; inputs are rechecked immediately before atomic closeout finalization. Private directories are 0700 and files 0600; symlinks, path escapes and overwrites are rejected. Each snapshot allows at most 100 files, 10 MiB per file and 100 MiB total; inherited per-run limits remain unchanged." Include concurrent member writers, symlink/path escapes, changed inventory before finalize and interruption with no finalized artifact. (FR-009, FR-011, FR-012, FR-014)
- [X] T006 Extend src/agent/validation/store.py for bounded separate closeout directories, sorted nonblocking multi-run locks and atomic finalization under C10; expose input inventories including every consumed context/source/review file without copying raw evidence. (FR-009, FR-011, FR-012)

## Phase 3: US1 — Local readiness (P1, MVP)

Independent check: all four selected cases return bounded safe readiness with every external/effect call denied.

- [X] T007 [P] [US1] Write tests/test_validation_readiness.py for complete/missing/invalid settings, extras, profiles, aliases and all registered checks in contracts/runtime.md; exercise C02: "Readiness selects 1–2 distinct registered live scenarios from one suite; live-phone requires exactly one named scenario. Check states are configured, missing, invalid, unverified or not_applicable; sections are execution or evidence; owners are operator, integration_owner or reviewer. No check result contains configuration values or arbitrary exception text." C03: "Readiness performs zero network/model/credential/phone/export calls, creates no validation artifacts, reads at most 10 MiB per local configuration file, and has a two-second total deadline." Include no token decoding-as-verification, safe exception mapping and the two-second CI budget. (FR-001, FR-002, FR-011, FR-012, FR-014, SC-001)
- [X] T008 [US1] Implement src/agent/validation/readiness.py and readiness models in models.py under C02/C03: collect all local checks, separate execution/evidence readiness, keep external checks unverified, validate bounded profile/CA inputs and never call probe(). (FR-001, FR-002, FR-005, FR-011, FR-012)
- [X] T009 [US1] Add validate ready parsing/output in src/agent/validation/commands.py and tests/test_validation_cli.py; suite required, reject invalid/duplicate/phone selection before Settings, no --root/--interactive or persistence, safe JSON and C11 exit mapping. (FR-001, FR-002, FR-011, FR-012)
- [X] T010 [US1] Reuse the readiness execution subset from src/agent/validation/scenarios.py immediately before genuine live ingress; extend tests/test_validation_runner.py for ready-then-changed/expired settings, missing evidence-only access, and no synthetic/admin fallback. Preserve existing zero-network offline path. (FR-002, FR-003, FR-014, SC-001)

## Phase 4: US2 — Native evidence correctness (P1)

Independent check: equivalent documented exports normalize consistently; incorrect identity/action/decision joins cannot qualify.

- [X] T011 [P] [US2] Add native-envelope/alias tests in tests/test_validation_importers.py and exact receipt tests in tests/test_validation_correlation.py covering C05: "Import format version 1 remains readable; version 2 permits documented native envelopes and an optional private native project ID of 1–128 characters. Contradictory simultaneously supplied aliases fail with evidence_contradicted; unsupported shapes fail with source_unsupported." Include nested Vault secret lease, conflicting aliases, schema/data row objects, rows/columns metadata, missing/internal project_id, parent-span completeness, v1 compatibility and HMAC/Verify unsupported cases. (FR-004, FR-005, FR-006, FR-014, SC-002)
- [X] T012 [US2] Implement format-version dispatch, strict native envelopes and private optional native project-ID binding in src/agent/validation/importers.py and models.py under C05. Preserve v1 canonical normalization/digests while preventing ambiguous old project-ID interpretations from qualifying new receipt/review; add safe blockers in correlation.py/report.py. No new read-token setting. (FR-004, FR-005, FR-006, SC-002)
- [X] T013 [P] [US2] Write transaction ownership/intentional-denial regression tests in tests/test_validation_scenarios.py and tests/test_validation_review.py for C06: "Each binding and transaction must match its containing validation ID, selected observation ID, run ID, expected source and approval/action binding. One native transaction cannot satisfy multiple observations; only DENIED, VERIFY_DENIED or USER_DENIED proves intentional phone denial." Cover wrong containing run/observation/action/source, repeated transaction across runs, forged manifest and timeout/expiry/cancel versus intentional denial. (FR-003, FR-009, FR-014, FR-016, SC-002, SC-005)
- [X] T014 [US2] Persist trusted pre-request approval_ref/action_digest and subsequent native transaction ID in src/agent/observability.py, verify.py and validation/models.py; enforce C06 joins in importers.py/report.py and precise phone result classification in scenarios.py. Never skip cleanup or execute a write after binding failure; retain old raw evidence bytes. (FR-003, FR-006, FR-009, FR-016)
- [X] T015 [US2] Tighten src/agent/validation/review.py eligibility and tests/test_validation_review.py under C12: "Only existing UC1-01, UC1-05 and UC2-02 eligibility may be retained; exact referenced evidence must cover their relevant successful operation phases, and unrelated source-kind matches never qualify. Unsupported criteria and changed revisions remain blocked." Follow the exact criterion rules in data-model.md; test unrelated phases/artifact references, selected actor failures, missing old bindings and stale implementation/mapping revisions without enabling new criteria. (FR-006, FR-010, FR-016)
- [X] T016 [US2] Run the fixture import → report → review workflow in tests/test_validation_cli.py and canary/cancellation checks in tests/test_observability.py; verify version 1 remains readable, version 2 produces equivalent supported evidence, unsupported fields cannot leak, and all required telemetry spans are matched. (FR-004, FR-005, FR-006, FR-014, FR-016, SC-002, SC-006)

## Phase 5: US3 — Immutable closeout (P2)

Independent check: select fixture runs covering four cases and reproduce one content revision without providers, effects or new reviews.

- [X] T017 [P] [US3] Write tests/test_validation_closeout.py for C07: "Closeout accepts 1–4 distinct explicit live run UUIDs and contains exactly four case slots: delegated-database-read, actor-only-denial, phone-approved and phone-denied. More than one observation for a slot blocks selection; no latest-run selection or effect replay is allowed." C08: "Operational and evidence closure each use pass, fail, blocked or interrupted with precedence interrupted > fail > blocked > pass. Exactly 15 criterion rows contain per-run dispositions; closeout creates neither an aggregate customer disposition nor a new review decision." Cover missing/duplicate slots, offline/foreign runs, mixed contexts/current revisions, all per-run reviews including conflicts, and complete operational results with blocked customer proof. (FR-007, FR-008, FR-010, FR-014, SC-003)
- [X] T018 [US3] Implement closeout models in src/agent/validation/models.py and assembly in closeout.py under C07/C08 plus C09: "Snapshot content revisions bind sorted run IDs, exact input inventories and report/review revisions, context and implementation/mapping revisions, all four cases and all 15 rows. Snapshot UUID and generation time are excluded from the content digest." Evaluate every exact case obligation in contracts/runtime.md; reuse report/review reconstruction, expose applicable review UUIDs, retain all 15 rows, and produce no aggregate acceptance disposition. (FR-005, FR-006, FR-008, FR-009, FR-010, SC-003)
- [X] T019 [US3] Implement immutable creation/inspection in src/agent/validation/closeout.py using C09/C10; extend tests/test_validation_closeout.py for changed/missing/tampered files, changed reviews, duplicate cross-run transactions, nonblocking lock contention and concurrent mutation. Old snapshots remain untouched and new input revisions require explicit new snapshots. (FR-007, FR-009, FR-011, FR-012, SC-003)
- [X] T020 [US3] Add validate closeout --run/--closeout with mutually exclusive selection in src/agent/validation/commands.py and tests/test_validation_cli.py; generate parity-tested safe JSON/Markdown, preserve private-root rules and implement C11: "Closeout has a 30-second wall deadline and a ten-second assembly budget excluding file I/O for four maximum-supported runs; exit precedence is 130 interrupted, 1 failed, 2 blocked or invalid, then 0 successful selected work. No command retries effects or deletes evidence." Unsupported wider customer claims do not redefine operational/evidence exit status. (FR-008, FR-010, FR-011, FR-012)
- [X] T021 [US3] Add four maximum-supported run performance fixtures and zero-network/effect canaries to tests/test_validation_closeout.py; prove the ten-second assembly budget, stable content revision despite generation UUID/time, interrupted snapshot safety, all 15 criterion rows and repeated inspection with no evidence deletion. (FR-009, FR-010, FR-011, FR-012, FR-014, SC-003, SC-004, SC-006)

## Phase 6: US4 — Authorized live walkthrough (P2; external gates)

Independent check: each real case is observed or explicitly blocked, with unchanged source proof and a present phone witness.

- [ ] T022 [US4] Execute the database readiness/run/import/report steps in specs/003-live-evidence-closure/quickstart.md using the configured authorized PoC; record genuine read, exact cleanup, actor-only denial and Logfire receipt or blockers in validation.md, linking specs/002-security-validation/tasks.md T036. Leave both live tasks open until original proof requirements are met. (FR-003, FR-005, FR-006, FR-013, SC-005)
- [ ] T023 [US4] Execute individually selected witnessed approve and deny invocations from specs/003-live-evidence-closure/quickstart.md; record distinct action-bound native decisions, exact receipt and Verify Events blocker in validation.md, linking specs/002-security-validation/tasks.md T037. No witness or token means task stays open; timeout is not denial. (FR-003, FR-006, FR-013, FR-016, SC-005)
- [ ] T024 [US4] Perform explicit source review and closeout inspection using the real run IDs from T022/T023; record safe outcomes and outstanding criterion owners in specs/003-live-evidence-closure/validation.md and reconcile original 002 task evidence without automatic acceptance.json changes. Keep this task open if required live/source/review evidence is absent. (FR-009, FR-010, FR-013, SC-005)

## Phase 7: Polish and delivery

Software checks can finish while external tasks remain open; delivery cannot bypass constitution gates.

- [X] T025 [P] Update docs/usage.md, docs/configuration.md, README.md links and docs/adr/0005-live-evidence-closure.md for commands, exact exit meanings, manual native exports, context/review migration and operational/evidence/customer distinctions; keep README concise and project naming private. (FR-001, FR-005, FR-006, FR-010, FR-013, FR-015)
- [X] T026 Extend scripts/publish_policy.py and tests/test_publication.py to reject context/closeout artifacts even if force-added; add deterministic readiness/closeout coverage to .github/workflows/ci.yml and verify installed base-wheel behavior outside checkout without live SDKs. Preserve locked extras and all existing privacy/distribution exclusions. (FR-011, FR-014, FR-015, SC-006)
- [X] T027 Run all CONTRIBUTING.md software gates and the deterministic quickstart portions; record exact results, threat review and uncompleted live gates in specs/003-live-evidence-closure/validation.md. Validate every feature independently of the local pointer; report software/live completion separately. (FR-012, FR-013, FR-014, FR-015, SC-001, SC-002, SC-003, SC-004, SC-006)
- [ ] T028 Review prospective Git/distribution contents and PR against .github/pull_request_template.md; verify required validate check, owner review, dismissed stale approvals and default-branch force-push/deletion protection, recording proof or delivery blocker in specs/003-live-evidence-closure/validation.md. Do not merge until controls and later explicit delivery authorization exist; do not mutate protection as a side effect. (FR-015, SC-006)

## Dependencies and execution order

T001 → T002 → foundation T003–T006 → US1 T007–T010 → US2 T011–T016 → US3 T017–T021.
T004 follows T003; T006 follows T005 and T004. Tests precede their implementation within each story.
T012 follows T011; T014 follows T013 and T012; T015 follows T014; T016 integrates T012–T015.
T018 follows T017; T019 follows T018; T020 follows T019; T021 verifies the integrated story.

T025/T026 can start after T021 and do not depend on live access. T027 depends on T025/T026.
US4 T022–T024 depends on software through T027 plus actual live prerequisites. T023 needs an
explicit case selection and present human witness for each invocation; it is never unattended.
T024 depends on actual T022/T023 evidence. T028 needs available software/live results, owner
review and server-side controls; unavailable live gates must be disclosed, never checked off.
Delivery requires separate explicit authorization after implementation and never follows this plan automatically.

## Parallel opportunities

- Foundation: T003 model/context tests and T005 storage tests touch different files after setup.
- US1: T007 readiness tests can be developed alongside synthetic CLI test preparation in T009;
  parser implementation waits for T008. Do not edit commands.py concurrently with another story.
- US2: T011 native parser tests and T013 transaction tests are independent after US1.
- US3: T017 pure assembly fixtures can be prepared alongside CLI fixtures for T020; implementation
  and shared models/report edits remain sequential. No simultaneous writers to the same test file.
- US4: manual source export preparation can proceed while awaiting a witness; live invocations
  and their ledger updates are sequential, never parallel phone prompts.
- Polish: T025 documentation and T026 publication/CI changes use different files after US3.

## Implementation strategy

MVP: foundation plus US1 gives useful local readiness without live credentials. Then add native
format correctness and ownership checks, then closeout. Validate each independent story before
moving forward. External tasks remain open when prerequisites are absent. None of these tasks
are marked complete during planning; the next model starts with $speckit-implement.

## Requirement coverage

| Requirement | Tasks |
| --- | --- |
| FR-001 | T007, T008, T009, T025 |
| FR-002 | T007, T008, T009, T010 |
| FR-003 | T001, T004, T010, T013, T014, T022, T023 |
| FR-004 | T002, T011, T012, T016 |
| FR-005 | T002, T008, T011, T012, T016, T018, T022, T025 |
| FR-006 | T002, T011, T012, T014, T015, T016, T018, T022, T023, T025 |
| FR-007 | T003, T004, T017, T019 |
| FR-008 | T017, T018, T020 |
| FR-009 | T004, T005, T006, T013, T014, T018, T019, T021, T024 |
| FR-010 | T015, T017, T018, T020, T021, T024, T025 |
| FR-011 | T003, T004, T005, T006, T007, T008, T009, T019, T020, T021, T026 |
| FR-012 | T005, T006, T007, T008, T009, T019, T020, T021, T027 |
| FR-013 | T001, T022, T023, T024, T025, T027 |
| FR-014 | T001, T003, T005, T007, T010, T011, T013, T016, T017, T021, T026, T027 |
| FR-015 | T001, T002, T025, T026, T027, T028 |
| FR-016 | T013, T014, T015, T016, T023 |
| SC-001 | T007, T010, T027 |
| SC-002 | T011, T012, T013, T016, T027 |
| SC-003 | T017, T018, T019, T021, T027 |
| SC-004 | T021, T027 |
| SC-005 | T013, T022, T023, T024 |
| SC-006 | T016, T021, T026, T027, T028 |

Task counts: 28 total; setup 2, foundation 4, US1 4, US2 6, US3 5, US4 3, polish/delivery 4.
