# Tasks: End-to-End PoC Closeout

**Input**: [spec](spec.md), [plan](plan.md), [research](research.md), [data model](data-model.md),
[contract](contracts/runtime.md), [quickstart](quickstart.md).
**Prerequisites**: Requirements/security reviews complete; no critical analysis finding remains.
**Tests**: Explicitly required by FR-021. Write meaningful failing cases before each new behavior.
**Status**: Implementation and validation complete; 38/38 software tasks executed. No native execution or signoff claimed.

Tasks follow `- [ ] Tnnn [P?] [USn?] action and exact file paths`. `[P]` marks disjoint test work at
its phase boundary, not permission to skip prerequisites. Every maintained module/function must explain
purpose, input/output and non-obvious privacy/failure behavior. Never mark tasks complete from a plan.

## Phase 1: Setup

- [X] T001 Create documented `src/agent/closeout/__init__.py` and the planned module structure; start `specs/010-poc-closeout/validation.md` with implementation/native evidence sections, record compatibility boundaries and the 13/6/5 design mapping. (FR-001, FR-020, FR-022)
- [X] T002 Add reusable synthetic inventory, source, cohort and reviewer fixture builders in `tests/closeout_support.py`; isolate every store under a temporary project, deny network/subprocesses and poison dotenv/provider environment without inspecting real `.local/`. (FR-018, FR-021, SC-002)

## Phase 2: Foundational contracts and storage

- [X] T003 [P] Add strict type/unknown-field/duplicate-key/enum/catalog/projection tests in `tests/test_closeout_models.py` and `tests/test_closeout_catalog.py`, including shared C01–C03/C09/C17 rules and exact sets; story-specific limits are exercised in their owning test tasks. (FR-001, FR-018, FR-019, SC-001)
- [X] T004 Implement common frozen models in `src/agent/closeout/models.py` and exact identifiers in `src/agent/closeout/catalog.py`: C01 “IDs are canonical UUIDs; revisions are strict positive integers; SHA-256 digests are 64 lowercase hex characters; timestamps are timezone-aware UTC.” C02 “Public labels are compiled enums or generated aliases; private identifiers are 1–256 characters; reviewer names are 1–128 characters; private rationale is 1–2,000 characters.” C03 “Catalog sets are exact: 4 use cases, 15 criterion IDs from CRITERIA, 13 build items, 6 Function 13 tests, 5 exit gates, 4 experiment scenarios and 5 review roles.” C09 “Evidence provenance is synthetic|operator|native; outcome is pass|fail|blocked; applicability is current|historical|missing|invalid; unknown provenance or status is rejected.” Implement the C17 allowlisted public projection and safe errors at this shared boundary. (FR-001, FR-018, SC-001)
- [X] T005 [P] Add owner/mode/link/inode-race, concurrent revision, quota, interrupted seal, immutable history and read-only inspection tests in `tests/test_closeout_store.py`; independently verify member source bytes/metadata never change. (FR-009, FR-019, SC-006)
- [X] T006 Implement bounded private storage in `src/agent/closeout/store.py`: C04 “Each source file is at most 10 MiB; each JSONL record at most 64 KiB; JSON depth at most 8; each dossier has at most 100 source artifacts and 10,000 normalized activity records.” C05 “Each dossier retains at most 100 revisions, 100 assessments, 100 reviews and 20 packages; total stored bytes including partial writes are at most 100 MiB; no automatic pruning or overwrite occurs.” C07 “Private directories are owned mode 0700; regular files are owned mode 0600 with one hard link; symlinks, traversal, inode replacement and special files are rejected before reading or writing.” C08 “Mutation requires the expected current revision under one per-dossier exclusive lock; seal publication is atomic and last; inspection never writes or creates source locks.” (FR-005, FR-009, FR-019)

**Checkpoint**: Strict shared contracts and private storage work with no runtime/provider initialization.
T003/T005 may be authored concurrently after T002; T004/T006 serialize shared model integration.

## Phase 3: US1 — Prepare and follow a complete demonstration (P1, MVP)

**Independent test**: An empty synthetic dossier lists four guides, all design items and fifteen
blocked criteria with exact owners/actions; commands dispatch zero network calls or processes.

- [X] T007 [US1] Add prepare/amend/guide/inspect CLI tests in `tests/test_closeout_cli.py`, including unknown selectors, missing inventory, revision conflict, hostile command text, no dotenv read and zero calls. (FR-002, FR-003, FR-004, FR-020, SC-002)
- [X] T008 [US1] Implement `Dossier`/`InventoryRevision` and inventory creation/amendment in `src/agent/closeout/models.py` and `src/agent/closeout/store.py`; enforce schema_version=1, “1–16 named source profiles”, “1–100 definition/identity mapping references”, “1–100 policy/dataset/configuration digests”, unique references and explicit unavailable/unknown capabilities; clock uncertainty is absent or 0–5 finite seconds; source event time cannot exceed actual capture plus reviewed uncertainty; delay is a strict integer 0–86,400 seconds with source-owner confirmation. Distinguish mutation revision from environment revision so adding a review does not stale its own subject; amendments preserve and invalidate dependent revisions. (FR-002, FR-009)
- [X] T009 [US1] Implement the 13-build/6-test/5-gate catalog and four use-case/four-experiment guides in `src/agent/closeout/catalog.py`; map exact commands to current parsers, label live reads/issuance/mutations, include cleanup/recovery steps, zero invented dashboard paths and concrete missing audit/phone/cohort/runner actions. (FR-001, FR-003, FR-004, FR-022, SC-001, SC-002)
- [X] T010 [US1] Register/dispatch `agent closeout` before Settings initialization in `src/agent/cli.py` and implement prepare/amend/guide/inspect in `src/agent/closeout/commands.py`; C18 “No closeout operation initializes provider settings, reads credentials, calls network, launches subprocesses or executes guide text; existing source stores remain read-only.” Preserve all existing aliases/contracts and demonstrate the standalone MVP. (FR-003, FR-004, FR-020, SC-002)

## Phase 4: US2 — Assess all acceptance criteria (P1)

**Independent test**: All fifteen rows exist from isolated member fixtures; unrelated, insufficient,
stale, synthetic, forged and contradictory source claims cannot pass; inspection preserves history.

- [X] T011 [P] [US2] Add source capture/import tests in `tests/test_closeout_sources.py`: each member family, missing/legacy/unsealed state, unknown profiles, raw-byte/pointer mismatch, duplicate IDs, cross-instance joins, selected-history omission and source mutation during read; verify no member writes. (FR-005, FR-007, FR-010, FR-018)
- [X] T012 [P] [US2] Add independent table-driven proof tests for all fifteen rows in `tests/test_closeout_assessment.py`; cover every contract obligation, native versus local denial, approval/denial/timeout, source causality, cleanup, later contradictions, real capture time/300-second F10 expiry and UC3 interval math. (FR-006, FR-007, FR-008, FR-009, FR-010, FR-014, SC-003)
- [X] T013 [US2] Add strict evidence/profile/fact/assessment models in `src/agent/closeout/models.py`: C10 “Each evidence member binds one environment digest, source kind/instance, format version, artifact digest, observation and capture times, exact object identity and complete selected reference closure.” Enforce “At most 16 fact selectors per profile, each a JSON Pointer of at most 256 characters with no wildcard”; all eleven discriminated fact kinds and their required values from the data-model table (counts 0–10,000, durations 0–86,400,000 finite milliseconds, strict booleans, required null handling), exact correlation types and source/schema/extraction review digests. (FR-005, FR-006, FR-007)
- [X] T014 [US2] Implement bounded snapshot adapters in `src/agent/closeout/sources.py` for validation runs/closeouts, response incidents, governance candidates and regression software records; verify fixed root/typed ID, complete related scope history and before/after inventories. Use pure helpers from `src/agent/validation/closeout.py`, `src/agent/validation/report.py` and `src/agent/governance/report.py` without source mutations or importing contributor scripts; regression records stay software-only. (FR-005, FR-009, FR-010, FR-020)
- [X] T015 [US2] Implement supported audit/Verify/Logfire/native-facts imports and source-profile/extraction reviews in `src/agent/closeout/sources.py` and `src/agent/closeout/review.py`; independently derive typed facts from original bounded bytes, validate exact digest/record/field references, reject known secrets and retain unsupported relations as blocked. Never promote manually asserted facts to native provenance. (FR-005, FR-007, FR-018)
- [X] T016 [US2] Implement all fifteen criterion predicates plus F13 test/gate projections in `src/agent/closeout/assessment.py`; preserve original meaning, latest contradiction/cleanup precedence and mechanism distinctions. C19 “Native eligibility is evaluated at actual capture time under the member's original freshness rules; neither import timestamps nor user-supplied evaluation times may renew expired proof.” C20 “Timing uses correlated source intervals with finite nonnegative clock uncertainty; a UC3-04 pass requires an upper latency bound below 1,800 seconds; unknown or inconsistent bounds block proof.” (FR-006, FR-007, FR-008, FR-010, FR-014, SC-003)
- [X] T017 [US2] Implement immutable historical assessment and current/missing/invalid applicability in `src/agent/closeout/assessment.py`; bind implementation/catalog/context/source inventories, preserve captured time/outcome, surface newly captured contradictions and prohibit cherry-picked old passes or report writes. (FR-009, FR-010, SC-006)
- [X] T018 [US2] Wire capture/import/assess/report in `src/agent/closeout/commands.py` and extend `tests/test_closeout_cli.py` with partial and complete synthetic source flows; distinguish successful import from proof/acceptance, check safe exits/actions and unchanged legacy commands. (FR-005, FR-006, FR-020, FR-022)

## Phase 5: US3 — Reconcile controlled client-count experiments (P2)

**Independent test**: Each fixed scenario computes expected native cohort sets and deltas from
synthetic source-shaped records; reused users, other consumers, lag and false cohorts cannot be hidden.

- [X] T019 [US3] Add tests in `tests/test_closeout_counting.py` for all four exact cohorts, repeated tokens from one user, actor/subject overlap, remapping, duplicate/conflicting exports, first-use field variants, incomplete/late export, namespace/mount/cluster/month mismatch, inventory versus activity and reused OBO/direct users. (FR-011, FR-012, FR-013, SC-004)
- [X] T020 [US3] Add experiment/roster/activity/measurement models in `src/agent/closeout/models.py`: C11 “Each experiment requires exactly 100 successful distinct execution references; agent scenarios require 100 distinct token-issuance references and trace references; user scenarios require exactly 100 distinct verified subject references.” C12 “Each experiment fixes one cluster, one namespace subtree, 1–16 auth mounts, one effective reporting period and one durable agent where applicable; cross-cluster totals are never deduplicated or combined into a single proof.” Also require direct token/trace uniqueness and “At most 100 delta explanations, each with 1–32 artifact references”. (FR-011, FR-012, FR-013)
- [X] T021 [US3] Implement explicit vault-activity-v1/execution-roster-v1/entity-mapping-v1 parsing in `src/agent/closeout/sources.py`; preserve private names/metadata, normalize only required fields, version the first-use spelling and reject conflicting/unknown shapes without dropping rows or confusing activity with audit. (FR-005, FR-011, FR-013, FR-018)
- [X] T022 [US3] Implement pre-operation experiment preparation and exact set reconciliation in `src/agent/closeout/counting.py`; C13 “A baseline precedes all scenario operations; final acquisition follows all operations and the declared reporting delay; expected entities come from independently resolved native mappings, never token-count arithmetic.” Require preparation before operations, compatible effective periods, scoped dedup, mapping provenance, source reviews, distinct scenario/incremental counts and evidence for every delta; no tolerances/invoice claims. (FR-011, FR-012, FR-013, SC-004)
- [X] T023 [US3] Wire experiment/measure in `src/agent/closeout/commands.py` and four exact collection guides in `src/agent/closeout/catalog.py`, including unsupported agent-only/direct execution surface, cohort/export privileges and reporting-delay actions; no provider execution or user creation. (FR-003, FR-004, FR-011, FR-012, FR-022, SC-002)
- [X] T024 [US3] Add four-scenario CLI flow and integration with F13-T5/T6/P4-G5 in `tests/test_closeout_cli.py` and `src/agent/closeout/assessment.py`; ensure synthetic results stay software evidence and external incomplete experiments remain explicit. (FR-001, FR-012, FR-013, SC-004)

## Phase 6: US4 — Review and hand over closeout (P2)

**Independent test**: A synthetic core can be packaged and re-inspected, each role can explicitly
review its exact digest, and final decisions require complete proof or properly qualified exceptions.

- [X] T025 [P] [US4] Add review tests in `tests/test_closeout_review.py`: exact digest/role/attestation, missing real witness, stale source/package, same person multiple roles, unsuperseded conflicts, explicit supersession, relevant-vendor/customer exception agreement and inability to waive integrity/cleanup. (FR-016, FR-017, SC-003, SC-006)
- [X] T026 [P] [US4] Add core/final package tests in `tests/test_closeout_package.py`: complete evidence/guides/readout, reviewed text/PNG/JPEG, unsupported/secret-bearing/unreviewed attachments, wrong signature, extra files, mutation/race/interruption, immutable core and no circular digest. (FR-015, FR-018, FR-019, SC-006)
- [X] T027 [US4] Implement review/exception/core/handoff models in `src/agent/closeout/models.py`: C14 “Each criterion or package review binds exactly one assessment or core digest, reviewer role/name, observed/reviewed times, decision, rationale and 1–32 private attestation references.” Source/attachment attestations use their own discriminated subject/digest schemas. C16 “Each package has at most 100 files and 50 MiB; attachments are text/plain, image/png or image/jpeg, at most 5 MiB each, with explicit sanitization review bound to exact bytes.” (FR-015, FR-016, FR-018)
- [X] T028 [US4] Implement criterion and package-role reviews, explicit supersession, exceptions and acceptance eligibility in `src/agent/closeout/review.py`; C15 “Full acceptance requires all 15 original criteria passed and all 5 role approvals for the same current core; exceptions require customer plus relevant vendor agreement and never change an original criterion to pass.” Require F13/P4 fulfillment, actual witness attestation and preserve historical decision versus current applicability; never authenticate a reviewer from a label. (FR-016, FR-017, SC-003, SC-006)
- [X] T029 [US4] Implement core assembly/sealing in `src/agent/closeout/package.py`, with original criteria matrix, frozen inventory summary, software/native distinctions, evidence index, timing/counts, gaps/readout, reproduction and fixture/reset guides; include only explicitly reviewed supporting attachments and exclude raw originals/prose/credentials. (FR-015, FR-018)
- [X] T030 [US4] Implement final handoff from unchanged core plus applicable external role records in `src/agent/closeout/package.py`, and derived final-status precedence in `src/agent/closeout/review.py`; detect extra/missing/changed files, avoid circular hashing, preserve all original failures and report accepted exceptions distinctly. (FR-015, FR-016, FR-017, SC-006)
- [X] T031 [US4] Wire review/package/handoff and package report into `src/agent/closeout/commands.py`; add full synthetic witness lifecycle and blocked-package CLI integration in `tests/test_closeout_cli.py`, including no public acceptance edit/upload/provider calls. (FR-015, FR-016, FR-017, FR-020, FR-022)

## Phase 7: Polish and delivery

- [X] T032 Add end-to-end confidentiality canaries in `tests/test_closeout_privacy.py` covering native identifiers, malicious source strings, reviewer prose, tokens, attachment rejection, console/errors/logging/Markdown and both packages; C17 “Public projections contain only schema versions, local UUIDs, compiled labels/reasons/actions, counts, UTC times, durations and content digests; native identifiers, paths, source prose and reviewer names are private.” (FR-018, FR-021)
- [X] T033 Extend `scripts/publish_policy.py` to reject new generated private names and renamed/damaged recognizable dossier/measurement/review/package shapes; add canary publication/distribution regressions in `tests/test_closeout_privacy.py` without public allowlist expansion. (FR-018, FR-020)
- [X] T034 Update `README.md`, `docs/usage.md` and `CONTRIBUTING.md` with concise entry point/full workflow, all private schema examples, exact existing/live command labels, native blockers, actual human signoff steps, fingerprint/legacy migration implications and no new environment variables; validate all doc command forms. (FR-003, FR-004, FR-015, FR-020, FR-022)
- [X] T035 Add bounded operation/repeatability tests in `tests/test_closeout_bounds.py` and run them: C06 “Each local operation has a 30-second deadline including cleanup; pure assessment of 15 criteria and 10,000 normalized activity records takes at most 5 seconds excluding I/O.” Exercise byte/count/depth/revision/package quotas, interrupt/crash/restart, readonly source metadata and deterministic unchanged reports with independent expected outputs. (FR-019, FR-021, SC-005, SC-006)
- [X] T036 Run all `.github/workflows/ci.yml` gates, retaining full WebKit and two-profile 009 regression; change CI only if a 010 bounded-repeatability check is not covered by full pytest; verify wheel/sdist include maintained closeout code and exclude every private artifact. Record exact results in `specs/010-poc-closeout/validation.md`. (FR-020, FR-021, SC-003, SC-005)
- [X] T037 Execute the synthetic lifecycle from `specs/010-poc-closeout/quickstart.md`, verify all four stories, all F13/P4 mappings and fifteen original meanings, and record exact native missing-prerequisite/owner/action/recheck entries in `specs/010-poc-closeout/validation.md`; no live actions are required by this task or silently performed. (FR-001, FR-004, FR-022, SC-001, SC-002, SC-004, SC-006)
- [X] T038 Review the prospective staged diff, rerun privacy/history and applicable artifact/link gates, verify docstrings and the complete requirement/task map, record actual software results in `specs/010-poc-closeout/validation.md`, and retain honest native status in `specs/010-poc-closeout/acceptance.json`. Mark only executed software tasks complete. (FR-018, FR-020, FR-021, FR-022)

## Dependencies and execution order

```text
Setup T001–T002 → Foundation T003–T006 → US1 T007–T010
US1 → US2 T011–T018 → US3 T019–T024
US2 + US3 → US4 T025–T031 → Delivery T032–T038
```

Each story's independent tests use synthetic prepared records; they need no live service or completed
external signoff. US3 needs US2's typed imports but can test its pure set arithmetic independently.
US4 needs US2 assessments and US3 measured outcomes for complete acceptance; blocked packaging can be
validated with missing measures. Shared `models.py`, `commands.py`, `sources.py`, `assessment.py` edits
serialize, even when disjoint tests are authored concurrently. T003/T005 precede behavior they verify.
T004 common models precede store integration T006. All CLI integrations follow their underlying services.

Parallel examples: US1's CLI test design T007 can proceed alongside review of existing guide command
forms for T009 after foundation (implementation integrates after T008). US2 T011 and T012 are disjoint;
US3 independent counting fixture design T019 can overlap documentation research for T023, with code
serialized after T020–T022; US4 T025 and T026 are disjoint. These are opportunities, not additional agents
required by implementation. Finish each story's integration tests before dependent stories.

## Requirement coverage

| Requirement | Task IDs |
| --- | --- |
| FR-001 | T001, T003, T004, T009, T024, T037 |
| FR-002 | T007, T008 |
| FR-003 | T007, T009, T010, T023, T034 |
| FR-004 | T007, T009, T010, T023, T034, T037 |
| FR-005 | T006, T011, T013, T014, T015, T018, T021 |
| FR-006 | T012, T013, T016, T018 |
| FR-007 | T011, T012, T013, T015, T016 |
| FR-008 | T012, T016 |
| FR-009 | T005, T006, T008, T012, T014, T017 |
| FR-010 | T011, T012, T014, T016, T017 |
| FR-011 | T019, T020, T021, T022, T023 |
| FR-012 | T019, T020, T022, T023, T024 |
| FR-013 | T019, T020, T021, T022, T024 |
| FR-014 | T012, T016 |
| FR-015 | T026, T027, T029, T030, T031, T034 |
| FR-016 | T025, T027, T028, T030, T031 |
| FR-017 | T025, T028, T030, T031 |
| FR-018 | T002, T003, T004, T011, T015, T021, T026, T027, T029, T032, T033, T038 |
| FR-019 | T003, T005, T006, T026, T035 |
| FR-020 | T001, T007, T010, T014, T018, T031, T033, T034, T036, T038 |
| FR-021 | T002, T032, T035, T036, T038 |
| FR-022 | T001, T009, T018, T023, T031, T034, T037, T038 |
| SC-001 | T003, T004, T009, T037 |
| SC-002 | T002, T007, T009, T010, T023, T037 |
| SC-003 | T012, T016, T025, T028, T036 |
| SC-004 | T019, T022, T024, T037 |
| SC-005 | T035, T036 |
| SC-006 | T005, T017, T025, T026, T028, T030, T035, T037 |

## Implementation strategy

Deliver the usable blocked-inventory/guide workflow first (US1), then typed proof assessment (US2),
measured counting (US3) and witnessed package review (US4). Validate each in isolation, then execute
the complete synthetic lifecycle and required gates. Counts: setup 2, foundation 4, US1 4, US2 8,
US3 6, US4 7, delivery 7 = 38. All are software work; live experiments/real meetings are explicitly
represented in the product as performed, failed or blocked based on evidence, not marked executed here.
