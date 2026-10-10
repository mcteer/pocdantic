# Tasks: Observable, repeatable security validation

**Owner**: mcteer
**Input**: spec.md, plan.md, research.md, data-model.md, contracts/runtime.md and quickstart.md.
**Status**: Planning only. All implementation tasks remain unchecked for the next model/session.
**Tests**: Explicitly required by FR-017 and constitution; write meaningful failing tests before behavior.
**Format**: Sequential IDs; [USn] maps to spec stories; [P] permits work on distinct files only after prerequisites.

## Phase 1: Setup

- [ ] T001 Record the dependency/license baseline, threat-boundary review and implementation validation ledger in specs/002-security-validation/validation.md; verify existing locked extras suffice and retain the no-new-dependency decision unless a reviewed change is necessary. (FR-015, FR-017)
- [ ] T002 Add the fixed suite catalog in config/validation-suites.json, explicit packaged resource mapping in pyproject.toml and package initialization in src/pocdantic/validation/__init__.py; catalog contains the nine offline, two live database and two individually selected phone scenarios from plan.md, with no executable expressions or customer values. (FR-001, FR-015, FR-017)

## Phase 2: Foundation

**Gate**: Complete these contracts before story implementation; do not change authorization semantics.

- [ ] T003 [P] Write strict model/catalog boundary tests in tests/test_validation_models.py for constraints C01–C05/C08/C12, duplicate selection, unsupported versions, invalid modes, generated-ID separation and one terminal projection per selected scenario. (FR-001, FR-005, FR-012, FR-013)
- [ ] T004 Implement models in src/pocdantic/validation/models.py and catalog loading in src/pocdantic/validation/catalog.py with C01: "`schema_version` is exactly `1`; unknown fields and unsupported versions are rejected"; C02: "Generated identifiers are UUIDs; labels match `^[a-z][a-z0-9-]{1,63}$`; revisions/digests are 64 lowercase hexadecimal characters; all timestamps are timezone-aware UTC"; C03: "Select 1–32 distinct registered scenarios; mode is `offline` or `live`; scenarios execute sequentially; live interactive scenarios require `interactive=true`; `live-phone` requires exactly one explicit scenario"; C04: "Scenario timeout is 1–180 seconds, suite timeout 1–1800 seconds, cleanup timeout 1–30 seconds; defaults are 30 offline/150 live, 300 suite and 30 cleanup"; C05: "A terminal outcome is `pass`, `fail`, `blocked` or `interrupted`; safe reason codes match `^[a-z][a-z0-9_]{1,63}$` and belong to the closed contract registry; arbitrary error strings are forbidden"; nullable completion/parent/trace fields and lifecycle enums follow data-model.md. (FR-001, FR-005, FR-012)
- [ ] T005 [P] Write private-store tests in tests/test_validation_store.py for symlinks, path traversal, concurrent writers, overwrite refusal, output outside .local/ or not Git-ignored, quota exhaustion, atomic-write failure, invalid encoding, duplicate keys, immutable revision digests and recovery of an unfinished manifest. (FR-005, FR-010, FR-016)
- [ ] T006 Implement src/pocdantic/validation/store.py with C06: "At most 100 artifacts, 10 MiB per artifact, 64 KiB per event, depth 16, 10,000 normalized events and 100 MiB total bytes per run; reject duplicate JSON keys and invalid UTF-8" and C07: "Private directories use 0700 and files use 0600; reject symlinks/path escapes, existing run overwrite and concurrent writers; copies and reports use atomic finalization; output must be beneath the project .local/ root and verified Git-ignored when in a worktree"; preserve bounded journals, private source copies and old revisions without automatic deletion. (FR-005, FR-010, FR-016)
- [ ] T007 [P] Write event/sink/definition-reference tests in tests/test_observability.py covering all typed phase enums, standard trace/span ID formats, private native bindings, stable opaque definitions, dropped arbitrary text and sink failure during cleanup. (FR-006, FR-009, FR-016)
- [ ] T008 Implement typed lifecycle/private-operation sink protocols in src/pocdantic/observability.py and persistent locked definition mapping in src/pocdantic/validation/store.py with C08: "Public metadata contains only opaque generated IDs, registered labels, enums, nonnegative counts/durations, safe reason codes and digests; native IDs, paths, payloads, secrets and free-form text are private"; sink failures must preserve finally/cleanup behavior. (FR-006, FR-009, FR-016)

**Checkpoint**: Strict contracts and private storage are independently testable; no external effect yet.

## Phase 3: US1 — Repeatable demonstration (Priority P1, MVP)

**Independent test**: One offline invocation covers all nine scenarios without network and emits terminal results.

- [ ] T009 [P] [US1] Write runner tests in tests/test_validation_runner.py for bounded sequential execution, missing extras/settings, expired identity, poisoned environment, timeout, first/repeated cancellation, no retry after uncertain effects and partial report recovery. (FR-002, FR-004, FR-005)
- [ ] T010 [P] [US1] Write effect-boundary scenario tests in tests/test_validation_scenarios.py for delegated reads, attempted forbidden actions/injection, denied/expired/replayed/mutated approvals and cleanup failure/cancellation; assert attempted boundaries plus zero forbidden effects, not model wording. (FR-003, SC-003)
- [ ] T011 [US1] Implement offline factory scenarios in src/pocdantic/validation/scenarios.py using existing Runtime/native capabilities and explicit deterministic models/adapters; distinguish expected negative assertion success from failed underlying operations and never import tests/ or local chat/. (FR-002, FR-003, SC-003)
- [ ] T012 [US1] Implement src/pocdantic/validation/runner.py with strict preflight, per-run sinks, suite/scenario/cleanup budgets, bounded event journals and complete terminal projections; isolate offline settings and prevent live fallback to synthetic adapters or administrative credentials. (FR-002, FR-004, FR-005, SC-001)
- [ ] T013 [US1] Add live database and explicitly interactive phone factories in src/pocdantic/validation/scenarios.py using genuine verified ingress, scoped broker and Verify approval backend; test missing prerequisite blocking, actor-only denial, safe handling if that request unexpectedly succeeds, exact cleanup and no automatic live retries. (FR-004, FR-015, FR-018)
- [ ] T014 [P] [US1] Write CLI contract tests in tests/test_validation_cli.py for list/run selection, invalid/duplicate inputs, mode/interactive enforcement, missing or multiple phone selections denied before any push, stdout privacy and exit precedence 130 > 1 > 2 > 0. (FR-001, FR-004, FR-012)
- [ ] T015 [US1] Add validate list/run parsing in src/pocdantic/cli.py and initial whitelist-only JSON/Markdown result projection in src/pocdantic/validation/report.py; preserve existing commands and distinguish wider blocked customer criteria from selected scenario failures. (FR-012, FR-013, SC-001)

**Checkpoint**: US1 is a usable offline MVP. Live scenarios require separately supplied prerequisites.

## Phase 4: US2 — Confidential-data-free traces (Priority P1)

**Independent test**: Local captured native spans preserve lineage and contain no canaries; receipt remains separate.

- [ ] T016 [P] [US2] Write telemetry wrapper/transport tests in tests/test_telemetry.py covering initial/updated names and attributes, events/links, exception/status text, tool schemas, resources/baggage, metrics, poisoned OTEL variables, redirect refusal, safe exporter logging and no ambient network. (FR-002, FR-007, FR-009, SC-005)
- [ ] T017 [US2] Extend tests/test_observability.py with runtime/parent-child/policy/approval/database lifecycle ordering, failed child terminal events, per-operation ID uniqueness and sink exceptions that cannot skip cleanup. (FR-005, FR-006, SC-004)
- [ ] T018 [US2] Wire typed sinks into src/pocdantic/runtime.py, capabilities.py, broker.py, vault.py, services.py and verify.py; bind identities when constructing trusted execution, persist per-operation IDs before calls, propagate audited X-Correlation-Id for Vault and expose native IDs only to private sinks; retain Audit.events and the broker string observer. (FR-006, FR-009, FR-010)
- [ ] T019 [US2] Implement the public OpenTelemetry provider/tracer/span allowlist wrappers and sole exporter pipeline in src/pocdantic/telemetry.py using research R1–R3; preserve native SpanContext, fresh root Context, fixed Resource/scope, NoOpMeterProvider and explicit safe OTLP transport; no private SDK access, global configure or unfiltered parallel exporter. (FR-006, FR-009, SC-005)
- [ ] T020 [US2] Add validated POCDANTIC_LOGFIRE_BASE_URL and key-only region discovery in src/pocdantic/settings.py and telemetry.py; inject providers throughout Runtime/build_agent and parent/child instrumentation, with a base-only no-op and optional local capture for offline mode. (FR-002, FR-007, FR-015)
- [ ] T021 [US2] Implement attempted/acknowledged/received delivery state and bounded five-second flush in src/pocdantic/telemetry.py and validation/runner.py; track actual exported batch IDs and partial rejection, keep receipt unset until imported evidence, and make telemetry failure unable to bypass lease cleanup. (FR-005, FR-008)
- [ ] T022 [US2] Add a full native nested-agent and trusted-lifecycle canary test in tests/test_telemetry.py inspecting both captured spans and serialized OTLP payloads across success, denial, exceptions and cancellation. (FR-006, FR-009, SC-004, SC-005)

**Checkpoint**: Native lineage and safe export are proven locally. Remote receipt still needs live source rows.

## Phase 5: US3 — Correlated source evidence (Priority P2)

**Independent test**: Known fixture bindings match; wrong-run, missing, unsupported and tampered evidence never pass.

- [ ] T023 [P] [US3] Write normalizer tests in tests/test_validation_importers.py for Vault JSONL, Verify Events envelopes and Logfire rows; cover malformed/oversized/deep input, incomplete windows, native unknown fields, source-instance collisions, supported mapping versions and secrets in every imported field. (FR-009, FR-010, FR-011)
- [ ] T024 [US3] Implement src/pocdantic/validation/importers.py with fixed versioned native adapters and C09: "Native operation IDs are private nonempty strings of at most 512 characters, scoped by source instance; imported observation windows have start <= end; identical duplicates deduplicate and conflicting duplicates fail"; preserve private raw-byte digests/provenance and refuse arbitrary mappings, remote URL fetches or archive extraction. (FR-010, FR-015, FR-016)
- [ ] T025 [P] [US3] Write correlation tests in tests/test_validation_correlation.py for exact Vault request/response/header binding, compatible lease HMAC contexts, unsupported OAuth metadata, Verify transaction-versus-audit linkage, Logfire project/trace/run parentage, clock skew, delayed receipt and absence claims from incomplete exports. (FR-008, FR-011, FR-018)
- [ ] T026 [US3] Implement src/pocdantic/validation/correlation.py with C10: "Correlation is `matched`, `missing`, `unsupported`, `ambiguous`, `outside_window`, `incomplete_export` or `contradicted`; timestamps alone never establish a match"; enforce the blocked/fail mapping and registered source rules in data-model.md and research R4, without assuming Verify ID equivalence or newer Vault fields. (FR-008, FR-011, FR-018, SC-004)
- [ ] T027 [US3] Add validate import and correlated report assembly in src/pocdantic/cli.py and validation/report.py, plus command tests in tests/test_validation_cli.py; include required suite evidence checks and exact missing-source reasons without issuing provider requests. (FR-010, FR-011, FR-012)

**Checkpoint**: Fixture and imported evidence correlation works independently of a live collector.

## Phase 6: US4 — Reviewable acceptance (Priority P2)

**Independent test**: Report construction preserves all criteria; only unchanged, live, explicitly reviewed evidence passes.

- [ ] T028 [P] [US4] Write report tests in tests/test_validation_report.py for every terminal outcome, counts, format parity, escaped fixed Markdown projection, missing evidence instructions, local/mixed/live strength, fifteen criterion coverage and no paths/customer text in public output. (FR-012, FR-013, FR-016, SC-001)
- [ ] T029 [P] [US4] Write review tests in tests/test_validation_review.py for missing/changed files, digest/config/suite/mapping drift, local-only references, duplicate/missing criteria, free-form review privacy and alternatives that attempt to bypass evidence requirements. (FR-013, FR-014, SC-006)
- [ ] T030 [US4] Complete src/pocdantic/validation/report.py with C12: "A report includes each of the 15 existing criteria exactly once; customer pass/alternative requires live evidence, resolved references, observation time, reviewer and an unchanged review digest"; compose with src/pocdantic/evidence.py without relaxing existing validation or editing tracked acceptance records. (FR-012, FR-013, FR-018, SC-006)
- [ ] T031 [US4] Implement src/pocdantic/validation/review.py with C11: "Review decisions are `pass`, `fail`, `blocked` or `alternative`; reviewer is 1–128 characters and rationale is 1–2000 characters, both private; every review includes criterion, UTC review time and an exact evidence revision digest"; bind all revision inputs from data-model.md and reject stale data immediately before atomic recording. (FR-014, FR-016, SC-006)
- [ ] T032 [US4] Finish validate review/report in src/pocdantic/cli.py and tests/test_validation_cli.py, preserving separate invocation/review/acceptance outcomes and immutable prior records; run the complete fixture-based import-review-report workflow. (FR-012, FR-013, FR-014)

**Checkpoint**: All four stories work independently with deterministic fixtures and compose through the CLI.

## Phase 7: Validation and handoff

- [ ] T033 [P] Update README.md, CONTRIBUTING.md, .env.example and docs/adr/0004-validation-evidence.md with commands, optional dependencies, private exports, token-only routing, limits, migration/compatibility and evidence/reviewer boundaries from the implemented contracts. (FR-007, FR-015, FR-016, FR-018)
- [ ] T034 Extend .github/workflows/ci.yml and tests/test_validation_runner.py to run the offline suite ten times with unique IDs, <=30 seconds/run and identical expected classifications; exercise two synthetic configurations, 10,000-event report assembly <=5 seconds excluding I/O, and network denial with poisoned environment. (FR-005, FR-015, FR-017, SC-002, SC-006)
- [ ] T035 Extend tests/test_publication.py and verify scripts/check_privacy.py and scripts/check_distribution.py reject generated evidence/reviews/reports and retain chat/design exclusions; verify installed base wheel offline behavior outside the repo and bundled catalog presence without optional SDKs. (FR-016, FR-017)
- [ ] T036 Execute the authorized live database/Logfire walkthrough from specs/002-security-validation/quickstart.md, capturing real operation, export receipt and supported Vault correlation privately under .local/validation/; record sanitized observations and any unsupported Verify/actor audit fields in specs/002-security-validation/validation.md. Leave this task open if required real receipt/correlation prerequisites are unavailable. (FR-004, FR-008, FR-011, SC-003, SC-004)
- [ ] T037 Execute the explicitly selected, witnessed live phone approve/deny scenarios from specs/002-security-validation/quickstart.md; capture genuine transaction evidence privately and record independent Events-audit linkage or its blocker in specs/002-security-validation/validation.md. Leave this task open until the human scenarios are observed. (FR-004, FR-018, SC-003)
- [ ] T038 Run all software gates from CONTRIBUTING.md and the completed quickstart, validate all feature artifacts independently of machine-local state, and record exact results/remaining customer gates in specs/002-security-validation/validation.md without promoting the acceptance.json snapshot automatically. (FR-017, FR-018, SC-001–SC-006)
- [ ] T039 Review the prospective Git/distribution contents and PR against .github/pull_request_template.md; verify required validate check, owner review, stale-review dismissal and default-branch protection before merge, record any delivery blocker in specs/002-security-validation/validation.md, and delete the feature branch locally/remotely after an authorized merge. (FR-016, FR-017)

## Dependencies and execution order

T001–T002 -> T003–T008 -> US1 -> US2 -> US3 -> US4 -> final gates.
Within foundation: T004 follows T003; T006 follows T005 and T004; T008 follows T007 and T006.
Within each story, test tasks precede their implementation and implementation precedes CLI integration.
T013 requires T011/T012 and later T018 adds source bindings; T015 supplies the US1 MVP projection,
T027 enriches it with correlations, and T030 completes acceptance rendering. T021 follows T019/T020;
T022 exercises all US2 wiring. T024 follows T023/store; T026 follows T025/T024 and US2 bindings.
T031 follows T029/T030; T032 follows T031. Live tasks T036/T037 require completed software through
T035 and their external prerequisites. T038/T039 require the available validation evidence and must
state any uncompleted live work honestly. No automatic task completion on an external blocker.

## Independent and parallel work

No parallel implementation agents are required. [P] identifies optional work on disjoint files,
not authorization to spawn agents or a waiver of dependencies.

- Foundation: T003 model tests, T005 store tests and T007 event tests can be authored independently.
- US1: T009 runner tests and T010 scenario tests; T014 CLI tests can be authored alongside T011
  once model/catalog contracts exist. Implementation integration remains sequential.
- US2: T016 privacy tests and T017 lifecycle tests can be prepared in parallel after foundation;
  T019/T020/T021 share telemetry.py and must be sequential.
- US3: T023 import tests and T025 correlation tests can be authored separately from frozen contracts;
  T026 waits for normalized source models and private bindings.
- US4: T028 report tests and T029 review tests can be authored independently; report/review integration
  follows the stated sequence.
- Final: T033 documentation can run alongside T035 publication verification after interfaces stabilize.

## Implementation strategy

Deliver US1 as the offline MVP, validate it, then add safe telemetry, exact source correlation and
explicit reviews in order. Commit focused increments under mcteer. Never add private artifacts,
frontend code or raw evidence. Run tests appropriate to each change, then the full required gates.
Run live scenarios only after deterministic privacy/boundary tests pass and prerequisite checks
are satisfied. The current handoff ends at analysis; no task is complete yet.

## Requirements coverage

| Requirement | Tasks |
| --- | --- |
| FR-001 | T002, T003, T004, T014 |
| FR-002 | T009, T011, T012, T016, T020 |
| FR-003 | T010, T011 |
| FR-004 | T009, T012, T013, T014, T036, T037 |
| FR-005 | T003–T006, T009, T012, T017, T021, T034 |
| FR-006 | T007, T008, T017–T019, T022 |
| FR-007 | T016, T020, T033 |
| FR-008 | T021, T025, T026, T036 |
| FR-009 | T007, T008, T016, T018, T019, T022, T023 |
| FR-010 | T005, T006, T018, T023, T024, T027 |
| FR-011 | T023, T025–T027, T036 |
| FR-012 | T003, T004, T014, T015, T027, T028, T030, T032 |
| FR-013 | T003, T015, T028–T030, T032 |
| FR-014 | T029, T031, T032 |
| FR-015 | T001, T002, T013, T020, T024, T033, T034 |
| FR-016 | T005–T008, T024, T028, T031, T033, T035, T039 |
| FR-017 | T001, T002, T034, T035, T038, T039 |
| FR-018 | T013, T025, T026, T030, T033, T037, T038 |
| SC-001 | T012, T015, T028, T038 |
| SC-002 | T034, T038 |
| SC-003 | T010, T011, T036, T037, T038 |
| SC-004 | T017, T022, T026, T036, T038 |
| SC-005 | T016, T019, T022, T038 |
| SC-006 | T029–T031, T034, T038 |
