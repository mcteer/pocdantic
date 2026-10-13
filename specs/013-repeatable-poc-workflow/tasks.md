# Tasks: Repeatable PoC Workflow

**Input**: [spec](spec.md), [plan](plan.md), [research](research.md), [data model](data-model.md),
[runtime contract](contracts/runtime.md), [agent bootstrap contract](contracts/agent-bootstrap.md).
**Status**: T001–T029 implemented and merged in PR #17. T030/T031 remain open for external evidence/review; see validation.md.
**Tests**: Required by FR-008 and constitution 1.2.0. Write meaningful failing regressions before
changing the corresponding behavior. Never use actual private deployment state in ordinary tests.

Format: `- [ ] Tnnn [P?] [USn?] action with exact file paths`. [P] means independent files/work
within the stated phase; it does not authorize editing shared files concurrently or skipping dependencies.

## Phase 1 — Setup and implementation boundary

- [X] T001 Confirm the implementation scope, baseline revision, focused failing probes and no live authority in specs/013-repeatable-poc-workflow/validation.md; read AGENTS.md/CONTRIBUTING.md/constitution and use the locked environment without changing .env.local/.local (FR-006, FR-008, FR-011).

## Phase 2 — Foundational contracts (before story implementation)

- [X] T002 Add strict catalog/report contract tests in tests/test_setup_recipes.py covering unknown/extra fields, duplicate IDs, over-limit collections/output, action dependency cycles, unsupported model prefixes and SetupReport v1 compatibility (FR-002, FR-009, FR-010).
- [X] T003 Implement the new ephemeral models in src/agent/setup/models.py from data-model.md: recipe ID exactly offline/workspace-read/workspace-analysis; extras at most six and capabilities at most four; guide schema_version 1; findings at most 32 and actions at most 16 with unique IDs; setting names match `[A-Z][A-Z0-9_]{0,63}` and are allowlisted; dependencies at most sixteen with no self-reference/cycle; all closed enum sets exact, extra fields forbidden and compiled definitions immutable; keep existing SetupReport v1 unchanged (FR-002, FR-004, FR-009, FR-010).
- [X] T004 Implement the immutable recipe/action/command catalog in src/agent/setup/recipes.py, including nullable profile/command IDs, exact effect/owner/proof labels, deterministic ordering and fixed extras/profile/capability requirements; no executable arbitrary strings or provider construction (FR-002, FR-006, FR-009).

Checkpoint: strict contracts/catalog tests pass. No new authority, persistent journal or schema migration.

## Phase 3 — US1: Reliable offline rehearsal (P1, smallest MVP)

**Goal**: A live configuration mistake cannot break or redirect offline rehearsal.
**Independent test**: Real CLI subprocesses under network denial and poisoned config, with private-state canaries.

- [X] T005 [US1] Add actual CLI subprocess regressions in tests/test_offline_entrypoints.py for clean/invalid dotenv and environment, short/legacy aliases, MODEL/PROFILES_FILE/telemetry poisoning, absent provider extras and unchanged private-state canaries; reproduce the recorded TIMEOUT_SECONDS defect (FR-001, FR-008, FR-009; SC-001).
- [X] T006 [US1] Add a validated synthetic settings/default-definition construction path in src/agent/settings.py that consults neither environment nor dotenv and cannot select ambient profiles/providers; do not globally mutate os.environ or weaken Settings validation (FR-001, FR-006).
- [X] T007 [US1] Dispatch the demo before live settings in src/agent/cli.py, consume the synthetic factory and preserve existing output/alias semantics; audit src/agent/sandbox/commands.py and src/agent/validation/runner.py for the same offline authority boundary without changing their proof/cleanup semantics (FR-001, FR-006, FR-010).
- [X] T008 [US1] Extend tests/test_offline_entrypoints.py to prove ten consecutive bounded runs with normalized expected outcomes, optional real-Monty unavailable handling, zero provider/telemetry traffic and zero live-state changes; record the focused result in specs/013-repeatable-poc-workflow/validation.md (FR-001, FR-008; SC-001, SC-006).

Checkpoint: US1 independently usable. This does not claim setup readiness or live portability.

## Phase 4 — US2: Recipe-specific truthful readiness (P1)

**Goal**: Detect known local launch blockers before launch and load the selected provider key consistently.
**Independent test**: Recipe × dependency/key/profile/limit matrix, using synthetic providers only.

- [X] T009 [P] [US2] Add prerequisite matrix regressions in tests/test_setup_recipes.py for server/postgres/model/sandbox packages, TIMEOUT_SECONDS 1–180, profile selection, trust errors, empty key wrappers and independent sign-in versus database readiness (FR-002, FR-003; SC-002).
- [X] T010 [P] [US2] Add private-file/environment/source-precedence tests in tests/test_model_configuration.py for Google/OpenAI/Anthropic, all reviewed prefixes, chat/responses distinction, absent unrelated keys, unknown custom direct resolution and zero secret error leakage (FR-003, FR-009, FR-010; SC-002).
- [X] T011 [US2] Implement reviewed provider descriptors/constructors in src/agent/model_config.py, private OPENAI_API_KEY/ANTHROPIC_API_KEY Settings fields in src/agent/settings.py and trusted selected_model integration in src/agent/cli.py; preserve existing aliases and unknown direct-runtime behavior without key printing or new dependencies (FR-003, FR-009, FR-010).
- [X] T012 [US2] Implement shared, non-effectful prerequisite checks in src/agent/setup/prerequisites.py for the exact contract matrix, names-only source diagnostics, no provider construction, two-second local budget and closed timeout/unsupported outcomes (FR-002, FR-003, FR-009).
- [X] T013 [US2] Wire explicit recipe selection into src/agent/setup/commands.py and src/agent/setup/readiness.py and common launch prerequisites into src/agent/workspace/app.py; omitted recipe remains workspace-read, offline recipe checks bypass live Settings/enrollment, preserve SetupReport v1 JSON/0-2-3 precedence, reject offline --network before dispatch and retain explicit public-network bounds/evidence freshness (FR-003, FR-006, FR-010).
- [X] T014 [US2] Extend tests/test_setup_readiness.py and tests/browser/test_workspace_portability.py for guided versus direct-provider compatibility, optional baseline independence, no false supported promotion and zero requests on failed preflight; rerun affected denial/cancellation/replay/cleanup tests and record results in specs/013-repeatable-poc-workflow/validation.md (FR-003, FR-006, FR-008; SC-002, SC-006).

Checkpoint: missing supported local prerequisites cannot yield a green launch check. No paid/network key validation.

## Phase 5 — US3: Safe repeat and deployment isolation (P1)

**Goal**: Show the next safe step without overwriting, resetting, reattributing or mixing roots.
**Independent test**: Absent/draft/enrolled/busy/held/mismatch/damaged state plus isolated root fixtures.

- [X] T015 [P] [US3] Add root-boundary subprocess tests in tests/test_project_boundary.py for checkout root/subdirectory, worktree, noncanonical/linked roots, absent/failing/timed-out Git, installed outside-Git usage and two independent deployment directories; assert refusal precedes private reads/writes (FR-005, FR-006, FR-008; SC-003).
- [X] T016 [P] [US3] Add state/action tests in tests/test_setup_guidance.py for every runtime-contract row, distinguishing absent from unreadable/partial state, required policy review, conditional action dependencies, stale observations and concurrent ownership; deny sockets/telemetry/writes (FR-004, FR-006, FR-009; SC-003).
- [X] T017 [US3] Implement bounded root classification/preconditions in src/agent/project.py and integrate before private Settings/store dispatch in src/agent/cli.py and src/agent/setup/commands.py; preserve config-free exemptions and outside-Git cwd semantics, fail on ambiguous discovery, and never move state or change fingerprints (FR-005, FR-006, FR-010).
- [X] T018 [US3] Implement read-only state projection and safe next-action selection in src/agent/setup/guidance.py, reusing sanitized status from src/agent/recovery/store.py and src/agent/response/store.py; any needed new status helper must remain read-only/bounded and cannot treat exceptions as absence (FR-004, FR-005, FR-006).
- [X] T019 [US3] Add setup guide parser/renderer in src/agent/setup/commands.py and src/agent/setup/guidance.py: text default, explicit JSON, SetupGuide v1, at most 32 findings/16 actions, at most 32 KiB output, two-second local budget, exact 0/2/3 mapping and only compiled commands; never execute or persist guidance (FR-004, FR-009, FR-010).
- [X] T020 [US3] Extend tests/test_setup_commands.py and tests/test_setup_guidance.py for three repeated preparation/guidance cycles, unchanged private bytes/journals, no draft overwrite, no auto-review/reset/replay and current-state rechecks; verify existing recover/respond effects still enforce locks/cleanup, then record results in specs/013-repeatable-poc-workflow/validation.md (FR-005, FR-006, FR-008; SC-003, SC-006).

Checkpoint: guide's next actions are safe suggestions, not authorization or live proof. No store schema migration.

## Phase 6 — US4: Agent-harness autonomous bootstrap (P1)

**Goal**: An agent can complete the mechanical setup from base variables using AGENTS.md, with exact bounded handoffs.
**Independent test**: Maintained-doc contract assertions and fresh/repeat synthetic walkthrough; real participant separately.

- [X] T021 [US4] Add instruction/command/setting contract tests in tests/test_setup_walkthrough.py for AGENTS.md and docs/setup.md using the compiled catalog and parser; require recipe selection, minimal base variables, complete locked extras, exits, review/sign-in stops, no secrets in chat and outcome separation (FR-007, FR-008, FR-010; SC-005).
- [X] T022 [US4] Update the actual AGENTS.md setup/development guidance from contracts/agent-bootstrap.md: distinguish implement versus operate scope, include concise base-variable/owner/default matrix, finite authorized install/check/enroll/launch algorithm, one retry after repair, immutable-policy review, real URL/WebKit procedure and evidence-aware final report; do not leave this only in specs (FR-007; SC-005).
- [X] T023 [US4] Update docs/setup.md and README.md with three recipe entry paths, minimal no-dev selected-extra install, no-sync follow-up commands, guided fresh/repeat flows, base-variable/environment-file choices, exact missing-administrator requests and explicit optional/full-lab limits (FR-002, FR-007, FR-010).
- [X] T024 [US4] Reconcile docs/configuration.md, docs/usage.md, .env.example and CONTRIBUTING.md with selected-provider credential loading, portable versus delegated routes, currently implemented optional features, root-only compatibility change and focused validation commands; preserve existing defaults/aliases and no new secret-bearing examples (FR-003, FR-007, FR-009, FR-010).
- [X] T025 [US4] Implement scripts/check_onboarding.py and synthetic integration coverage in tests/test_setup_walkthrough.py with fixed --case offline/guided/installed selections and exits 0/1/2/130; cap overall execution at 180 seconds plus ten-second drain, each offline child at thirty seconds, deny live dispatch and arbitrary command execution, and exercise fresh/three-repeat/two-directory paths from the documented contract (FR-007, FR-008, FR-009; SC-001, SC-003, SC-005).
- [X] T026 [US4] Extend the installed case in scripts/check_onboarding.py and package test coverage in tests/test_setup_walkthrough.py for wheel/sdist outside source/PYTHONPATH, packaged resources/aliases, base/each-provider/analysis matrices, unavailable packages and private canary exclusion; dependency environments must use committed lock resolution and artifact installs must not fall back to editable source (FR-008, FR-009, FR-010; SC-005, SC-006).
- [X] T027 [US4] Wire focused onboarding and locked artifact-install matrix jobs into .github/workflows/ci.yml with explicit time bounds and no live credentials/provider provisioning; document local reproduction in CONTRIBUTING.md, preserving existing required validate and sandbox gates (FR-008, FR-010; SC-005, SC-006).

Checkpoint: actual AGENTS.md is sufficient for authorized mechanical setup; human/admin gates remain honest.

## Phase 7 — Cross-cutting validation and delivery

- [X] T028 Review new/changed module/function documentation, security-ordering comments, public links and compatibility guidance across src/agent/setup/, src/agent/model_config.py, src/agent/project.py, AGENTS.md and docs/; review the prospective publication paths against scripts/publish_policy.py without broad allowlist expansion (FR-007, FR-009, FR-010).
- [X] T029 Run all applicable authoritative .github/workflows/ci.yml gates, new quickstart walkthroughs, WebKit, both-profile security regression, build/distribution privacy and targeted repeatability/readiness checks; record exact software results and skipped blockers in specs/013-repeatable-poc-workflow/validation.md (FR-006, FR-008, FR-009; SC-001, SC-002, SC-003, SC-005, SC-006).
- [ ] T030 With separately authorized resources and a real unfamiliar colleague, complete the still-outstanding specs/011-portable-poc-setup/tasks.md T028/T029 checks, add the five-minute warm-repeat and agent-instruction measurements, and record sanitized results in both features' validation.md; preserve raw evidence privately and leave this unchecked if access/participation is unavailable (FR-011; SC-004).
- [ ] T031 Review git diff --cached and rerun privacy against the proposed publication tree/history, obtain maintainer boundary review of provider-secret loading/root/state classification, and record delivery disposition in specs/013-repeatable-poc-workflow/validation.md while keeping acceptance.json honest; no push/merge without explicit authorization (FR-006, FR-009, FR-011; SC-006).

## Dependencies and execution order

- T001 → T002 → T003 → T004 establish the shared contract.
- US1: T005 → T006 → T007 → T008. This is the smallest independently shippable reliability fix.
- US2: T009/T010 tests can be developed in parallel after foundation; T011 → T012 → T013 → T014.
  Integrate after US1 to avoid concurrent edits to settings.py and cli.py.
- US3: T015/T016 tests can be developed in parallel after foundation; T017 → T018 → T019 → T020.
  Guide integration consumes US2's prerequisite engine. Do not edit cli.py/commands.py concurrently.
- US4: T021 → T022 → T023 → T024 → T025 → T026 → T027; it consumes US1–US3 and completes
  the explicit AGENTS.md request. Documentation drafting may start earlier, but validation depends
  on final parser/catalog behavior. T025/T026 share a script and are not parallel tasks.
- T028–T029 follow completed software stories. T030 is external acceptance, not a reason to use live
  resources in CI or block honest software-only delivery. T031 requires the actual publication tree
  and maintainer review. Never mark T030/T031 complete from an automated green report alone.

## Requirement coverage

| Requirement | Primary tasks |
| --- | --- |
| FR-001 | T005–T008 |
| FR-002 | T002–T004, T009, T012, T023 |
| FR-003 | T009–T014, T024 |
| FR-004 | T003, T016, T018–T019 |
| FR-005 | T015, T017–T018, T020 |
| FR-006 | T001, T004, T006–T007, T013–T020, T029, T031 |
| FR-007 | T021–T025, T028 |
| FR-008 | T005, T008, T014–T016, T020–T021, T025–T027, T029 |
| FR-009 | T002–T005, T010–T012, T016, T019, T024–T026, T028–T029, T031 |
| FR-010 | T002–T003, T007, T010–T011, T013, T017, T019, T021, T023–T024, T026–T028 |
| FR-011 | T001, T030–T031 |

SC-001: T005/T008/T025/T029; SC-002: T009/T010/T014/T029; SC-003: T015/T016/T020/T025/T029;
SC-004: T030 (external observation); SC-005: T021/T022/T025–T027/T029;
SC-006: T008/T014/T020/T026–T031.

## Incremental delivery and parallel examples

- First reviewable increment: foundation + US1; show the real poisoned-configuration regression fixed.
- Second: US2, showing no false-green setup for server/model/timeout/sandbox cases.
- Third: US3, showing clear versus blocked next steps without writes or reset.
- Fourth: US4, demonstrating an agent can use actual AGENTS.md to prepare a synthetic fresh/repeat
  deployment from supplied variables; then run the complete gates and separate live handoffs.
- US1 implementation is intentionally serial because factory/dispatch/tests depend on each other.
- US2 parallel example: T009 prerequisite matrix versus T010 provider-key tests (different files).
- US3 parallel example: T015 root-boundary tests versus T016 state-guide tests (different files).
- US4 has no unconditional parallel task markers: instructions, parser validation and smoke script
  must stay synchronized. A second reviewer can inspect AGENTS.md while tests run, without editing
  shared files or claiming live acceptance.

**Counts**: 31 tasks: setup/foundation 4; US1 4; US2 6; US3 6; US4 7; cross-cutting 4.
T030/T031 are external acceptance, not completed by automated gates alone.
