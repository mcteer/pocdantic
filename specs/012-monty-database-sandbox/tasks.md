# Tasks: Monty Database Sandbox

**Input**: spec.md, plan.md, research.md, data-model.md, contracts/runtime.md, quickstart.md
**Tests**: Required by FR-014. Checked tasks have completed implementation and verification; owner review remains separate. [P] means separate files and
no dependency between those tasks after their stated phase prerequisites are complete.

## Phase 1: Setup

- [X] T001 Add optional `sandbox` extra with `pydantic-monty==1.1.0` and `sqlglot==30.22.0` in pyproject.toml/uv.lock; review direct/transitive licenses and matching installed worker resolution, then add real-worker startup/async-callback/denied-import compatibility probes in tests/test_sandbox_compatibility.py and record results in specs/012-monty-database-sandbox/validation.md (FR-003, FR-013, FR-014; SC-005).
- [X] T002 Update AGENTS.md and CONTRIBUTING.md narrowly to allow this profile's generated read-only SQL through a closed admission/compiler boundary; retain fixed-reader guidance, document module/function responsibilities, credential privacy and reviewed dependency notices in docs/configuration.md (FR-001, FR-005, FR-006, FR-013, FR-014).
- [X] T003 Create src/agent/sandbox/__init__.py without eager optional imports; add explicit unavailable detection and exact installation guidance in src/agent/setup/readiness.py plus base-install tests in tests/test_sandbox_optional.py and provider/environment guards in tests/conftest.py (FR-001, FR-013, FR-014; SC-005).

## Phase 2: Foundational boundaries

Prerequisite: Phase 1 compatibility probes pass. These are shared by every story.

- [X] T004 Define and test strict models in src/agent/sandbox/models.py and tests/test_sandbox_models.py: host UUID ownership; profile `database-analyst`; code `1–16384 bytes`; SQL `1–8192 bytes`; request `at most 16384 bytes`; parameters `0–32 elements`, strict signed 64-bit integer or UTF-8 string `at most 1024 bytes`; reject bool/null/float/container/coercion/extra fields. Encode data-model.md's closed state/boundary/outcome/reason/limit enums and immutable ReadPlan rules (FR-004, FR-005, FR-007, FR-009, FR-010).
- [X] T005 [P] Add adversarial SQL/worker contract tests in tests/test_sandbox_sql.py for every allowed form and rejected construct in contracts/runtime.md, including unknown AST fields, `at most 256 nodes and depth 16`, process timeout/output bounds, Unicode/comments, operators, catalogs, parameter type/index mismatch and zero downstream dispatch (FR-005, FR-007, FR-014; SC-002, SC-004).
- [X] T006 Implement bounded parser worker and trusted compiler in src/agent/sandbox/sql_worker.py and src/agent/sandbox/sql.py: 1-second kill/reap bound, no shell/argument payload, closed ReadPlan revalidation, relation `public.poc_records`, kinds rows/count/grouped_count, `0–8` AND comparisons, `0–2` unique order terms, `limit 1–100, default 100`, trusted ONLY/pg_catalog fragments and separate driver parameters; never execute source or AST serialization (FR-005, FR-007; SC-002, SC-004).
- [X] T007 Add trusted `database-analyst` policy role and sandbox.execute resource database-analysis in src/agent/schemas.py and src/agent/security.py; retain database.read scope/resource enforcement for this new role and test forged profile/identity, scope denial and old-profile behavior in tests/test_sandbox_policy.py (FR-001, FR-004, FR-009, FR-014).
- [X] T008 Extract common auth/custody mechanics beneath DatabaseBroker.__call__ in src/agent/broker.py and src/agent/vault.py without changing its fixed query; add typed admitted-query entry point with no model-provided executor/target, preserving root guards, JWT checks, effect lock, v3 journal and both cleanup routes; run existing tests/test_broker.py and tests/test_portable_vault.py (FR-001, FR-004, FR-006, FR-008).

## Phase 3: US1 — Ask and compute (P1)

Goal: Real generated execution can query permitted records and compute a correct answer.
Independent test: three known questions over four synthetic records; broker assertions separately
exercise both authentication routes. The live run is a separate final acceptance task.

- [X] T009 [P] [US1] Add both-route admitted-query tests in tests/test_sandbox_broker.py: policy/JWT/SQL denial before issuance, recheck every callback, immutable query binding, fresh credentials per call and no results until exact cleanup; include expired identity, prior unresolved state and guard changes (FR-004, FR-005, FR-006; SC-001, SC-003).
- [X] T010 [P] [US1] Add real-Monty program tests in tests/test_sandbox_runner.py for callback suspend/resume, filtered/grouped/percentage results, empty rows, strict input/output boundaries and no credential objects, keeping transport guards active (FR-002, FR-003, FR-006, FR-007; SC-001).
- [X] T011 [P] [US1] Add generation/runtime tests in tests/test_sandbox_runtime.py requiring one generated program, two meaningfully different admitted queries, computation after retrieval, at least one observed database read, denial of fabricated success and correct model-refusal/not-exercised outcome (FR-001, FR-002, FR-010, FR-011; SC-001, SC-002).
- [X] T012 [US1] Implement src/agent/sandbox/runner.py with AsyncMonty, pinned installed worker, one worker/one checkout, no modules/mounts/host objects, a single query_database callback, private bounded print sink and closed errors; enforce the contract's 32 MiB allocator, 2s compute, 30s active, 64 recursion, 16 suspensions, zero sleep, 1s checkout, 5s request and 0.5s timeout-grace bounds without claiming an RSS limit (FR-003, FR-007, FR-009).
- [X] T013 [US1] Implement the admitted database execution in src/agent/broker.py and src/agent/vault.py: read-only transaction, verified TLS, 5s connect/statement and 1s lock bounds, administrator-managed built-in column schema, server-side limit+1, `0–100` rows and `at most 65536 bytes`, status cells `up to 4096 UTF-8 bytes`, strict integer id/count, truncation flag and confirmed cleanup before returning; preserve fixed reader behavior (FR-005, FR-006, FR-007; SC-001, SC-003).
- [X] T014 [US1] Wire src/agent/sandbox/capability.py through src/agent/capabilities.py and src/agent/runtime.py plus config/agents.json: curated schema/prompt, run_python(code), role binding, one submission/three sequential query reservations, no implicit retries, callback task ownership and timeout/drain contract; keep eager profile creation safe without optional dependencies (FR-001, FR-002, FR-004, FR-007, FR-009).
- [X] T015 [US1] Add config/sandbox-demo.sql and tests/test_sandbox_postgres.py with a dedicated synthetic four-row table and restricted SELECT-only role; add an isolated PostgreSQL CI service/job in .github/workflows/ci.yml, validate compiler semantics/read-only grants/types/truncation/timeouts and never provision a remote deployment or commit credentials (FR-005, FR-014; SC-001, SC-002).
- [X] T016 [US1] Add privacy tests in tests/test_sandbox_privacy.py for generated code, parameters, rows, stdout and exceptions across model tool tracing, Monty tracing, application telemetry and broker errors; implement suppression/projection in src/agent/sandbox/capability.py, src/agent/sandbox/runner.py and src/agent/telemetry.py so raw payloads never enter exporters (FR-006, FR-010, FR-014).

## Phase 4: US2 — Demonstrate denied actions (P1)

Goal: Show the responsible boundary with real engine execution and zero forbidden effects.
Independent test: fixed offline probes, including the remote-Linux-command scenario.

- [X] T017 [P] [US2] Add controlled actual-engine probes in tests/test_sandbox_demo.py for host file/env access, sockets, ssh/process launch, remote-library import and unexposed run_remote_command; assert zero host query/credential/remote effects, and distinguish these from model refusal and SQL-policy rejection (FR-003, FR-005, FR-011, FR-014; SC-002).
- [X] T018 [P] [US2] Add resource/partial-effect cases in tests/test_sandbox_limits.py covering loop, memory, output, sleep, recursion, suspension/callback excess, concurrent calls, parser hang, caught denial, earlier successful read and later failure; assert declared bounds and no authority after a latched failure (FR-007, FR-008, FR-011; SC-002, SC-004).
- [X] T019 [US2] Implement fixed catalog/report generation in src/agent/sandbox/demo.py and src/agent/sandbox/commands.py, register agent sandbox demo in src/agent/cli.py, and enforce exit 0/1/2/130 with metadata-only outcomes and origin synthetic; no user-code argument or real provider/SSH dispatch (FR-010, FR-011, FR-012; SC-001, SC-002, SC-004).
- [X] T020 [US2] Add closed sandbox/query observation codes to src/agent/observability.py and revision inputs to src/agent/validation/models.py; include all sandbox modules/config/pins, add evidence classification tests in tests/test_sandbox_evidence.py and preserve original native acceptance/closeout semantics (FR-010, FR-011, FR-012, FR-014; SC-002, SC-006).

## Phase 5: US3 — Cancel and recover (P1)

Goal: Terminating a worker cannot abandon host callbacks or silently clear custody.
Independent test: injected cancellation/crash/lost-response at every effect transition.

- [X] T021 [P] [US3] Add host-task cancellation/drain tests in tests/test_sandbox_cancellation.py for callback registration races, outstanding coroutines after worker exit, sign-out, request deadline and guard changes before resume; verify no new calls and no released effect lock while work remains (FR-008, FR-009, FR-014; SC-003, SC-004).
- [X] T022 [P] [US3] Add tests/test_sandbox_recovery.py covering both-route lost issuance replies, lease failure, native-token cleanup despite lease failure, restart, replay, duplicate submissions and independent session canaries using existing recovery/response stores (FR-006, FR-008, FR-009, FR-014; SC-003, SC-004).
- [X] T023 [US3] Complete tracked callback registry, cancellation latch and teardown in src/agent/sandbox/runner.py and src/agent/runtime.py; drain independently owned broker tasks through existing 30s cleanup reserve, kill/reap parser and engine workers, discard sessions and preserve unresolved state without retries (FR-007, FR-008, FR-009; SC-003, SC-004).
- [X] T024 [US3] Integrate sandbox completion/read/cleanup counts and partial/unresolved outcomes into src/agent/workspace/runs.py; preserve idempotent admission and no-replay retry semantics, and extend tests/test_workspace_runs.py for the new capability's success requirements and sign-out containment (FR-001, FR-008, FR-010, FR-012; SC-003).

## Phase 6: US4 — Portable and explainable demonstration (P2)

Goal: A colleague runs offline/live demonstrations and inspects genuine execution stages.
Independent test: clean optional/base installs, macOS/Linux engine checks and WebKit ownership.

- [X] T025 [P] [US4] Add tests/browser/test_workspace_sandbox.py and tests/test_sandbox_workspace.py for signed owner-only inspection, foreign/malformed IDs, 404/410, no-store, inert code display, truncation/refusal/unavailable labels, keyboard access, sign-out purge and result bounds (FR-010, FR-013, FR-014; SC-005).
- [X] T026 [US4] Implement GET /workspace/runs/{job_id}/sandbox and Show execution in src/agent/workspace/app.py, src/agent/workspace/models.py, src/agent/workspace/runs.py and src/agent/workspace/static/{app.js,index.html,style.css}; keep code/queries transient with `at most 131072 encoded bytes per run`, `at most 10 run inspections per session`, final output/print combined `at most 16384 encoded bytes`, and metadata `at most 32` observations; purge on sign-out/expiry and never return parameters/provider secrets (FR-007, FR-009, FR-010, FR-013).
- [X] T027 [US4] Extend .github/workflows/ci.yml with sandbox-extra full validation, Python 3.12 macOS arm64/Linux x86_64 real-worker smoke checks and a separate base-install check using tests/test_sandbox_optional.py; verify installed runtime executable identity and isolated PostgreSQL test admission in tests/conftest.py (FR-001, FR-013, FR-014; SC-005).
- [X] T028 [US4] Update docs/setup.md, docs/configuration.md, docs/usage.md, README.md and AGENTS.md with optional install, exact sample questions, remote-Linux refusal versus rejection, Vault credential flow, bounds, inspection privacy and recovery instructions; keep the README concise (FR-006, FR-011, FR-013; SC-005).

## Phase 7: Validation and delivery

- [X] T029 Run focused and full CI gates, WebKit, both-profile security regression, offline demo/validation and new real-Monty/isolated-PostgreSQL matrix; record exact versions, platforms, results and remaining limits in specs/012-monty-database-sandbox/validation.md (FR-014; SC-001, SC-002, SC-003, SC-004, SC-005).
- [X] T030 Execute one separately authorized live model-generated query/computation using a prepared deployment and human login as needed; verify actual acquisition/read and route-specific cleanup, retain private evidence under .local/ and record a sanitized outcome or exact missing administrator prerequisite in specs/012-monty-database-sandbox/validation.md (FR-002, FR-006, FR-012; SC-006).
- [X] T031 Review prospective publication/dependency notices and packaged optional resources with scripts/publish_policy.py, scripts/check_distribution.py and git diff; run build/distribution and staged/history privacy gates, keeping raw programs/results out of Git; record results in specs/012-monty-database-sandbox/validation.md (FR-010, FR-013, FR-014).
- [X] T032 Obtain owner review of the concrete implementation/boundary changes and live limitations, update specs/012-monty-database-sandbox/validation.md, and preserve independent truthful statuses in specs/012-monty-database-sandbox/acceptance.json; implementation authorization is not fabricated acceptance evidence (FR-012, FR-014; SC-006).

## Dependencies and parallel opportunities

T001 → T003; T002 is documentation but completes before behavioral work. T004 → T005/T007;
T005 → T006; T004/T006/T007 → T008. US1 tests T009/T010/T011 can be authored in parallel
following Phase 2; T012/T013 follow their relevant tests; T014 joins them; T015/T016 validate
the joined path. US2 test T017 and T018 are independent; T019/T020 follow passing runtime
integration. US3 T021/T022 are independent test files; T023/T024 follow them. US4 T025 can be
authored after contracts stabilize; T026 follows T024/T025; T027 updates CI after T015;
T028 follows final command/UI behavior. Final T029/T031 validate the completed software;
T030 requires live prerequisites and remains unchecked if they are absent; T032 follows reviewable
validation. Do not run live tests or override unresolved recovery while waiting for prerequisites.

Parallel examples: US1 T009 + T010 + T011; US2 T017 + T018; US3 T021 + T022; US4 T025 test
authoring alongside T028 documentation drafting, with final docs reconciled after T026. Shared
runtime/broker/UI/CI edits remain sequential. [P] does not authorize live provider operations.

## Implementation strategy

First achieve US1's synthetic query-and-compute path while preserving all foundational checks.
US2 and US3 are security requirements for delivery, not optional polish; do not ship the MVP
without their denials, budgets and lifecycle tests. Add the portable UI/documentation layer,
then complete software gates and separately review live evidence. Mark tasks only after their
actual work/verification is complete; do not mark T030 complete for an unexecuted live test.
