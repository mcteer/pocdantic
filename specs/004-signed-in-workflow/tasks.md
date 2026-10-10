# Tasks: Signed-in agent workflow

**Input**: `specs/004-signed-in-workflow/`
**Status**: Software implementation and validation complete (T001–T033). T034 live walkthrough complete (provider no-refresh fallback verified); T035 delivery requested; push/PR/CI/merge in progress.
**Tests**: Required by spec FR-015 and the constitution. Write security tests first and verify failure before changing the boundary.

Tasks follow the clarified browser workspace scope. C01–C14 below are verbatim constraints from data-model.md, with whitespace normalized. Source paths are repository-relative.

## Phase 1: Setup

Establish optional browser tooling and publishable assets without changing runtime behavior.

- [X] T001 Add the browser development group to pyproject.toml and resolve uv.lock; use Python Playwright directly, record direct/transitive license review and matching WebKit installation instructions in specs/004-signed-in-workflow/validation.md. Create src/agent/workspace/__init__.py without eagerly importing optional SDKs. (FR-013, FR-015, SC-006)
- [X] T002 [P] Write rejection/allowlist tests in tests/test_publication.py before allowing exactly src/agent/workspace/static/index.html, app.js and style.css in scripts/publish_policy.py; keep browser traces, storage state, screenshots and private session files excluded in .gitignore and distribution checks. (FR-011, FR-013, FR-015, SC-003, SC-006)

## Phase 2: Foundation

Complete shared data and request boundaries before the user stories; all security tests must fail before the corresponding change.

- [X] T003 [P] Write tests/test_workspace_models.py for strict schemas, nullable JobView fields, enum/size limits, secret exclusion and bounded event aggregation. Test the explicit entity fields and public projections in data-model.md. C01: "New JSON request/response models use schema_version exactly 1, reject unknown fields, use UUIDs for submission/job/request/run/retry identifiers, and UTC timestamps for exposed times. Server-generated IDs never derive from identity, task text or credentials." C05: "A job has kind task or approval_retry and state accepted, running, waiting_for_approval, cleaning_up, completed, denied, failed or interrupted. Only the last four states are terminal. Exactly one global job may own admission/execution/cleanup. Task length is 1–8000 characters; result summary is at most 32000 characters with an explicit truncated flag; each session retains at most twenty jobs and twenty distinct submission keys, including retry aliases; duplicate lookup precedes capacity checks and new alias keys at capacity are rejected; it rejects new jobs at capacity rather than evicting idempotency records." C12: "Public job projections expose only job/request/run/parent IDs, kind, state, UTC times, bounded result, approval status, safe action summary, cleanup status, retry eligibility and a closed error code/stage/next-action mapping. Tokens, cookies, state, nonce, raw provider responses, native transaction/lease IDs and identity claims never appear in job projections or telemetry." C14: "The memory sink retains at most 1000 safe lifecycle events per job and aggregates cleanup, approval and effect facts without retaining raw source bindings. Input HTTP bodies are limited to 64 KiB before JSON/form parsing. All sensitive responses use Cache-Control: no-store; callback/access logs and HTTP traces must omit query codes, cookies and authorization headers." (FR-006, FR-007, FR-008, FR-011, FR-015, SC-003)
- [X] T004 Implement src/agent/workspace/models.py with all entity/projection fields from data-model.md and the closed WorkflowError catalog from contracts/runtime.md; enforce C01/C05/C12/C14 and profile pattern ^[a-z][a-z0-9-]{1,63}$, default parent. Do not serialize private records generically. (FR-006, FR-007, FR-008, FR-011, SC-003)
- [X] T005 [P] Write tests/test_workspace_security.py for exact Host/port, foreign/missing/null Origin, duplicate cookies, CSRF binding, body limits, callback exception, no CORS, CSP/no-store/referrer headers and credential/query log canaries. C11: "All workspace requests require the exact configured Host including port; mutation requests require exact Origin and a browser/session-bound CSRF token. Authenticated mutations accept application/json only, including login. The GET login callback is the sole cross-site exception and requires its browser-bound single-use transaction." (FR-002, FR-011, FR-015, SC-003)
- [X] T006 Implement src/agent/workspace/security.py for C11/C14 and contracts/runtime.md cookie/header/log rules, including no proxy authority and no arbitrary redirect destination; distinguish bootstrap CSRF from authenticated session CSRF. (FR-002, FR-011, SC-003)

## Phase 3: US1 — Sign in and stay ready (P1)

Independently verify sign-in, renewal and sign-out against controlled identity responses with no model/database/phone calls. This is the first usable milestone.

- [X] T007 [P] [US1] Write tests/test_workspace_auth.py for code/S256/state/nonce, single-use/expired/duplicate callback inputs, endpoint trust, initial ID and access validation, at_hash/azp/audience rules, refresh rotation/omission, identity change, scope narrowing, ambiguous refresh and lifetime boundaries. Assert no credentials reach output. C02: "Opaque browser/session/CSRF/state/nonce values each contain at least 256 random bits; PKCE uses S256 and a 43–128-character verifier. Login attempts expire after 300 seconds, are single-use, and are capped at one per browser and sixteen globally; anonymous bootstraps share that cap and 300-second lifetime. Callback code/state/error parameters must be unique; reject duplicates, oversized values over 8192 characters and mixed code/error responses before exchange." C04: "Access, refresh and ID tokens are SecretStr fields excluded from repr and all public projections; token strings are nonempty and at most 65536 characters, and new login/refresh responses are limited to 256 KiB before parsing. ID tokens require RS256 or ES256 signatures, exact issuer, nonempty subject, exp/iat, one audience equal to LOGIN_CLIENT_ID, matching azp when present and the initial nonce. Access tokens retain the configured audience/type verifier and must match ID issuer/subject. Refresh is attempted at most once per admission under a session lock; remaining access lifetime must be at least TIMEOUT_SECONDS + 45 seconds." (FR-002, FR-003, FR-004, FR-015, SC-001, SC-003)
- [X] T008 [P] [US1] Write tests/test_workspace_sessions.py for bounded bootstrap/session state, cookie rotation, idle/absolute expiry, non-extending polling, capacity rejection, restart invalidation and sign-out admission revocation while cleanup retains its snapshot. C03: "At most four authenticated sessions exist; each expires after 1800 seconds without a successful user mutation or 28800 seconds absolutely. Polling does not extend idle expiry. Session states are active, reauth_required, closing and closed. Rotate the opaque cookie at login; sign-out/expiry immediately refuse work and retain run credentials only through cleanup." (FR-003, FR-005, FR-007, FR-015, SC-001, SC-003)
- [X] T009 [P] [US1] Extend tests/test_settings.py and create tests/test_workspace_app.py startup cases covering required login fields, existing actor/API credential separation, alias/env precedence, invalid scopes/port/runtime budgets, occupied port and actionable missing-extra errors before network work. C10: "LOGIN_CLIENT_ID and LOGIN_CLIENT_SECRET are required only by workspace; LOGIN_SCOPES defaults to openid and is a whitespace-delimited unique list of at most 32 scope tokens, each 1–128 characters with no control characters. Short names precede POCDANTIC_LOGIN_* aliases. --port defaults to 8000 and accepts integers 1024–65535; host is always 127.0.0.1." (FR-001, FR-013, FR-015, SC-001, SC-006)
- [X] T010 [US1] Extend src/agent/settings.py with C10 login settings and src/agent/oauth.py with secret optional refresh/ID token fields and refresh grant; preserve existing callers and token audience/type checks. Validate HTTPS authorization endpoints under the existing trust rules and bound token response sizes. (FR-002, FR-003, FR-013, SC-001, SC-003)
- [X] T011 [US1] Implement src/agent/workspace/auth.py for C02/C04 code and ID validation plus locked admission renewal. Require access/ID identity agreement, exact login audience, nonce and at_hash when present; treat expires_in only as a shortening access bound. No code/refresh automatic retry or mid-run credential replacement. (FR-002, FR-003, FR-004, SC-001, SC-003)
- [X] T012 [US1] Implement src/agent/workspace/sessions.py for C02/C03 lifecycle, bootstrap/session CSRF and bounded state; expose a shutdown/sign-out drain hook, discard replaced refresh tokens, invalidate bootstrap after login and keep polling from extending idle lifetime and prune closed-session/job/approval state after drain. (FR-002, FR-003, FR-005, FR-007, SC-001, SC-003)
- [X] T013 [US1] Implement src/agent/workspace/app.py authentication routes and lifespan, src/agent/cli.py workspace command, and static/index.html, app.js, style.css sign-in shell. Serve package resources, return LoginStart authorization_url for navigation, use safe error mapping and print the exact callback; preserve agent serve. (FR-001, FR-002, FR-003, FR-005, FR-008, FR-013, FR-014, SC-001, SC-006)
- [X] T014 [US1] Create tests/browser/conftest.py and tests/browser/test_workspace.py controlled HTTPS identity routing and signed-token fixtures; verify keyboard sign-in, nonce/state rejection, renewal, sign-out and missing configuration in WebKit. Deny unmocked external network; no production fake-auth switch or live browser-state persistence. (FR-001, FR-002, FR-003, FR-014, FR-015, SC-001, SC-003, SC-006)

## Phase 4: US2 — Run a task and inspect its result (P1)

Independently run a deterministic task; reload sees the same result and another session cannot inspect it.

- [X] T015 [P] [US2] Write tests/test_workspace_runs.py for global admission, renewal/admission races, duplicate payload conflicts, capacity and foreign/unknown run equivalence. Test trusted runtime ID reservation before effects and no browser-selected runtime authority. C06: "A submission key is a browser-generated UUID scoped to one session. The same key and canonical payload return the same job; changed payload returns conflict. Job access requires its owning session; unknown and foreign UUIDs both return not-found. Runtime IDs are generated by trusted code, reserved before effects and cannot be selected by a browser." (FR-004, FR-006, FR-007, FR-015, SC-002, SC-003)
- [X] T016 [P] [US2] Extend tests/test_adapters.py, tests/test_broker.py and tests/test_validation_scenarios.py with timeout, cancellation during read/revocation, repeated cancellation, expired admission token and stubborn cleanup; assert credentials/gate retained through drain and uncertainty never reports success. C09: "Cleanup status is not_acquired, pending, revoked, failed or unknown. Runtime budget is TIMEOUT_SECONDS in 1–180 seconds for the workspace; cleanup allows 30 seconds plus five seconds to drain cancellation. Unresolved cleanup holds the global gate and quarantines admission. Completed requires successful execution and all acquired leases revoked; cleanup failure or uncertainty cannot report completed or expose retry." (FR-004, FR-005, FR-007, FR-015, SC-002, SC-003)
- [X] T017 [US2] Add trusted fresh RunContext reservation to src/agent/runtime.py with pre-start containment and default-call compatibility; harden src/agent/vault.py cleanup failure normalization and cancelled-child drain per C09. Connect unresolved cleanup to process admission quarantine without losing the private cleanup context. (FR-004, FR-005, FR-007, SC-002, SC-003)
- [X] T018 [US2] Implement src/agent/workspace/runs.py global job manager, immutable per-run token snapshot, session ownership, twenty-key idempotency registry (including retry aliases), bounded memory sink, shared Runtime containment and trusted terminal mapping under C05/C06/C09/C14. Expiry/sign-out contains before cancelling, holds the slot through cleanup and exposes the run-termination invalidation hook completed by T024. (FR-004, FR-005, FR-006, FR-007, FR-008, SC-002, SC-003)
- [X] T019 [US2] Extend src/agent/workspace/app.py run/list/status routes and tests/test_workspace_app.py for all HTTP outcomes, server profile allowlist, no cookie fallback in existing bearer /runs, closed errors and no network retry on status reads; keep src/agent/api.py contract unchanged. (FR-006, FR-007, FR-008, FR-011, FR-013, SC-002, SC-003, SC-006)
- [X] T020 [US2] Implement task/profile form, status, prior-run list and inert bounded result in src/agent/workspace/static/index.html, app.js and style.css. Preserve submission UUID on uncertain delivery, disable busy actions, implement keyboard focus/error/status behavior and no durable browser state. C13: "Browser polling runs at most once per second per page and performs no effects. Status updates must become visible within two seconds under controlled local tests. Browser storage contains no tokens, cookies copied by script, task text or result history; only in-memory page state and HttpOnly opaque cookies are used. All untrusted content is rendered as inert text." (FR-001, FR-006, FR-007, FR-008, FR-014, SC-002, SC-006)
- [X] T021 [US2] Extend tests/browser/test_workspace.py for task submission, double-click, lost response/retry, page reload, session ownership, sign-out during execution, stage errors and inert malicious markup; assert two-second status bound and keyboard-only operation. (FR-005, FR-006, FR-007, FR-008, FR-011, FR-014, FR-015, SC-002, SC-003, SC-006)

## Phase 5: US3 — Understand and retry approval failures (P2)

Independently drive controlled native decisions and prove that one eligible retry sends one fresh prompt without replaying a model or prior tools.

- [X] T022 [P] [US3] Extend tests/test_verify.py and tests/test_security.py for every exact native alias, bool compatibility, deadline/expiry, cancellation, unknown/binding-invalid states, persistence failures and late decision/consumption/invalidation races. False alone cannot establish explicit denial. C07: "Approval decisions are approved, denied or unconfirmed. Only DENIED, VERIFY_DENIED and USER_DENIED establish native denial; existing exact success aliases remain approved. Expiry, timeout, cancellation, failure and unrecognized/malformed results cannot authorize effects. Approval states are pending, approved, denied, consumed, expired, cancelled, unconfirmed and superseded; decision, invalidation and consumption are atomic, expiry-checked and terminal." (FR-004, FR-009, FR-010, FR-015, SC-003, SC-004)
- [X] T023 [P] [US3] Write tests/test_workspace_retry.py for immutable nested parameters, issuer/subject continuity, revoked scope/profile, candidate cardinality, effect/cleanup facts, duplicate/concurrent retry keys, late old approval and post-write model failure. Assert model and earlier tool counts never increase during retry. C08: "A retry candidate contains canonical immutable action bytes, original issuer/subject, profile, parent job and original approval reference. Only one unconfirmed candidate with zero simulated writes, no uncertain other effects and completed cleanup is eligible. Retry atomically consumes that candidate, creates fresh job/request/run/approval IDs, rechecks identity/profile/ policy and invokes no model. Approved, denied, interrupted, binding-invalid and cleanup-failed jobs are ineligible; an old decision never authorizes a new attempt." (FR-004, FR-009, FR-010, FR-015, SC-003, SC-004)
- [X] T024 [US3] Implement typed outcomes and expiry-checked atomic terminal invalidation in src/agent/approval.py, src/agent/verify.py and src/agent/services.py under C07; retain explicit compatibility adapters for existing bool callers. Extend tests/test_validation_scenarios.py and shared source/report mappings only as needed to preserve genuine-vs-unconfirmed evidence without upgrading old acceptance. (FR-004, FR-009, FR-010, FR-013, SC-003, SC-004)
- [X] T025 [US3] Extract the trusted approval/execution helper in src/agent/capabilities.py and add the internal exact-action path in src/agent/runtime.py. Both tool and retry use current authorization, reserved run context, new approval, canonical action and explicit trusted simulated-effect facts; integrate lifecycle/status with src/agent/observability.py without raw payloads. (FR-004, FR-009, FR-010, SC-003, SC-004)
- [X] T026 [US3] Implement atomic candidate reservation and fresh action execution in src/agent/workspace/runs.py, retry route in app.py and waiting/denied/unconfirmed/eligible-Retry UI in static/app.js and index.html. Preserve same-key/consumed-candidate deduplication, terminal cleanup, and no browser decision setter. (FR-009, FR-010, FR-014, SC-004, SC-006)
- [X] T027 [US3] Extend tests/browser/test_workspace.py for all approval states, explicit retry, duplicate retry, stale success, disabled denied/success/interrupted retries, no-second-model assertion and keyboard flow. Verify app errors are described only as unconfirmed when the server lacks a decision. (FR-008, FR-009, FR-010, FR-014, FR-015, SC-003, SC-004, SC-006)

## Phase 6: US4 — Complete the database read workflow (P2)

Independently prove sign-in → permitted read → result → exact cleanup with deterministic signed identity and broker fixtures.

- [X] T028 [US4] Extend tests/test_broker.py and tests/test_workspace_runs.py for workspace token snapshots, delegated read, multiple sequential leases, cleanup uncertainty, missing permission/integration and model output that falsely claims success. Derive stage/cleanup from trusted facts, never summary text. (FR-004, FR-008, FR-012, FR-015, SC-002, SC-003, SC-005)
- [X] T029 [US4] Connect DatabaseBroker and safe lifecycle/error mapping in src/agent/workspace/runs.py, src/agent/broker.py and src/agent/observability.py; retain exact existing lease delegation/revocation and show cleanup pending/revoked/failed/unknown correctly. Add the example read task and safe correlation view in static/app.js/index.html. (FR-004, FR-008, FR-012, SC-002, SC-005)
- [X] T030 [US4] Extend tests/browser/test_workspace.py with ten complete deterministic signed-in database reads, exact lease accounting and runtime/status budgets; cover renewal, permission denial and cancellation during cleanup. Keep synthetic fixtures labeled and all external network poisoned. (FR-012, FR-014, FR-015, SC-002, SC-003, SC-005, SC-006)

## Phase 7: Polish and software validation

Complete all software work and checks regardless of unavailable live vendor proof.

- [X] T031 [P] Update README.md concisely plus docs/usage.md, docs/configuration.md, .env.example and docs/adr/0006-signed-in-workflow.md with startup, exact callback, three short login settings, local-only security, session/history limits, lifetime/retry/cleanup behavior and concrete troubleshooting. Record threat/boundary review in specs/004-signed-in-workflow/validation.md. (FR-001, FR-008, FR-011, FR-013, FR-016, SC-001, SC-005, SC-006)
- [X] T032 Update .github/workflows/ci.yml for required WebKit tests and locked browser group; verify src/agent/workspace/static assets in built distributions using tests/test_publication.py and scripts/check_distribution.py. Exercise isolated base/server wheel installs outside checkout, with optional SDKs absent in the base case; require browser CI to fail rather than skip missing tooling. (FR-013, FR-015, SC-003, SC-006)
- [X] T033 Run all CONTRIBUTING.md gates and deterministic specs/004-signed-in-workflow/quickstart.md checks; record commands/results, full regression and threat review in specs/004-signed-in-workflow/validation.md. Verify exact staged publication contents and no acceptance promotion. Mark only software tasks actually completed. (FR-015, FR-016, SC-002, SC-003, SC-004, SC-005, SC-006)

## Phase 8: US4 — Separate live observation

This task is independently incomplete if external prerequisites are unavailable; it does not prevent software completion or authorized PR preparation.

- [X] T034 [US4] Attempt the configured live sign-in/renewal/database walkthrough from specs/004-signed-in-workflow/quickstart.md and record sanitized stage/owner/results in validation.md. Inspect actual read/cleanup evidence, keep raw material private, and leave this task open if unavailable. Do not send phone prompts without an individual operator action, close 003 evidence gaps automatically, or modify acceptance.json dispositions. (FR-012, FR-016, SC-001, SC-005)

## Phase 9: Later authorized delivery

Planning and implementation do not imply a request to publish or merge. Existing PR #4 exception has expired.

- [ ] T035 When delivery is later requested, prepare the reviewed PR using .github/pull_request_template.md, verify current CI/protection/review and publication contents, and record proof or a new explicit scoped owner exception in specs/004-signed-in-workflow/validation.md. Preserve live limitations; do not silently change protection or reuse the previous exception. (FR-016, SC-006)

## Dependencies and execution order

- Setup T001–T002 precedes foundation. Foundation test pairs T003→T004 and T005→T006 may be
  developed independently, but both complete before US1. [P] marks independent files within a
  phase, never authorization to run multiple agents or to skip unfinished prerequisites.
- US1: T007/T008/T009 are independent test work; T010→T011→T012→T013→T014 follow. Session drain
  hooks are tested with controlled cleanup first and integrated with real runtime cleanup in US2.
- US2 follows US1. T015/T016 tests can run independently; T017→T018→T019→T020→T021 integrate.
  US2 independent acceptance uses read-only deterministic fixtures. Privileged workspace
  behavior is verified only after US3; no partial implementation receives live phone testing.
- US3 follows US2: T022/T023 tests are independent; T024→T025→T026→T027 follow. Shared runtime,
  approval, observer and static files must be edited sequentially.
- US4 software T028→T029→T030 follows US3. T031 documentation can proceed alongside T032 after
  story contracts stabilize; T033 requires both and all software stories.
- Live T034 follows software verification T033. Record its blocker and continue authorized
  software delivery if external prerequisites are unavailable; never check it off as passed.
- T035 needs a later delivery request and concrete checks/review or a newly authorized exception;
  it is not authorized or performed by the planning request.

Dependency graph: Setup → Foundation → US1 → US2 → US3 → US4 software → Software gates.
Software gates → optional available live observation; Software gates → later authorized delivery.
Live proof status accompanies delivery but does not redefine software verification.

## Parallel examples and independent checks

| Story | Parallel opportunity after prerequisites | Independent verification |
|---|---|---|
| US1 | T007 auth tests, T008 session tests, T009 settings tests | Sign in/renew/sign out without model or tools |
| US2 | T015 job tests and T016 cleanup tests | Submit once, reload same result, deny foreign-session read |
| US3 | T022 native-state tests and T023 exact-action retry tests | One fresh decision, no model replay, stale success has zero effects |
| US4 | No same-file implementation parallelism; T031 docs may follow stable contracts | Ten signed-in reads with exact cleanup; separate live observation |

## Implementation strategy

MVP is US1 sign-in/session lifecycle. Add task execution, then typed approval retry, then the full
read walkthrough. Stop to verify each independent story. Keep all software validation deterministic;
report T034/T035 separately if live prerequisites or delivery authorization are absent. $speckit-implement executed the software tasks. A later delivery
request is handled separately. The implementation command is `$speckit-implement`. Planning originally made no source changes; implementation is recorded in validation.md.

## Requirement coverage

| Requirement | Tasks |
|---|---|
| FR-001 | T009, T013, T014, T020, T031 |
| FR-002 | T005, T006, T007, T010, T011, T012, T013, T014 |
| FR-003 | T007, T008, T010, T011, T012, T013, T014 |
| FR-004 | T007, T011, T015, T016, T017, T018, T022, T023, T024, T025, T028, T029 |
| FR-005 | T008, T012, T013, T016, T017, T018, T021 |
| FR-006 | T003, T004, T015, T018, T019, T020, T021 |
| FR-007 | T003, T004, T008, T012, T015, T016, T017, T018, T019, T020, T021 |
| FR-008 | T003, T004, T013, T018, T019, T020, T021, T027, T028, T029, T031 |
| FR-009 | T022, T023, T024, T025, T026, T027 |
| FR-010 | T022, T023, T024, T025, T026, T027 |
| FR-011 | T002, T003, T004, T005, T006, T019, T021, T031 |
| FR-012 | T028, T029, T030, T034 |
| FR-013 | T001, T002, T009, T010, T013, T019, T024, T031, T032 |
| FR-014 | T013, T014, T020, T021, T026, T027, T030 |
| FR-015 | T001, T002, T003, T005, T007, T008, T009, T014, T015, T016, T021, T022, T023, T027, T028, T030, T032, T033 |
| FR-016 | T031, T033, T034, T035 |
| SC-001 | T007, T008, T009, T010, T011, T012, T013, T014, T031, T034 |
| SC-002 | T015, T016, T017, T018, T019, T020, T021, T028, T029, T030, T033 |
| SC-003 | T002, T003, T004, T005, T006, T007, T008, T010, T011, T012, T014, T015, T016, T017, T018, T019, T021, T022, T023, T024, T025, T027, T028, T030, T032, T033 |
| SC-004 | T022, T023, T024, T025, T026, T027, T033 |
| SC-005 | T028, T029, T030, T031, T033, T034 |
| SC-006 | T001, T002, T009, T013, T014, T019, T020, T021, T026, T027, T030, T031, T032, T033, T035 |
