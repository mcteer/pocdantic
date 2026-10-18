# Tasks: Model Gateway and Credential Guardrails

**Input**: [Specification](spec.md), [plan](plan.md), [research](research.md),
[data model](data-model.md), [runtime](contracts/runtime.md) and
[administration](contracts/administration.md) contracts.
**Status**: T001–T048 completed within the operator-approved scope. Live control review,
signed-in read and analysis pass; spending and internal retention remain operator-owned
and unverified. See [validation](validation.md) for separate external limitations.
**Tests**: Required by FR-017 and the constitution; write meaningful failing regressions before
behavior changes. No live providers, phone prompts or remote mutations in ordinary tests.

## Phase 1: Setup

- [X] T001 Record the reviewed model-use boundary, Google GLA/Vertex migration, remote processing/retention limits and no-fallback design in `docs/adr/` (next available ADR number) and its `docs/adr/README.md` index; preserve unrelated staged work. (FR-016, FR-018)
- [X] T002 Review HTTPX2 BSD-3-Clause/compatibility and declare already-transitive `httpx2>=2.13.1,<3` in `pyproject.toml`; update `uv.lock` metadata without unrelated upgrades or a Gateway extra, retaining Pydantic AI Slim 2.55.0 and optional providers. (FR-018)

## Phase 2: Foundational boundaries

All story implementation depends on T003–T006. These models/readers provide local contracts,
not remote acceptance. Synthetic test fixtures can supply reviews without a production bypass.

- [X] T003 Add configuration and private-review boundary regressions in `tests/test_gateway_configuration.py` and `tests/test_gateway_review.py`: missing mode, aliases, exact allowlist, unsafe paths/ownership, size, clock, expiry, rejection with missing/stale evidence or configuration, drift and key rotation. (FR-002, FR-003, FR-015, FR-017)
- [X] T004 Implement strict frozen route/config models in `src/agent/gateway/models.py`, `src/agent/gateway/config.py` and `src/agent/settings.py`: mode `gateway`/`direct` with absent blocking live admission; region `us`/`eu`; route “1–64 characters matching `[a-z0-9][a-z0-9_-]*`”; protocol `google-cloud`/`openai-chat`/`openai-responses`/`anthropic`; model “1–128 characters matching `[A-Za-z0-9][A-Za-z0-9._/-]*`”; allowlist “1–16 unique protocol-qualified exact models; selected model must be a member”; policy digest “64 lowercase hexadecimal characters”; generated opaque UUID route/model registry references. GatewayCredential is “SecretStr, nonempty, repr=False”, rejects surrounding whitespace/control bytes, uses only its two explicit aliases with environment precedence and conflict rejection. (FR-001–FR-003, FR-008)
- [X] T005 Implement private control-review schema and read-only admission in `src/agent/gateway/models.py` and `src/agent/gateway/review.py`: schema_version `1`, UUID review_id; four digests each “64 lowercase hexadecimal characters”; reviewer “1–128 characters”; “observed_at ≤ reviewed_at < expires_at ≤ observed_at + 24 hours” in aware UTC with future times rejected; decision `approved`/`rejected`, all four control dispositions pass for approval; “1–1024 unique private local artifact basenames, no absolute paths or traversal”; control_revision digest; `.local/gateway/` directory `0700`, files `0600`, no symlinks/hard links, atomic reads/writes and “maximum review-file size of 64 KiB”. Bind key digest privately, never publicly. Implement immutable review records and atomic locked `current.json` UUID pointer (schema_version `1`, “maximum 4 KiB”), with revision recheck/conflict refusal and final-dispatch freshness. (FR-011, FR-015, FR-016)
- [X] T006 Define the closed errors/outcomes and documented package interfaces in `src/agent/gateway/__init__.py` and `src/agent/gateway/models.py`; add exhaustive schema/unknown-code tests to `tests/test_gateway_configuration.py`. All boundary models reject extra fields; no exception body or freeform diagnostic field. (FR-007, FR-012, FR-017)

## Phase 3: US1 — Controlled routing (Priority P1)

**Goal**: All supported model entry points use the admitted route.
**Independent test**: Mock native transports capture all four protocols, CLI/API/workspace,
children and later turns; Gateway mode has zero direct dispatch and offline has zero live traffic.

- [X] T007 [P] [US1] Add poisoned-environment/native-wire tests in `tests/test_gateway_transport.py` for exact HTTPS origin/path, auth replacement, custom headers, provider keys, cookies/baggage, proxy/TLS variables, redirects and one-send admission. (FR-001, FR-002, FR-004, FR-017; SC-001)
- [X] T008 [P] [US1] Add construction/migration/optional-package tests in `tests/test_model_configuration.py`, `tests/test_runtime.py`, `tests/test_api.py` and `tests/test_offline_entrypoints.py`, covering explicit direct mode, missing mode, arbitrary injected live models and synthetic isolation. (FR-001–FR-003, FR-016; SC-001)
- [X] T009 [US1] Implement owned hardened `httpx2.AsyncClient` and final send guard in `src/agent/gateway/transport.py`: explicit verified TLS, `trust_env=False`, no redirects, exact native paths, closed headers, exact Gateway bearer, deadline and at most one actual model send per attempt. (FR-001, FR-002, FR-004, FR-007)
- [X] T010 [US1] Implement explicit native Gateway construction and public SDK retry disabling in `src/agent/model_config.py`; retain OpenAI Chat/Responses distinction and explicit Google cloud route, prohibit GLA conversion and environment inference; preserve legacy custom providers only in direct mode and lazy extra imports. (FR-001–FR-003, FR-008, FR-018)
- [X] T011 [US1] Centralize admitted model ownership and per-turn review/containment in `src/agent/runtime.py`, `src/agent/gateway/capability.py`, `src/agent/capabilities.py`, `src/agent/cli.py`, `src/agent/api.py` and `src/agent/workspace/app.py`; scope attempt state to trusted run context, cover child/later turns and await closure on all host shutdown/cancellation paths. (FR-001, FR-002, FR-007, FR-015, FR-016)
- [X] T012 [US1] Add early Gateway mode/credential/extra checks and fresh-template defaults in `src/agent/setup/commands.py`, `src/agent/setup/prerequisites.py` and `src/agent/setup/models.py`; preserve existing file bytes, require explicit migration selection, and reject fresh direct-mode preparation before enrollment. Extend `tests/test_setup_commands.py` and `tests/test_setup_recipes.py`. (FR-003, FR-013, FR-018; SC-005)
- [X] T013 [US1] Validate cross-entry-point routing, hidden SDK retries, concurrent parent/child isolation and client closure in `tests/test_gateway_transport.py`, `tests/test_runtime.py`, `tests/test_api.py` and `tests/test_workspace_app.py`; record observed software results in `specs/014-gateway-guardrails/validation.md`. (FR-001–FR-003, FR-016, FR-017; SC-001)

## Phase 4: US2 — Credential blocking (Priority P1)

**Goal**: Covered credential material is refused without exposing it or replaying effects.
**Independent test**: Synthetic canary/benign matrix across every supported text surface and
protocol, with post-tool denial/cancellation, error-body and secret-isolation capture assertions.

- [X] T014 [P] [US2] Add runtime-generated invalid canaries and benign controls in `tests/test_gateway_controls.py` for every mandatory class × five surfaces × four supported protocols from `data-model.md`; do not commit complete credential-like strings or invoke live models. (FR-004–FR-006, FR-017; SC-002)
- [X] T015 [P] [US2] Add secret-bearing exception/header/body and unsupported media/native-tool regressions in `tests/test_gateway_privacy.py`; capture prompts, CLI/browser errors, logs and exported telemetry, including adapter credential canaries. (FR-004, FR-005, FR-011, FR-012; SC-002, SC-004)
- [X] T016 [US2] Implement text-surface admission and early safe error normalization in `src/agent/gateway/transport.py` and `src/agent/gateway/capability.py`; parse at most 16 KiB of error input, recognize only reviewed exact signatures and retain generic/unknown outcomes otherwise. Never infer guardrail cause from HTTP status or stringify native errors. (FR-005–FR-007, FR-012)
- [X] T017 [US2] Preserve terminal-denial, cancellation, unknown-dispatch and exact-cleanup semantics in `src/agent/runtime.py` and `src/agent/gateway/capability.py`; extend `tests/test_runtime.py`, `tests/test_workspace_runs.py` and `tests/test_sandbox_runtime.py` for post-read refusal, pending/failed cleanup and zero replay/ModelRetry/fallback. (FR-007, FR-016, FR-017; SC-003)
- [X] T018 [US2] Extend closed Gateway errors in `src/agent/workspace/models.py`, `src/agent/workspace/runs.py` and `src/agent/cli.py`; add `tests/browser/test_workspace_gateway.py` WebKit refusal cases and CLI capture tests in `tests/test_gateway_privacy.py`. No payloads, arbitrary headers or automatic retry controls. (FR-007, FR-012; SC-002, SC-003)
- [X] T019 [US2] Publish credential inventory, per-surface blocking verification, false-positive handling and explicit unknown/encoded-secret limits in `docs/configuration.md` and `docs/usage.md`, based on `specs/014-gateway-guardrails/contracts/administration.md`; distinguish synthetic protection tests from live vendor proof. (FR-004–FR-006, FR-014, FR-018)

## Phase 5: US3 — Model and spend controls (Priority P1)

**Goal**: Permitted model selection and remote spending refusals are enforced without evasion.
**Independent test**: Local disallowed selections cause zero sends; mocked remote spend/access/
pricing refusals and concurrent/uncertain requests cause no retries, key switches or false zero costs.

- [X] T020 [US3] Extend `tests/test_gateway_controls.py` with model allowlist, budget/auth/access/rate-limit/unknown signatures, unpriced requests, concurrent boundary crossing, output-validation turns and no-route/key substitution cases. (FR-007–FR-009, FR-017; SC-003)
- [X] T021 [US3] Enforce exact allowlist and per-turn existing request/token/delegation/time bounds in `src/agent/gateway/capability.py` and `src/agent/model_config.py`; close all supplied-model and later-turn admission paths without altering tool authority. (FR-002, FR-008, FR-016)
- [X] T022 [US3] Validate private spend-control evidence in `src/agent/gateway/models.py` and `src/agent/gateway/review.py`: finite daily/monthly per-key whole-USD limits, zero deny-all, blank unlimited rejected, pricing-required=true and blocking=true; review key/project scopes, reset/accounting evidence and optional limits, never local billing authority. (FR-008, FR-009, FR-015)
- [X] T023 [US3] Implement exact reviewed budget/access/pricing classification and unknown cost propagation in `src/agent/gateway/transport.py`; test malformed/shared-status responses and terminal behavior in `tests/test_gateway_controls.py`. No fabricated cost or inferred exact budget exhaustion. (FR-007, FR-009, FR-012; SC-003)
- [X] T024 [US3] Document included spending caps, soft-limit/concurrency overshoot, Require pricing data, BYOK billing, model allowlists and optional advanced-policy distinctions in `docs/configuration.md` and `docs/setup.md`; no plan purchase, auto-recharge or amount is implicitly authorized. (FR-008, FR-009, FR-014, FR-018)

## Phase 6: US4 — Content-free visibility (Priority P2)

**Goal**: Every attempt is observable without conversation/credential retention.
**Independent test**: Metadata capture includes success/denial/failure/unknown and correct run
correlation, with no private canaries; exporter/storage failure and missing prices remain truthful.

- [X] T025 [US4] Add attempt/telemetry/concurrency/storage-failure tests in `tests/test_gateway_privacy.py` and `tests/test_telemetry.py`, including remote trace capture unavailable, opaque model references and unknown-versus-zero cost. (FR-010–FR-012, FR-017; SC-004)
- [X] T026 [US4] Implement ModelAttempt schema and bounded private observation in `src/agent/gateway/models.py`, `src/agent/gateway/review.py`, `src/agent/observability.py` and `src/agent/validation/models.py`: generated UUID correlations, parent UUID/null, positive run sequence, opaque route/model refs, closed protocol/mode/stage/reason values; duration/tokens “nonnegative integers or null when unobserved”; cost “nonnegative decimal string or null”, known requires observed value/source and unknown requires null/unavailable; telemetry `ok`/`degraded`. Enforce one terminal event, pre-send start persistence and crash-derived unknown without replay. (FR-010, FR-012, FR-015)
- [X] T027 [US4] Wire per-attempt lifecycle into `src/agent/gateway/capability.py` and metadata-only export into `src/agent/telemetry.py`; preserve include_content/binary/parameter exclusions, retain closed Pydantic agent semantics and environment labels, pass the exporter into every host,
flush after runtime drain, sanitize native correlation privately, fail closed on start-record failure and preserve cleanup on exporter failure. (FR-007, FR-010–FR-012, FR-016; SC-004)
- [X] T028 [US4] Add protected-review/legacy-direct status and bounded actionable outcomes to `src/agent/workspace/models.py`, `src/agent/workspace/app.py` and `src/agent/workspace/static/app.js`, with `tests/browser/test_workspace_gateway.py`; expose no route/key/reviewer values or browser configuration authority. (FR-003, FR-010, FR-012, FR-013)
- [X] T029 [US4] Add 1,000-attempt local-admission p95 ≤25 ms verification with warmup and synthetic transports in `tests/test_gateway_controls.py`, record timing environment/results in `specs/014-gateway-guardrails/validation.md`, and document safe visibility/unknown cost in `docs/usage.md`. (FR-010, FR-017, FR-018; SC-004)

## Phase 7: US5 — Setup, review and migration (Priority P2)

**Goal**: Prepare/migrate without silent state changes and distinguish local software from live proof.
**Independent test**: Root/config/review matrix gives exact owner/action/exit; fixed probes cannot
carry arbitrary content or tools; existing enrollment/holds survive and stale reviews block work.

- [X] T030 [P] [US5] Extend `tests/test_gateway_review.py` for complete four-control evidence, expiry during a run, invalidation/rejection races and exact configuration binding; add `tests/test_gateway_probes.py` for fixed-case-only dispatch, no prompt/file/tool injection, no automatic approval/retry and sanitized output. (FR-013–FR-017; SC-005, SC-006)
- [X] T031 [P] [US5] Add setup/migration/root/private-state preservation matrices in `tests/test_setup_guidance.py`, `tests/test_setup_readiness.py`, `tests/test_setup_walkthrough.py` and `tests/test_portable_recovery.py`; include existing explicit direct mode, new Gateway setup, missing mode, fresh direct-mode rejection before enrollment, GLA migration and unsupported beta behavior. (FR-003, FR-013, FR-015, FR-016; SC-005)
- [X] T032 [US5] Implement fixed synthetic coverage-case registry and bounded no-tool probes in `src/agent/gateway/probes.py`, using the same transport with a dedicated synthetic-only context; persist case IDs/outcomes/private native joins without payloads and reject arbitrary case/body/config overrides. (FR-005, FR-006, FR-014, FR-017; SC-002, SC-006)
- [X] T033 [US5] Implement `status`, `probe` and explicit `review` CLI contracts in `src/agent/gateway/commands.py`, `src/agent/gateway/review.py` and `src/agent/cli.py`; `valid-hours` is >0 and ≤24; evidence paths stay below canonical `.local/gateway/`; preserve exit 0/2/3 distinctions and never infer remote administration authority. Validate `bundle.json` schema_version `1`, source `live`/`synthetic` with synthetic unable to approve, four closed control dispositions and complete coverage; manifest “1–1024 unique local basenames and matching SHA-256 digests”, each source “at most 8 MiB”, total “at most 32 MiB”, bundle “at most 1 MiB”, aware UTC observations and exact input bindings. (FR-013–FR-015; SC-005, SC-006)
- [X] T034 [US5] Extend `src/agent/setup/models.py`, `src/agent/setup/readiness.py`, `src/agent/setup/guidance.py` and `src/agent/setup/recipes.py` with names-only Gateway findings and administrator actions, preserving v1 JSON/exit meanings, existing “32 KiB guide limit”, all private state and non-billable `--network` behavior. (FR-013, FR-014, FR-016; SC-005)
- [X] T035 [US5] Bind Gateway policy/review identity to private validation context in `src/agent/validation/context.py` and `src/agent/validation/models.py`; extend `tests/test_setup_evidence.py` and `tests/test_portable_recovery.py` proving transport-only changes preserve recovery digests/enrollment while identity/database changes retain existing migration requirements. (FR-015–FR-017; SC-005, SC-006)
- [X] T036 [US5] Update `README.md`, `.env.example`, `docs/setup.md`, `docs/configuration.md`, `docs/usage.md`, `AGENTS.md` and `CONTRIBUTING.md` with complete extras, new-live Gateway requirements, explicit legacy direct migration, reviewed Google selection, admin/probe/review/rotation procedures and privacy/spend/drift limitations. (FR-003, FR-014, FR-018)
- [X] T037 [US5] Extend `scripts/check_onboarding.py` and `.github/workflows/ci.yml` locked wheel/sdist and onboarding matrices for Gateway native protocols, base optional isolation and explicit direct compatibility; verify exports/install commands preserve selected extras without introducing real service calls. (FR-003, FR-017, FR-018; SC-001, SC-005)
- [X] T038 [US5] Implement synthetic publication/privacy coverage for private Gateway artifacts in `tests/test_gateway_privacy.py`, using existing `scripts/publish_policy.py` and `scripts/check_privacy.py` boundaries; make only narrowly required private-artifact recognition changes if a test proves a gap, never expand the publication allowlist for private evidence. (FR-004, FR-011, FR-015, FR-017)

## Phase 8: Integration, validation and handoff

- [X] T039 Run complete applicable `.github/workflows/ci.yml` gates, including WebKit, security regression, repeatability/readiness, onboarding/locked artifacts and sandbox platform/container checks; record actual runs and blocked/unavailable platforms in `specs/014-gateway-guardrails/validation.md`. (FR-017; SC-001–SC-006)
- [X] T040 Review staged publication contents, run history/proposed-tree privacy checks, build and inspect distributions, and document final compatibility/migration/live limitations in `specs/014-gateway-guardrails/validation.md`; do not mark legacy `acceptance.json` criteria passed from Gateway tests. (FR-004, FR-011, FR-017, FR-018; SC-006)
- [X] T041 Under separately authorized operational scope, have the Gateway administrator perform `specs/014-gateway-guardrails/contracts/administration.md` setup and fixed live routing/blocking/spend/privacy probes; store source evidence privately, record reviewer/time/disposition and final-config bindings for GW-01 through GW-06 in `specs/014-gateway-guardrails/validation.md`. Leave unavailable items blocked. (FR-005, FR-006, FR-009, FR-011, FR-014, FR-015, FR-017; SC-002, SC-006)
- [X] T042 After explicit control review and existing sign-in/read authorization, execute both live workspace flows from `specs/014-gateway-guardrails/quickstart.md`, verify observed model/tool/cleanup stages and separate unknown costs; update `specs/014-gateway-guardrails/validation.md` and retain maintainer review as a pre-merge requirement. Execution completed under the approved operator-owned scope; external administration limitations remain explicit. (FR-001, FR-007, FR-010, FR-016–FR-018; SC-001–SC-006)

- [X] T043 Document the operator-authorized shared project API key for Gateway and telemetry; keep an explicit private dotenv binding, test it without implicit fallback, and correct the privacy scanner to inspect resolved whole-value local references while preserving earlier literal credentials. Add regression cases in `tests/test_gateway_configuration.py` and `tests/test_publication.py`; run focused publication/configuration, lint, distribution and proposed-tree/history privacy checks. (FR-002, FR-004, FR-011, FR-017, FR-018)

- [X] T044 Preserve every referenced setup repair action when a Gateway migration has both an unsupported model protocol and missing inputs; add a read-only regression in `tests/test_setup_guidance.py` and run focused setup checks. (FR-003, FR-013, FR-017)
- [X] T045 Correct native HTTP framing in `src/agent/gateway/transport.py`, deriving Host/Content-Length and fixed content headers from the validated origin/body; add a real HTTP/1.1 in-memory network regression. Bound fixed probes to 64 output tokens and 30 seconds with wire assertions across all four protocols. Run adapter/cleanup/replay regressions, applicable full gates and final artifacts. (FR-002, FR-004, FR-007, FR-017, FR-018)

- [X] T046 Support an exact reviewed native error-response SHA-256 signature when Gateway's Google protocol supplies only generic numeric/INVALID_ARGUMENT codes. Preserve status matching, the 16 KiB bound, no keyword classification, no raw-error persistence and explicit review; cover mismatched bodies/status and malformed fingerprints, update contracts, and rerun relevant gates. (FR-006, FR-007, FR-012, FR-017)

- [X] T047 Apply the operator-approved administration scope amendment across spec/plan/contracts/docs and strict evidence/review models. Preserve legacy full review by default; explicit operator-owned scope still requires routing, complete credential coverage and content-free telemetry, omits spend amounts and leaves external administrative claims unverified. Surface ownership in status/workspace; add negative, source-drift and legacy tests, run full gates and current-revision live checks, then prepare actual activation review. (FR-009–FR-015, FR-017, FR-018; SC-004–SC-006)

## Dependencies and execution order

T001–T002 → T003–T006 → US1 → US2 → US3 → US4 → US5 → T039–T040.
T041 requires completed software and separate operational authorization; T042 additionally requires
passing applicable live controls and existing baseline authority. Do not block software delivery on
absent live accounts: leave unexecuted live work pending and never simulate vendor proof.
T041/T042 were executed under the explicit T047 administration amendment; unavailable external
claims remain unverified, separately from completed application acceptance.
Within each story execute in listed order except explicitly marked parallel test tasks. Later
stories extend shared files, so their implementations are sequential even when test design is independent.

T011 depends on T005 and T009–T010. T016 depends on T009–T011. T022 depends on T005 and T020.
T026 precedes T027; T033 depends on T022/T026/T032. T035 retains recovery identity rather than
adding transport fields to it. T037 precedes full gate execution. No task grants permission to
push, merge, publish, purchase or change remote policy.

## Parallel execution examples

- US1: T007 wire tests and T008 entry-point tests touch different files and may proceed together.
- US2: T014 canary controls and T015 privacy tests may proceed together after US1.
- US3: model/spend test work T020 is followed by shared-file implementations; no safe parallel
  implementation pair is claimed within this story. Independent administrator documentation
  research for T024 can proceed alongside tests, with the file edit performed at its listed step.
- US4: telemetry cases can be designed separately from browser cases; T025–T029 edits are serial
  because metadata/capability/schema contracts are shared. Do not mark dependent edits parallel.
- US5: T030 review/probe tests and T031 setup/migration tests may proceed together after US4.

## Implementation strategy

First deliver a synthetic routing increment (US1), then add blocking, spend and visibility
increments, then complete setup/activation. US1 alone is a software demonstration, not a protected
private-data deployment; private use requires all baseline stories and applicable live review.
Each story has an independent fake-transport acceptance test. Keep security documentation and
module/function explanations accurate as behavior changes. Use the user's next instruction to
start implementation; every checkbox intentionally remains open here.

- [X] T048 Fix the guided onboarding CI extras after the hosted job exposed an absent optional OpenTelemetry SDK in the new exporter-failure regressions. Install `logfire` for that fixed synthetic CI job, preserve the slim installed-artifact matrix, and verify the isolated locked Python 3.12 guided environment. (FR-017, FR-018)
