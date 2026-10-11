# Tasks: Portable PoC Setup

**Input**: [spec.md](spec.md), [plan.md](plan.md), [research.md](research.md),
[data-model.md](data-model.md), [contract](contracts/runtime.md).
Tests are required by FR-011 and the constitution. Software completion and external acceptance
are tracked separately; see validation.md for results and remaining prerequisites.

## Phase 1: Setup

- [X] T001 Record reviewed route/ownership threats, exact setup prerequisites and original compatibility in specs/011-portable-poc-setup/validation.md (FR-003, FR-007, FR-009, FR-010).
- [X] T002 [P] Create independent synthetic Verify/generic fixtures with custom mounts and namespaces in tests/portability_support.py; isolate ambient settings and ban real HTTP in ordinary tests (FR-004, FR-011).

## Phase 2: Foundational

- [X] T003 Add strict DeploymentProfile, DatabaseTarget and CapabilityObservation in src/agent/setup/models.py; trusted_hosts is unique, at most 16 DNS hostnames of at most 253 characters without wildcard/scheme/path/userinfo; report at most 32 observations; use fixed feature/state/evidence/owner enums from data-model.md (FR-004, FR-006).
- [X] T004 Wire explicit authentication route, custom auth/database target, private CA and bounded trust settings into src/agent/settings.py and .env.example; preserve aliases/default delegated mode and reject legacy/new target conflicts (FR-002, FR-004, FR-010).
- [X] T005 Share mode-aware endpoint trust through src/agent/probe.py and src/agent/workspace/auth.py; generic selection must not derive Verify discovery from leftover admin settings or require separate agent/service credentials for signature verification; preserve signed token purpose/issuer/audience/time checks in src/agent/oauth.py (FR-002, FR-004).
- [X] T006 Wire separate OAUTH_CA_FILE/VAULT_CA_FILE SSL contexts into trusted HTTP clients and src/agent/workspace/diagnostics.py plus src/agent/recovery/workers.py; carry trust to child workers, preserve response bounds/no redirects and test isolation in tests/test_setup_tls.py (FR-004, FR-008, FR-011).
- [X] T007 Extend journal-v3 native-user-token/database-lease ownership in src/agent/recovery/models.py and src/agent/recovery/store.py with human ownership, linked child attempts sharing one effect lock, write-ahead intents, original provider/namespace/trust/target fingerprint, exact private handles and idempotent v1/v2 migration; uncertain states block and cannot infer missing authority (FR-009, FR-010).
- [X] T008 Extend kind-aware status/revoke/import and reviewed proof in src/agent/recovery/commands.py, src/agent/recovery/proof.py and src/agent/recovery/workers.py; preserve original provider context, capture known-token authority, reject expiry/403 as cleanup proof, prohibit rediscovery by new login/listing (FR-009, FR-010).
- [X] T009 Add restart, two-child effect-lock, v1/v2 migration, malformed-login cleanup and kind-aware proof tests in tests/test_portable_recovery.py; independent token/lease receipts and uncertain states must survive process restart (FR-009, FR-010, FR-011).
- [X] T010 Replace hardcoded database/creds invariants with trusted DatabaseTarget in src/agent/vault.py, src/agent/validation/readiness.py, src/agent/validation/context.py and src/agent/validation/importers.py; retain old context and exact enrolled target in recovery/evidence (FR-004, FR-009).

## Phase 3: US1 - Colleague baseline (P1)

Goal: standard-provider sign-in/read/deny/cleanup from private setup without maintained-source edits.
Independent test: fresh generic-provider fixture with custom Vault mount and no Verify admin credentials.

- [X] T011 [P] [US1] Add positive and negative identity/endpoint tests in tests/test_portable_oidc.py covering wrong issuer/audience/typ, opaque token, forged identity, missing scopes, separate trusted hosts and leftover Verify settings (FR-002, FR-004, FR-011).
- [X] T012 [P] [US1] Add standard/delegated route contract tests in tests/test_portable_vault.py covering custom target, exact token/lease cleanup, unsupported native token type, lost login/lease response, cancellation, cleanup failure, replay and no privileged fallback (FR-003, FR-007, FR-009, FR-011).
- [X] T013 [US1] Implement distinct verified-user JWT login and native token self-revocation in src/agent/vault.py; capture native handles before validating service-token type and lookup-self verified explicit_max_ttl of 1–300 seconds; accept either renewable flag but never renew; require remaining time greater than operation deadline plus shared 30-second cleanup reserve, never use operator tokens and journal intent before dispatch (FR-003, FR-008, FR-009).
- [X] T014 [US1] Integrate explicit route selection into src/agent/broker.py and src/agent/recovery/lifecycle.py; deterministic policy and fixed SQL precede execution, allocate 20 seconds to exact lease cleanup and 10 seconds to exact native-token cleanup, attempt both even on failure, preserve uncertainty and cancellation ownership, keep delegated route unchanged (FR-003, FR-007, FR-009).
- [X] T015 [US1] Update cleanup classification in src/agent/vault.py and success projections in src/agent/workspace/runs.py to keep self-revoke allowed after containment and report complete only after both credential cleanup dispositions; test shared 20/10-second budgets in tests/test_portable_vault.py (FR-003, FR-009, FR-011).
- [X] T016 [US1] Implement no-effect, private non-overwriting `agent setup init --mode` in src/agent/setup/commands.py and src/agent/cli.py; repeated setup preserves configuration and unresolved journal state with fixed repair instructions and fresh-recovery initialization guidance (FR-001, FR-005, FR-010).
- [X] T017 [US1] Write concise colleague guide and exact administrator policy/client/callback examples with role-restricted synchronous lease-revocation parameters, hard-capped service token and separate baseline/advanced settings in docs/setup.md, link from README.md, document short settings and aliases in docs/configuration.md and narrow docs/setup.md publication allowlist in scripts/publish_policy.py (FR-001, FR-004, FR-008, FR-010).
- [X] T018 [US1] Add setup repeatability/privacy tests in tests/test_setup_commands.py covering no overwrite, no network/issuance, path safety, ignored private settings and no raw error/report secrets (FR-005, FR-008, FR-011).

## Phase 4: US2 - Accurate capabilities (P1)

Goal: identify available demonstrations and exact repairs before effects.
Independent test: fixture capability matrix distinguishes configured/advertised/demonstrated and blocked.

- [X] T019 [P] [US2] Add capability/report deadline tests in tests/test_setup_readiness.py covering 403, expired credentials, unsupported exchange/phone/audit, unknown support, timeout, untrusted metadata and independent baseline readiness (FR-006, FR-007, FR-011).
- [X] T020 [US2] Implement default local `agent setup check` and explicit public-only `--network` in src/agent/setup/readiness.py and src/agent/setup/commands.py with 2-second local/10-second network call/30-second overall bounds, at most 32 sanitized observations, exact missing names and administrator/operator repair steps (FR-005, FR-006, FR-008).
- [X] T021 [US2] Integrate route/capability projections into src/agent/workspace/app.py and src/agent/workspace/static/app.js; keep unsupported demos unavailable without blocking the baseline; no downgrade after failures (FR-002, FR-006, FR-007).
- [X] T022 [US2] Extend src/agent/validation/readiness.py and src/agent/validation/closeout.py to distinguish standard-user evidence from delegated proof and optional features; no native acceptance promotion from configuration or advertisements (FR-006, FR-007, FR-012).
- [X] T023 [US2] Persist authentication mode, generic source product, original context fingerprint and timestamps in src/agent/validation/models.py and src/agent/validation/context.py; project only trusted matching demonstration observations younger than 24 hours in src/agent/setup/readiness.py and test no stale/foreign/synthetic acceptance promotion in tests/test_setup_evidence.py (FR-006, FR-008, FR-009, FR-012).
- [X] T024 [US2] Add WebKit capability/setup/sign-in negative tests in tests/browser/test_workspace_portability.py, exercising generic issuer with no Verify configuration, no pre-saved bearer/agent credentials and preserving existing session/logout protection (FR-002, FR-006, FR-011).

## Phase 5: US3 - Independent portability evidence (P2)

Goal: software compatibility plus honest separate real-provider and colleague results.
Independent test: distinct fixture deployments; live acceptance requires original evidence and actual colleague.

- [X] T025 [P] [US3] Add software two-deployment compatibility and historical migration tests in tests/test_setup_portability.py; distinct provider shapes and custom paths, old unresolved history retained after mode/target change, no ambient live provider use (FR-009, FR-010, FR-011).
- [X] T026 [US3] Implement distinct user-jwt-read/user-jwt-denial in config/validation-suites.json, src/agent/validation/catalog.py and src/agent/validation/scenarios.py under live-portability with no original UC criterion mapping; add strict private denied-token input in src/agent/settings.py and route-aware ready/run behavior in src/agent/validation/runner.py (FR-003, FR-007, FR-011, FR-012).
- [X] T027 [US3] Provide separately invoked fixed-action live validation recipe in docs/setup.md and specs/011-portable-poc-setup/quickstart.md using existing broker/workspace boundaries; name issuance/read/cleanup effects and exact allow/deny expected outcomes for each route (FR-011, FR-012).
- [ ] T028 [US3] Execute baseline sign-in/allowed read/denied read/exact cleanup on IBM Verify and Keycloak with independent Vault instances; record actual versions, sanitized outcomes and private original evidence references in specs/011-portable-poc-setup/validation.md; if unavailable document exact access/setup prerequisite and leave task unchecked (FR-011, FR-012; SC-002).
- [ ] T029 [US3] Observe an unfamiliar IBM colleague performing two fresh setup runs with zero source edits/undocumented assistance and <=30-minute measured non-excluded time each; record repeat results and excluded waits in specs/011-portable-poc-setup/validation.md; leave unchecked without actual participation (FR-001, FR-012; SC-001).

## Phase 6: Polish and validation

- [X] T030 Review new/changed module and function documentation, route migration and capability limits in src/agent/setup/, src/agent/broker.py, src/agent/vault.py, docs/setup.md and docs/usage.md; no repo-wide commenting expansion (FR-001, FR-010).
- [X] T031 Run focused and full CI gates, WebKit, offline validation/demo, both-profile security regression and distribution privacy; record sanitized software results separately from live tasks in specs/011-portable-poc-setup/validation.md (FR-008, FR-011; SC-005).
- [ ] T032 Review prospective Git publication tree/privacy and obtain owner boundary review; keep original fifteen native criteria honest in specs/011-portable-poc-setup/acceptance.json and state live/colleague blockers in specs/011-portable-poc-setup/validation.md (FR-008, FR-012).

## Dependencies and parallel opportunities

T001–T002 precede foundation T003–T010; T003 before settings/target/journal integration,
T004 before shared OAuth builder, T007 before any new credential issuance. Tests may be
written alongside implementation only once foundation contracts are fixed. US1 is the MVP;
US2 uses shared foundation and integrates baseline after US1. US3 compatibility/evidence follows
both; T028–T029 require real deployment access and colleague participation, not software tests.
T031 follows all software; T032 follows validation and does not imply merge authorization.

Parallel examples: US1 T011/T012 (separate test files); US2 T019 can precede readiness build
while US1 implementation continues; US3 T025 fixture tests can precede live recipe execution.
No simultaneous edits to shared broker, recovery or configuration files. Incremental strategy:
foundation -> standard baseline -> capabilities -> software validation -> real pair -> colleague.
Never mark blocked external tasks complete solely to finish implementation.
