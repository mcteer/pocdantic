# Tasks: Secure agent runtime

Owner: mcteer. Inputs: spec.md, plan.md, research.md and contracts/runtime.md.

## Phase 1: Setup
- [X] T001 Configure privacy and distribution rules in .gitignore, pyproject.toml and scripts/check_privacy.py.
- [X] T002 Lock slim base and optional dependencies in pyproject.toml and uv.lock.

## Phase 2: Foundation
- [X] T003 Write boundary tests in tests/test_security.py and tests/test_adapters.py before implementation.
- [X] T004 Implement frozen identity, typed contracts and settings in src/pocdantic/schemas.py and settings.py.
- [X] T005 Implement policy, containment and safe audit in src/pocdantic/security.py.

## Phase 3: US1 bounded delegation
- [X] T006 [US1] Implement native capabilities and profile factory in src/pocdantic/capabilities.py.
- [X] T007 [US1] Implement bounded runtime with child usage sharing in src/pocdantic/runtime.py.
- [X] T008 [US1] Prove offline delegation and injection denial in tests/test_runtime.py.

## Phase 4: US2 configuration and repeatability
- [X] T009 [US2] Implement provider-independent OAuth and JWT ingress in src/pocdantic/oauth.py.
- [X] T010 [US2] Add optional safe telemetry in src/pocdantic/telemetry.py.
- [X] T011 [US2] Add run, batch, demo and probe commands in src/pocdantic/cli.py and authenticated API in api.py.

## Phase 5: US3 credentials and approval
- [X] T012 [US3] Implement exact-action approval and simulated write in src/pocdantic/approval.py.
- [X] T013 [US3] Implement Vault lease lifecycle and optional PostgreSQL executor in src/pocdantic/vault.py.
- [X] T014 [US3] Implement Verify push adapter and test supported contracts in src/pocdantic/verify.py.

## Phase 6: US4 evidence and containment
- [X] T015 [US4] Implement acceptance evidence schema/validator in src/pocdantic/evidence.py.
- [X] T016 [US4] Record blocked/live dependencies in specs/001-secure-agent-runtime/acceptance.json.

## Final Phase: Validation
- [X] T017 Add executable CI and hook gates in .github/workflows/ci.yml and .githooks/.
- [X] T018 Document configuration and operating boundaries in README.md and config/.
- [X] T019 Run tests, lint, package privacy and sanitized live probes; record results in validation.md.

## Dependencies & Execution Order
Setup -> foundation -> US1 -> US2 -> US3 -> US4 -> validation.
Each story has deterministic independent tests. Independent documentation/lint checks may run together.
No parallel implementation agents required. MVP is US1; vendor phase gates stay pending until live proof.

## Implementation Strategy
Validate local stories incrementally. Treat live acceptance as separate work with a named owner,
source-system evidence and review. Never substitute synthetic results for vendor enforcement.

## Database integration follow-up
- [X] T020 Provision existing HCP Vault against reachable TLS PostgreSQL and verify leases.
- [X] T021 Add pooler routing and database-reader capability profile.
- [ ] T022 Complete live signed user/actor exchange and exact RAR verification.


## Governance and contribution documentation
- [X] T023 Update README/CONTRIBUTING, review ownership and PR template.
- [X] T024 Version sanitized Spec Kit artifacts and ADRs; retain private-source exclusions.
- [X] T025 Validate specification gates from a clean publishable checkout without local state.


## Delegated identity implementation
- [X] T026 Implement separate-client PKCE login in ignored chat/ with validated callback and private sessions.
- [X] T027 Verify subject and actor before exchange; validate exact returned delegation grants.
- [X] T028 Request exact-lease cleanup authorization separately from credential-read authorization.
- [X] T029 Test signed end-to-end broker contracts, denial and cancellation cleanup.
- [ ] T030 Exercise the real user/agent/Vault/database chain and capture private evidence.

- [X] T031 Build ignored local chat frontend with user-isolated conversation context and session boundary tests.
