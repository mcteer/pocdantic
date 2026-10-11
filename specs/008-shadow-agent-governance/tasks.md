# Tasks: Shadow Agent Governance

**Input**: Design documents from `specs/008-shadow-agent-governance/`.
**Prerequisites**: spec, plan, research, data model, runtime contracts and quickstart.
**Tests**: Required by FR-018 and the constitution; write meaningful failing cases before implementation.
**Organization**: Stories are independently testable with injected fixtures. Production flow remains sequential.

Task markers track verified implementation completion; native dispositions remain separately blocked. `[P]` permits parallel work only after prerequisites pass and on distinct files. Bounds quoted below are normative model constraints; all entity fields/relationships and contract predicates also apply.

## Phase 1: Setup

Create documented package boundaries and network-denied fixtures. No provider effects.

- [X] T001 Create documented governance package and additive CLI routing in src/agent/governance/__init__.py and src/agent/cli.py; preserve existing command behavior. (FR-014, FR-018).

- [X] T002 [P] Add isolated synthetic governance fixtures in tests/governance_support.py and tests/conftest.py with poisoned ambient settings, fake source/registry/issuer adapters and no real .local reads. (FR-018).

## Phase 2: Foundation

All stories depend on these strict contracts, durable state, metadata configuration and bounded ownership primitives.

- [X] T003 [P] Add strict contract/unsafe-file/capacity tests in tests/test_governance_models.py and tests/test_governance_store.py before implementing the shared boundaries. (FR-007, FR-016, FR-018, SC-006).

- [X] T004 Implement shared models, identifiers, private/public separation and lifecycle in src/agent/governance/models.py. Constraint C01: "UUIDs are canonical; revisions/generations are strict positive integers; digests are 64 lowercase hex characters; timestamps are timezone-aware UTC." Constraint C02: "Aliases match `[a-z][a-z0-9-]{0,30}`; private identifiers are 1–256 characters; owner/purpose text is 1–256 characters; public labels are generated aliases only." Constraint C10: "State enums are closed: candidate `prepared|observed|reviewed|enrolling|registered|blocked|closed`; attempt `prepared|submitted|confirmed|denied|uncertain|conflict`; proof `pass|fail|blocked|inconclusive`; provenance `synthetic|operator|native`." (FR-001, FR-005, FR-006, FR-007, FR-016).

- [X] T005 Implement anchored atomic state, exact ownership checks, short transactions and complete-reference retention in src/agent/governance/store.py; never reset established state. Constraint C04: "There are at most 16 sources, 1,000 candidates and 10,000 observations; the journal is at most 32 MiB; unresolved records are pinned and resolved cases retain all linked evidence for 30 days after closure." Constraint C08: "Private directories are mode 0700 and regular files 0600 owned by the current user with one hard link; symlinks, inode replacement and non-atomic state replacement are rejected." Constraint C16: "Each effect reserves 256 KiB of journal capacity before dispatch; recorded results consume that reservation; pruning never removes unresolved work or breaks reference closure." (FR-007, FR-016, SC-005).

- [X] T006 Implement fixed private prepare/configure files, source/candidate drafts, generation activation and metadata readiness in src/agent/governance/config.py; no provider provisioning or mint during readiness. Constraint C03: "HTTPS origins are exact and reviewed; paths contain no traversal, query, fragment or embedded credentials; namespace is exact; redirects and token-selected URLs are forbidden." Constraint C09: "Reviews/readiness expire after 300 seconds; imports are at most 1 MiB; at most 32 evidence references attach to one candidate; changed evidence/configuration invalidates dependent reviews." (FR-005, FR-008, FR-015, FR-016).

- [X] T007 [P] Add effect-owner, parent-death, deadline and response-hold race tests in tests/test_governance_concurrency.py using existing response/recovery fixtures. (FR-007, FR-015, FR-018, SC-002).

- [X] T008 Implement compiled worker ownership and conservative response/recovery admission in src/agent/governance/workers.py and src/agent/governance/coordinator.py with the exact lock order in plan.md; preserve hold ingestion during I/O and recheck at every dispatch. Constraint C07: "Network calls are at most 10 seconds and 256 KiB; effect workers are at most 120 seconds including drain; one local effect worker is active; at most 16 unresolved credential intents exist." (FR-007, FR-015).

- [X] T009 [P] Add candidate direct-OAuth/RAR negatives in tests/test_governance_bootstrap.py; cover opaque/missing/changed RAR, wrong actor/audience, unexpected act, lost issuance and impossible lifetime bounds. (FR-005, FR-009, FR-011, FR-018, SC-003).

- [X] T010 Implement candidate bootstrap and durable credential intent in src/agent/governance/bootstrap.py plus additive client_credentials_details in src/agent/oauth.py; no change to existing client_credentials or OBO behavior. Constraint C21: "Credential intent kinds are `actor_oauth|obo_oauth|svid`; tokens are memory-only; unknown lifetime bounds remain unresolved rather than expiring automatically." Constraint C22: "Candidate direct OAuth requests carry exact `vault:path_access` authorization details; verified JWTs require the exact candidate issuer/subject/audience and requested details, with no `act` claim; no RAR downgrade is allowed." Constraint C26: "A lost issuance needs provider evidence or an independently reviewed server-completion bound to establish its last possible issuance time; client timeout and worker exit alone do not establish that bound." (FR-005, FR-007, FR-009, FR-011).

## Phase 3: User Story 1 — Observe an unknown workload

MVP: authenticated observation-only intake preserves first evidence and grants no authority. Independently test with seeded source and controlled-case fixtures.

- [X] T011 [P] [US1] Add source spoofing, duplicate/changed replay, unknown-object attribution, secret-field and size/depth tests in tests/test_governance_source.py before source implementation. (FR-001, FR-002, FR-018, SC-001).

- [X] T012 [P] [US1] Add pre-registration absence, healthy control, chronology/skew, late/backdated evidence and compiled activity tests in tests/test_governance_activity.py. (FR-003, FR-004, FR-018, SC-001).

- [X] T013 [US1] Implement bounded native source projection, selected-content identity, immutable first observation and separate relay authentication in src/agent/governance/source.py; never widen response:submit. Constraint C05: "Input is at most 64 KiB, JSON depth 8 and 128 scalars; projection has at most 12 scalar JSON Pointers of at most 256 characters and 8 fixed predicates; compressed bodies are rejected." Constraint C06: "Relay tokens have exact enrolled issuer/subject/audience and `governance:observe` scope; age and lifetime are at most 300 seconds with at most 30 seconds future skew; event age is at most 300 seconds for automatic intake." Constraint C24: "Confidence is a finite numeric source value, a label of 1–64 characters or absent; it is never compared across sources; native classification/event kinds must match the enrolled fixed predicates." (FR-001, FR-002).

- [X] T014 [US1] Implement loopback observation routes in src/agent/governance/api.py with generation recheck, durable-before-ack and safe closed errors; intake performs no registry or credential effects. (FR-001, FR-002, FR-016, SC-001).

- [X] T015 [US1] Implement controlled case preparation, exact registry absence capture, candidate safe read and healthy control in src/agent/governance/activity.py; create intent before token exchange and never log returned fixture values. Constraint C18: "Native chronological proof requires clock bounds of at most 5 seconds per source, correlated registry absence, captured activity, received collector evidence and detection's latest possible time before registration's earliest possible time." (FR-003, FR-004, FR-007).

- [X] T016 [US1] Implement evidence linkage and bounded-clock chronology in src/agent/governance/evidence.py; separate notification receipt, collector classification and operator assertions from native discovery. (FR-001, FR-003, FR-013, FR-017, SC-001).

- [X] T017 [US1] Implement prepare/configure/case/readiness/observe/serve commands and safe operator status in src/agent/governance/commands.py; generated case is prepared, never a discovery claim. (FR-004, FR-008, FR-014).

- [X] T018 [US1] Add US1 end-to-end synthetic flow in tests/test_governance_discovery.py proving duplicate intake has no credential/registration effect and late receipt cannot fabricate prior discovery. (FR-001, FR-002, FR-003, FR-004, FR-018, SC-001).

## Phase 4: User Story 2 — Review and enroll one agent

Seed an observed candidate and metadata independently of US1 transport; exact reviewed creation/readback succeeds while crash, conflict and stale review remain blocked.

- [X] T019 [P] [US2] Add create-vs-update, absent-vs-unauthorized, default-policy, consumed-review, identity mismatch and external administration conflict tests in tests/test_governance_registry.py. (FR-005, FR-006, FR-008, FR-018, SC-002).

- [X] T020 [P] [US2] Add lost response, restart, matching-foreign-record, post-submit persistence failure and no-retry tests in tests/test_governance_enrollment_crash.py. (FR-007, FR-015, FR-018, SC-002).

- [X] T021 [US2] Implement exact registration payload and metadata adapter in src/agent/governance/registry.py; use entity/name/ID reads, no list/update/delete, and pin effective policy/alias/OAuth-profile metadata. Constraint C11: "Registration has one exact entity, operation-reserved name, owner, description, 1–8 ceiling policies and explicit default/RAR flags; create never includes an existing registration ID." Constraint C25: "Registration fixes `no_default_ceiling_policy=true` and `optional_authorization_details=false`; ceiling policies exclude `root`; exact SPIFFE IDs reject userinfo, port, query, fragment and dot segments." (FR-005, FR-006, FR-008).

- [X] T022 [US2] Implement fresh preview/review consumption, metadata recheck and submitted-before-create orchestration in src/agent/governance/coordinator.py; native enrollment needs qualifying case evidence and hold-free current anchors. (FR-005, FR-006, FR-007, FR-015, SC-002).

- [X] T023 [US2] Implement read-only reconcile and evidence-backed uncertainty resolution in src/agent/governance/registry.py and src/agent/governance/evidence.py; matching present is not owned creation and 404 alone never permits resubmission. (FR-006, FR-007, FR-013, SC-002).

- [X] T024 [US2] Wire review/enroll/reconcile/resolve/close in src/agent/governance/commands.py with exact UUID/revision and private preview; local close cannot remove provider authority or unresolved pins. (FR-006, FR-007, FR-014, FR-015).

- [X] T025 [US2] Add US2 synthetic enrollment and containment integration in tests/test_governance_enrollment.py; a new hold after dispatch prevents later phases and never triggers restoration or duplicate POST. (FR-005, FR-006, FR-007, FR-015, FR-018, SC-002).

## Phase 5: User Story 3 — Verify short-lived workload identity

Seed a registered binding and synthetic issuer independently of discovery; verify through a separately started relying process with no minting credential.

- [X] T026 [P] [US3] Add JWT-SVID signature/key/URI/entity/time/claims negatives and key-refresh tests in tests/test_governance_verifier.py, including duplicate JSON keys and JOSE URL/key confusion. (FR-010, FR-018, SC-003).

- [X] T027 [P] [US3] Add candidate-vs-operator/OBO mint, lost OAuth/SVID response, maximum-lifetime drift and token-canary tests in tests/test_governance_identity.py. (FR-009, FR-011, FR-018, SC-003, SC-006).

- [X] T028 [P] [US3] Add separate relying-process, socket ownership, one-use challenge, stale generation and containment tests in tests/test_governance_relying.py. (FR-010, FR-015, FR-018, SC-003).

- [X] T029 [US3] Implement strict Vault JWT-SVID verification in src/agent/governance/verifier.py with exact pinned trust and signed entity; never trust decoded claims before signature or token-selected endpoints. Constraint C12: "Trust uses one pinned algorithm from `RS256|RS384|RS512|ES256|ES384|ES512`, one audience of at most 256 characters, one exact SPIFFE ID of at most 255 characters and one exact entity; maximum SVID lifetime is 300 seconds and clock leeway is 30 seconds." Constraint C13: "JWT compact input is at most 16 KiB; headers allow only `alg`, `kid`, `typ`; `typ` is absent, `JWT` or `JOSE`; `kid` is required and at most 128 characters; `iss`, `sub`, `aud`, `iat`, `exp` and `vault.entity.id` are required." Constraint C19: "RS keys are at least 2048 bits; EC curves match ES256/P-256, ES384/P-384 or ES512/P-521; only signature-verification key operations are accepted." Constraint C20: "`aud` is one string or a singleton list matching the configured audience; time claims are strict finite integers with `exp>iat`, `exp-iat<=300`, `iat<=now+30` and `exp>now`; optional `nbf` is validated." (FR-010).

- [X] T030 [US3] Implement bounded independent OIDC metadata/JWKS retrieval and atomic key-cache refresh in src/agent/governance/verifier.py; successful empty keys deny, expired/invalid trust fails closed. Constraint C14: "JWKS has at most 16 usable public keys, a 60-second freshness ceiling and a 10-second unknown-key refresh throttle; duplicate key IDs, private key material, wrong key usage and ambiguous matches are rejected." (FR-008, FR-010).

- [X] T031 [US3] Implement separate private relying service in src/agent/governance/relying.py; load current profile independently, consume challenge before result, recheck current holds/generation before committing, and return no token/claim payload. Constraint C15: "A relying challenge is 32 random bytes, expires after 60 seconds and is consumed once; only its digest is persisted; requests/results are bound to candidate, profile generation, attempt and implementation digest." Constraint C23: "The relying socket is mode 0600 under the private directory; its JSON envelope is at most 64 KiB; access/body logging and browser listeners are disabled." (FR-010, FR-014, FR-015, FR-016).

- [X] T032 [US3] Implement candidate-authenticated mint and private IPC delivery in src/agent/governance/identity.py; bind signed vault.entity.id to registration, reserve intents and track last-possible-completion lifetime without revocation claims. (FR-009, FR-010, FR-011, SC-003).

- [X] T033 [US3] Implement identity/negatives proof command wiring in src/agent/governance/commands.py; actual unauthenticated mint denial has a healthy control, and locally tampered-token checks retain synthetic provenance. (FR-009, FR-010, FR-011, FR-014, FR-017, SC-003).

- [X] T034 [US3] Add US3 end-to-end independent native-adapter fixture in tests/test_governance_identity_flow.py; issuer mint success without relying proof, nonce replay or stale enrollment cannot pass. (FR-009, FR-010, FR-011, FR-018, SC-003).

## Phase 6: User Story 4 — Prove permissions and report outcomes

Seed per-path evidence independently; prove five authorization paths, seven honest native dispositions and browser owner isolation.

- [X] T035 [P] [US4] Add policy-layer attribution tests in tests/test_governance_permissions.py; missing RAR, wrong human ACL, provider outage and local denial cannot masquerade as a ceiling denial. (FR-012, FR-018, SC-004).

- [X] T036 [P] [US4] Add per-F11 evidence, chronology, latest contradiction, stale revision and unavailable-audit tests in tests/test_governance_closeout.py. (FR-013, FR-017, FR-018, SC-004, SC-007).

- [X] T037 [US4] Implement fixed read-only permission scenarios in src/agent/governance/permissions.py with verified exact OBO RAR, separate human/actor validation, direct bootstrap and healthy controls. Constraint C17: "Five authorization probe paths are fixed: preregistration, OBO allowed, OBO beyond ceiling, direct allowed and direct denied; targets are exact dedicated KV-v2 data reads, never credential-issuing or arbitrary write endpoints." (FR-012).

- [X] T038 [US4] Implement bounded import/review, native triage linkage and credential-uncertainty evidence in src/agent/governance/evidence.py; never rewrite original observation or automatically update acceptance.json. (FR-011, FR-013, FR-017, SC-004, SC-007).

- [X] T039 [US4] Implement independent F11 predicates, safe operator summaries and exact next-action codes in src/agent/governance/report.py; classify native audit absence separately from other paths. (FR-013, FR-014, FR-017, SC-004, SC-007).

- [X] T040 [US4] Wire permissions/import/status/closeout commands in src/agent/governance/commands.py; preserve CLI exit contract and non-TTY secret inputs. (FR-012, FR-013, FR-014, FR-017).

- [X] T041 [P] [US4] Add owner/session/API privacy checks in tests/test_governance_workspace.py and WebKit flows in tests/browser/test_workspace_governance.py before browser integration. (FR-014, FR-016, FR-018, SC-006).

- [X] T042 [US4] Integrate read-only owner-scoped GET /api/governance and safe status rendering in src/agent/workspace/app.py and src/agent/workspace/static/app.js, src/agent/workspace/static/index.html and src/agent/workspace/static/style.css; clear DOM on sign-out/expiry/suspension. (FR-014, FR-015, FR-016, SC-006).

- [X] T043 [US4] Add closed governance telemetry fields in src/agent/telemetry.py and canary checks in tests/test_governance_privacy.py; register all new source files in src/agent/validation/models.py implementation revision. (FR-016, FR-017, SC-006).

- [X] T044 [US4] Add four-story synthetic proof matrix in tests/test_governance_acceptance.py covering all seven F11 outcomes without live calls or native acceptance promotion. (FR-017, FR-018, SC-004, SC-007).

## Phase 7: Polish and cross-cutting validation

Finish bounded-operation evidence, publication controls, documentation and every native disposition.

- [X] T045 [P] Add 1,000-candidate/10,000-observation report budget and reference-closure/near-capacity reservation tests in tests/test_governance_bounds.py; unresolved results must remain writable after dispatch. (FR-007, FR-016, FR-018, SC-005).

- [X] T046 Extend scripts/publish_policy.py and tests/test_governance_privacy.py to reject private governance artifacts, raw identity tokens and renamed state/config/receipts; add only an exact synthetic config/governance.example.json exception if needed. (FR-016, SC-006).

- [X] T047 Update README.md briefly, docs/usage.md and docs/configuration.md with setup, private input, busy-workspace recovery, source prerequisites and concrete operator rechecks; add docs/adr/0010-shadow-agent-governance.md and its docs/adr/README.md index link. (FR-008, FR-014, FR-018).

- [X] T048 Review every touched module/function for purpose, inputs/outputs, effects, failure and security-ordering documentation per AGENTS.md; record threat/compatibility review in specs/008-shadow-agent-governance/validation.md. (FR-015, FR-016, FR-018).

- [X] T049 Run full CI commands and synthetic quickstart scenarios from specs/008-shadow-agent-governance/quickstart.md; record exact results, implementation revision and remaining limitations in specs/008-shadow-agent-governance/validation.md. (FR-018, SC-001, SC-002, SC-003, SC-004, SC-005, SC-006, SC-007).

- [X] T050 For each authorized live F11 test run its concrete workflow or record exact unavailable prerequisite, operator action and recheck in specs/008-shadow-agent-governance/validation.md; change specs/008-shadow-agent-governance/acceptance.json only for reviewed qualifying native evidence. (FR-017, SC-007).

## Dependencies and execution order

Phase 1 → Phase 2 → US1 → US2 → US3 → US4 → polish. Tests within each story precede its implementation. Source and activity tests can run in parallel after foundations; US2 registry/crash tests likewise; US3 verifier/identity/relying tests likewise; US4 permission/closeout tests likewise. Shared model/store/coordinator/command edits remain sequential. US4 browser test work can proceed alongside permission tests after safe summary contracts exist. Final privacy tests touching the same file as telemetry tests remain sequential.

No parallel marker bypasses a dependency. Foundation bootstrap tests precede bootstrap implementation; source activity uses that implementation. Relying tests precede the service, and verifier/cache implementation precedes native mint delivery. Completion verification follows publication/privacy changes.

## Independent story checkpoints and MVP

US1 is the observation-only MVP: no registry or credential authority from intake. US2 can be tested with a seeded observed candidate. US3 can be tested with a seeded registered binding and isolated signer. US4 can be tested with seeded per-path evidence and two browser owners. The complete feature includes every story, final gate and native-disposition task; MVP is a development milestone, not permission to stop early.

## Requirement coverage

| Requirement | Task IDs |
| --- | --- |
| FR-001 | T004, T011, T013, T014, T016, T018 |
| FR-002 | T011, T013, T014, T018 |
| FR-003 | T012, T015, T016, T018 |
| FR-004 | T012, T015, T017, T018 |
| FR-005 | T004, T006, T009, T010, T019, T021, T022, T025 |
| FR-006 | T004, T019, T021, T022, T023, T024, T025 |
| FR-007 | T003, T004, T005, T007, T008, T010, T015, T020, T022, T023, T024, T025, T045 |
| FR-008 | T006, T017, T019, T021, T030, T047 |
| FR-009 | T009, T010, T027, T032, T033, T034 |
| FR-010 | T026, T028, T029, T030, T031, T032, T033, T034 |
| FR-011 | T009, T010, T027, T032, T033, T034, T038 |
| FR-012 | T035, T037, T040 |
| FR-013 | T016, T023, T036, T038, T039, T040 |
| FR-014 | T001, T017, T024, T031, T033, T039, T040, T041, T042, T047 |
| FR-015 | T006, T007, T008, T020, T022, T024, T025, T028, T031, T042, T048 |
| FR-016 | T003, T004, T005, T006, T014, T031, T041, T042, T043, T045, T046, T048 |
| FR-017 | T016, T033, T036, T038, T039, T040, T043, T044, T050 |
| FR-018 | T001, T002, T003, T007, T009, T011, T012, T018, T019, T020, T025, T026, T027, T028, T034, T035, T036, T041, T044, T045, T047, T048, T049 |
| SC-001 | T011, T012, T014, T016, T018, T049 |
| SC-002 | T007, T019, T020, T022, T023, T025, T049 |
| SC-003 | T009, T026, T027, T028, T032, T033, T034, T049 |
| SC-004 | T035, T036, T038, T039, T044, T049 |
| SC-005 | T005, T045, T049 |
| SC-006 | T003, T027, T041, T042, T043, T046, T049 |
| SC-007 | T036, T038, T039, T044, T049, T050 |

**Total**: 50 tasks. Phase 1: Setup: 2, Phase 2: Foundation: 8, US1: 8, US2: 7, US3: 9, US4: 10, Phase 7: Polish and cross-cutting validation: 6.
