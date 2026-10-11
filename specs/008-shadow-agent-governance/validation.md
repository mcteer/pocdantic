# Validation ledger: Shadow Agent Governance

## Planning scope — 2026-10-10

Prepared specification, clarification review, researched plan, data model, runtime
contracts, quickstart, tasks and requirements/security checklists on
`feature/008-shadow-agent-governance`. No application code, dependency, live provider,
credential or existing private runtime state changed. The ignored Spec Kit feature pointer
selects 008 locally.

Clarify: zero questions required. The supplied Function 11 design and prior decisions
resolve scope. Requirements quality is 16/16; security requirements review is 19/19.
The plan skill's three research agents reviewed primary provider contracts and existing
code. Research identified candidate-vs-operator mint provenance, distinct OBO/direct policy
semantics, explicit client-credentials RAR verification, and server-completion uncertainty.
These are reflected in requirements, contracts and tasks before formal analysis.

Fifty sequential implementation tasks cover all 18 functional requirements and seven
measurable outcomes. Twenty-six normative constraint sentences are quoted in tasks.
All tasks are unchecked; no implementation or native acceptance is claimed.

Pre-analysis checks passed: all-feature gates for all eight features, runtime configuration
gate, 50 sequential correctly formatted tasks, 25/25 requirement/outcome mappings, 26 exact
constraint quotes and 15 valid local document links. The final staged/history privacy
check and formal read-only consistency analysis follow these artifact checks and are
reported in the completion response. No application tests or native execution were needed
for this documentation-only planning phase.

## Approved analysis remediation — 2026-10-10

Initial analysis found I1: FR-012 called the pre-registration check delegated, while
the researched plan uses the candidate's direct OAuth request and tests delegated
permissions separately after registration. The user authorized remediation. FR-012
now says "pre-registration direct OAuth denial", aligning it with the planned activity
and preserving both post-registration permission paths. Task scope and count are unchanged.
The subsequent read-only analysis and final artifact/privacy checks are reported in
the completion response; implementation remains unstarted.

## Native Function 11 prerequisites

All seven tests remain **blocked** at planning. An implementation task must either perform
an explicitly authorized isolated check or record its exact missing prerequisite and action.
Neither missing provider capability nor unavailable audit authorizes invented evidence.

| Test | Exact prerequisite | Operator action and recheck |
| --- | --- | --- |
| F11-T1 | Reviewed tenant collector schema/classification, notification evidence, exact unknown object attribution and bounded clocks | VIP operator supplies private source/schema/collector receipts; integration owner runs the unregistered controlled case and confirms detection/notification before enrollment |
| F11-T2 | Dedicated candidate JWT client with exact RAR, unregistered entity/alias/profile and healthy registered control | Verify/Vault owners configure isolated prerequisites; observe validates signed candidate claims then compares actual pre-registration denial and later matched positive read |
| F11-T3 | Licensed native SPIFFE mount/role, candidate direct mint permission and published trust | Vault owner configures exact role/subject/TTL; run identity proof through the separately started relying service and review signed entity provenance |
| F11-T4 | Synthetic fixture paths, human baseline/RAR allowing excessive request, and restrictive candidate ceiling | Provider owner pins policy bytes; permissions proof shows allowed OBO read and attributable provider ceiling denial |
| F11-T5 | Correlated real VIP and Vault audit evidence | Existing demo-tier Vault audit is unavailable; retain blocked, or use a separately authorized supported environment if this criterion is pursued |
| F11-T6 | Authorized unauthenticated mint negative and healthy issuer control, plus independent verifier negatives | Run compiled negatives; retain source attribution for the actual provider denial and label constructed token negatives separately |
| F11-T7 | Same candidate entity on valid OBO and direct auth with narrow independent policies | Run the two allow/deny pairs and review actual decisions and policy digests independently |

Exact setup and command sequence: [quickstart](quickstart.md). The public 15-criterion
acceptance file preserves all blocked statuses; implementation/closeout never auto-promotes it.

## Implementation completion — 2026-10-10

The 50 implementation tasks are complete, including the explicit blocked native
dispositions required by T050. All governance commands are wired; the browser exposes
only an owner-filtered read-only summary. No live provider workflow was run and no
acceptance criterion was promoted. The prerequisites table above remains the final
native disposition for each of F11-T1 through F11-T7. Missing live evidence is separate
from completed software work; no user authentication is needed to run these tests.

### Threat and compatibility review (T048)

Reviewed maintained governance modules/functions for purpose, inputs, outputs, effects,
failure and security ordering. An AST check confirms every governance module and function
has a docstring. Existing edited CLI/OAuth/workspace/telemetry functions retain their
purpose documentation; new browser helpers explain session fencing and safe rendering.

- Intake uses a separate verified relay audience/scope and bounded scalar projection;
  source findings never authorize registry or credential operations.
- Exact entity, alias, OAuth profile, policy digests, namespace, SPIFFE role and trust
  are rechecked. Group/inherited policy ambiguity, root policies and unsupported claim
  mappings block readiness. Provider-selected URLs, redirects and token-selected trust
  are rejected. OAuth client credentials remain private; returned tokens remain memory-only.
- Effect ownership follows the existing recovery/response lock order. Child descriptors
  retain ownership after parent death; response intake remains available during I/O.
  Holds are checked before dispatch and serialized with final confirmation. Lost issuance
  or creation remains uncertain; a timeout or worker exit is not a lifetime bound.
- Submitted intents precede effects. Registration acknowledgments are persisted before
  exact readback; foreign matching records never prove owned creation. Resolution needs
  reviewed completion/no-issuance evidence. Local closure never deletes native authority.
- Snapshot/anchor/seal checks reject unsafe files, rollback and inode replacement.
  Capacity is reserved before dispatch; unresolved records stay pinned. Closed-case
  pruning removes the complete reference closure only after the retention interval.
- JWT verification checks signature before claims, signed nested entity, exact trust and
  bounded time. Independent public-key retrieval has atomic refresh and throttling.
  Private Unix-socket challenges are one-use and generation/implementation-bound.
- Owner filtering, session expiry/suspension and DOM clearing protect browser summaries.
  Late responses are fenced by session identity and a clearing generation. Browser routes
  cannot invoke privileged governance commands. Telemetry accepts only closed safe fields.
- Native receipts require explicit review; review does not cryptographically authenticate
  an imported provider artifact. Synthetic issuer/key/negative fixtures prove software
  behavior only. F11 predicates require correlated, attributed and current evidence.

Compatibility: additive CLI routes and OAuth details method preserve existing methods.
Existing recovery/response schemas are unchanged; governance uses a separate anchored
private root. No dependency or environment-variable additions, provider provisioning,
registry update/delete, VIP administration API, reset or automatic credential revocation.
The exact inactive example is the only new publication exception; renamed private
artifacts and generic compact signed tokens remain rejected.

### Executed software validation (T049)

Implementation revision (source SHA-256):
`0aa0ea9993001839589b70dfb1ad5df431a1485daa0d8e7a6ca3e3497b454daa`.

- Final full suite with WebKit: **849 passed** in **117.83 seconds**.
- Final metadata/CLI/F11/budget focused checks: **26 passed**.
- Repeatability plus readiness/closeout checks: **29 passed** in 4.71 seconds.
- Ruff check and format: passed; **309 files** formatted.
- All eight feature specification gates and runtime-only gate: passed.
- `agent validate run`: all **9** offline scenarios passed; native criteria stayed blocked.
- `agent demo`: completed synthetic restricted-child read.
- `uv build`: wheel and source distribution built; distribution privacy gate passed.

Synthetic quickstart story coverage: US1 authenticated HTTP duplicate intake persists once
without authority and rejects spoof/replay/late chronology; US2 exact creation/readback,
consumed review, lost response, foreign match, persistence failure, restart and actual
response-hold integration; US3 native-adapter-shaped mint plus actual separate-process
private socket/public JWKS verification, nonce replay, stale generation and all verifier
negative classes; US4 independent seven-predicate matrix, unavailable audit, five fixed
permission paths, owner isolation and WebKit logout/expiry/suspension clearing. Maximum
1,000-case/10,000-observation reporting and near-capacity result persistence passed.
All use temporary roots, poisoned ambient settings and denied unmocked HTTP transports.

Native limitations: actual collector schema, isolated actors/entities/policies, licensed
SPIFFE setup, independent native receipts and a supported audit environment have not been
validated in this turn. Follow the precise prerequisite/action/recheck table above and
[quickstart](quickstart.md) for an explicitly authorized live run. No blocked check has
been relabeled as passing; `acceptance.json` retains all 15 blocked criteria.

Final documentation checks: **41** relative links passed. Staged-tree and full-history
privacy gate passed. Post-execution extension hooks were checked: configuration absent.
