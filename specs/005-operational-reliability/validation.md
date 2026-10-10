# Validation ledger: Operational reliability

## Planning and companion documentation — 2026-10-10

Specification and clarification completed; user selected exact repair steps plus recovery
checks. Plan/research/design and tasks are planning artifacts. No 005 runtime code or live
provider configuration has been changed, and no 005 runtime test pass is claimed.

Root AGENTS.md is a separately requested companion documentation change on this branch.
It is linked from CONTRIBUTING.md; the publication allowlist adds only that exact root
file. The existing staged-secret regression now also covers AGENTS.md. Publication suite:
26 passed. All-feature Spec Kit gates, targeted Ruff lint/format checks, staged diff
whitespace review, and the index/history privacy gate passed. Task validation found 35
sequential checklist entries, full coverage of 16 requirements and 8 success criteria,
and all 13 model constraints quoted in their implementation tasks. Contributor instructions require useful module/function documentation. A
comprehensive code-commenting pass is queued for a separate branch after the user switches
models; it has not started.

## Planned live validation dispositions

| Case | Current disposition | Evidence/review |
|---|---|---|
| Normal read with confirmed synchronous cleanup | Blocked: not run for 005 | No source collected; reviewer pending. |
| Known-handle operator recovery retaining valid session | Blocked: not run for 005 | Requires a safely resolvable incident and authorized cleanup. |
| Unknown acquisition correlated to native lease | Blocked: native export/linkage not established | No invented mapping; reviewer pending. |
| Pre-execution denial proving non-issuance | Blocked: exact native proof not collected | Generic failure is insufficient. |

Deterministic software tasks can complete with supported cases validated synthetically and
an explicit live disposition recorded. A blocked live claim is not a completed live proof.
Acceptance.json preserves all 15 existing UC criteria as blocked; those criteria are
legacy vendor acceptance, not a substitute for the 005 FR/SC task coverage matrix.

## Historical limitations

The two unknown credential acquisitions recorded in 004 remain unreconciled. A new
journal cannot supply their missing native handles or correlation. Prospective enrollment
must not be described as resolving them. Existing 003 native audit/denial limitations
remain separately tracked. No prior exception or merge instruction is extended to 005.

## Delivery prerequisite

At last inspection main did not have the protections required by constitution 1.2.0.
Before any later merge, verify required validate, PR review, stale-approval dismissal,
and prevention of force pushes/deletion, and obtain actual maintainer review. Planning
completion is not a delivery approval or claim these controls are configured.

## Runtime implementation — 2026-10-10

Implementation branch: `feature/005-implementation`. Planning was merged separately;
the code-commenting work was also merged before this implementation. The earlier
planning-only descriptions above record the state at that checkpoint.

Implemented prospective durable acquisition/cleanup tracking, explicit enrollment,
private native-proof import/review, exact synchronous operator revoke, shared database
admission, authenticated ownership projections, fixed-target diagnostics, browser repair
controls, workspace lifetime ownership, and restart normalization. No dependency or
environment variable was added. No installed provider policy was changed.

### Deterministic evidence and boundaries

| Coverage | Executed evidence |
|---|---|
| FR-001–004 / SC-001–002 | Unit and WebKit diagnostics distinguish configuration, reachability, timeout, authorization, sign-in, and recovery; keyboard controls, delayed bootstrap, stale facts, bounded reports, no automatic provider retry/effect. |
| FR-005–007 / SC-003–004 | Strict models/store/lifecycle/broker/API tests, exact signed sync details, malformed credentials, lost replies, durability failure, actual SIGKILL checkpoints, native pair linkage, synchronous completed responses. |
| FR-008–010 / SC-005 | CLI import/revoke/repeat/contention/cancellation and WebKit operator closure with valid session/new manual submission; signed-out/expired authority stays absent, prior result unchanged, restart loses session/job history. |
| FR-011–014 / SC-006–007 | Seeded private exports, journal and public projections, logs/errors, duplicate/deep/oversized JSON, unsafe private paths, environment removal/change, capacity/pruning, cross-incident receipt reuse, stale revisions, lifetime/effect lock contention. |
| FR-015–016 / SC-008 | Full suite and CI commands below; separate explicit live/delivery dispositions. Legacy 003/004 acceptance remains unchanged. |

The eight-point process-interruption matrix uses real subprocess SIGKILL and the actual
Vault credential lifecycle against a controlled provider. While each child is alive,
the parent is refused effect ownership; after termination the new store normalizes and
validates without replaying issuance or SQL.

| Kill point | Restart disposition |
|---|---|
| Durable intent before transport send | Unresolved, acquisition blocked. |
| Provider request entered, response lost | Unresolved, acquisition blocked. |
| Handle returned but not yet persisted | Unresolved, acquisition blocked. |
| Handle persisted before SQL | Unresolved with exact handle, acquisition blocked. |
| Cleanup intent persisted before request | Unresolved with exact handle, acquisition blocked. |
| Cleanup submitted, response not received | Unresolved with exact handle, acquisition blocked. |
| Completed sync response before terminal receipt | Unresolved with exact handle, acquisition blocked. |
| Terminal receipt durably committed | Resolved/revoked, later explicit admission allowed. |

Canceled operator cleanup holds the effect lock until a cancellation-resistant controlled
worker actually stops. A handle-persistence failure still attempts exact in-memory
cleanup and never yields credentials to SQL. Production diagnostics/administrative
cleanup isolate network work in terminable processes, including spawn-cancellation
ownership. A second initialized workspace is rejected; an idle operator can acquire the
separate effect lock. Source exports are never copied into the journal.

Seeded forced-staging tests demonstrated that `config/state.json`, `config/anchor.json`,
and copied recovery receipts escaped the previous filename filter. The shared publication
rule now rejects these names in the Git index and distributions. The same filter rejects
`.local/` evidence; no publication allowlist expansion was needed.

### Optional live cases: disposition, not native success

No live issuance, phone prompt, provider administration, or cleanup was performed for
005. No authenticated browser session or approved native export was available in this
implementation turn. Do not create an unknown live lease to produce a recovery example.

| Case | Disposition and concrete prerequisite | Evidence/review |
|---|---|---|
| Normal read with confirmed sync cleanup | Blocked: installed RAR/ACL support for boolean sync=true has not been migrated/verified, and a fresh human session is absent. Integration administrator must review/install the documented schema/ACL change before a normal signed-in read. | No 005 native source collected; maintainer review pending. |
| Known-handle recovery preserving valid session | Blocked: no safely resolvable prospective live incident with a known native handle and valid user session is available. Use a genuine journal incident and authorized exact cleanup; do not manufacture an incident. | Synthetic CLI/WebKit proof only; native review pending. |
| Unknown acquisition to native lease | Blocked: matching original audit request/response, un-HMACed correlation/lease fields, and verified source provenance have not been provided. Vault administrator must export the exact original pair into the supported private wrapper. | No guessed native linkage; review pending. |
| Explicit pre-execution denial/non-issuance | Blocked: exact native pair with policy_results.allowed=false and supported denial evidence is absent. HTTP error or missing lease is insufficient. | Synthetic strict-denial proof only; native review pending. |

All 15 acceptance manifest criteria remain blocked and unmodified. The two historical
004 unknown acquisitions and 003 audit/denial gaps remain open. New enrollment is
prospective and cannot reconstruct them. T034 completes by recording these concrete
dispositions; it does not claim live validation passed.

### Security review and delivery readiness

Implementation self-review checked intent/handle/receipt ordering, type-aware delegation,
fixed destinations, cancellation containment, owner-only bounded storage, source review
provenance, cross-incident reuse, session ownership, projection privacy, and publication.
An independent maintainer's security/owner review remains pending.

Read-only GitHub inspection on 2026-10-10 returned **Branch not protected (404)** for
main's protection endpoint and an empty repository ruleset list. Required validate checks,
PR review, stale approval dismissal, and force-push/deletion prevention therefore are
not enforced on main. This is a **delivery block**, not a waiver or incomplete runtime
feature. The repository administrator must configure those controls; a maintainer must
review the eventual PR before merge. No provider or GitHub settings were changed.

No 005 implementation push, PR, or merge was authorized in this turn or performed.
T035 completes by recording actual readiness and missing controls. Earlier merge
instructions apply to their earlier PRs and do not authorize this implementation merge.

### Executed quality gates

- Final full suite: **465 passed in 85.13 seconds**, including **31 WebKit
  tests**, eight SIGKILL checkpoints, and the added receipt-before-completion regression.
  Earlier full runs passed 452, 458, 459, 460, and 464 tests as additional checks were added.
- Four focused publication regressions covered renamed native exports; the publication/
  privacy suites passed separately and also in the final full run. Final count is below.
- All-feature Spec Kit gates passed for 001–005; each retains 15 blocked live criteria.
  Runtime configuration gate, Ruff lint, Ruff format, and diff whitespace checks passed.
- Offline validation: nine selected scenarios, nine terminal passes; no acceptance
  promotion. Synthetic demo completed without network effects.
- CI's targeted repeatability/report-budget/readiness/closeout command: **29 passed**.
- Wheel and source distribution built; shared filename/content and local-secret privacy
  checks passed. The staged tree and reachable history were checked before delivery.
- Private live enrollment is absent; implementation did not initialize the real journal.
- No `.specify/extensions.yml` exists; before/after implementation hooks are absent.

The final review found an early broker cleanup event that preceded durable receipt
persistence. A regression reproduced it by failing the terminal write. Completion now
emits only after that write; cleanup still runs and the attempt remains pending on failure.
Explicit recovery checks prune expired resolved records under effect/journal ownership;
zero unresolved records are removed and pruning supplies no recovery proof.

A further forced-staging regression showed that renaming native exports bypassed filename
checks. The shared content detector now rejects intact native audit/credential envelopes
and recovery bindings in JSON/JSONL, even under other filenames, in index/history and
wheel/sdist checks. Maintained Python synthetic examples remain permitted. No live source
was copied or published to demonstrate either gap.

Final publication/privacy follow-up: **38 passed** (35 publication cases and three
recovery-privacy cases). The final tree passes **465 tests**, including 31 WebKit
cases. All 35 implementation tasks are marked complete; optional live cases and
server-side delivery controls have the explicit blocked dispositions above.

A retention regression also verified that completed incidents leave the manager's
quarantine registry after their durable completion event. Otherwise a later seven-day
prune could remove old receipts yet leave stale in-memory references blocking unrelated
recovery. Session-owned history stays separate; unresolved references remain tracked.

### Authorized delivery follow-up — 2026-10-10

After the implementation results were presented, the maintainer explicitly requested
“merge it.” This authorizes committing, pushing, opening the implementation PR, and
merging after green CI. The earlier delivery disposition above records the preceding
checkpoint. Main remains unprotected (GitHub returned HTTP 404 on recheck); the explicit
merge instruction takes precedence for this delivery. No repository protection or
provider settings are changed. Live acceptance remains blocked as recorded above.

### Live operational follow-up — 2026-10-10

The maintainer authorized provider configuration, prospective enrollment, and live
checks. A refreshed private Vault operator token authenticated successfully. The
installed database ACL and the agent-registry ceiling ACL now require `lease_id`
and boolean `sync=true` for cleanup, retaining the existing credential-role boundary.
The IBM Verify authorization-detail schema was updated only to allow `[true]` for
`allowed_parameters.sync`; other type settings were preserved. All changes were read
back from their provider. Backups and observations stay beneath ignored `.local/`.

Explicit recovery enrollment succeeded. Read-only production diagnostics observed
identity metadata, an unsealed Vault endpoint, and database TCP connectivity. The
workspace then completed fresh IBMid authentication in WebKit.

The first synthetic-record read succeeded but delegated cleanup returned HTTP 403:
the initially overlooked registry ceiling still excluded `sync`. The durable journal
retained the exact known handle and blocked admission. One authorized operator
`recover revoke` completed synchronous cleanup and durably resolved that incident.
The browser's recovery check cleared quarantine while preserving the signed-in session
and the original failed result. The registry ceiling was then migrated and verified.

A new explicitly submitted read completed with delegated synchronous cleanup and a
terminal durable receipt. Both attempts are resolved; recovery status is clear. A
separate administrative exact-lease lookup reported each handle absent. The same
browser session remained signed in throughout repair and the successful new submission.
No ambiguous acquisition was manufactured, no old task was replayed, and no passwords
were tested against the live database.

These observations establish the normal-read and genuine known-handle recovery flows
operationally. They do not substitute for original source-system audit pairs or explicit
native-evidence review. Unknown-acquisition linkage and pre-execution denial remain
unverified; the historical 003/004 gaps and all 15 acceptance-manifest dispositions
remain unchanged. No raw evidence, credentials, provider identifiers, or lease handles
are included in this ledger.
