# Validation and Handoff: Model Gateway and Credential Guardrails

**Status**: Software implemented, 2026-10-18. Synthetic software validation and real hosted
metadata trace delivery are recorded below. Initial live checks exposed Observe-mode enforcement and message capture. The operator repaired
both; the final 100-case matrix passes, with 100 hosted records containing no designated message
fields. The operator-owned control review is recorded; signed-in Gateway read and analysis pass.
Tasks T001–T047 are complete within the amended scope; external administrative claims remain unverified. Requirements checklists remain
read-only design review records.

## Requirements traceability

| Requirement | Implementation tasks | Acceptance evidence planned |
| --- | --- | --- |
| FR-001 | T004, T007–T011, T013, T042 | Four native protocols; every CLI/API/workspace/root/child/later turn. |
| FR-002 | T003–T004, T007–T011, T013, T021 | Explicit key, exact destination/model; no fallback or injected live bypass. |
| FR-003 | T003–T004, T008, T010, T012–T013, T028, T031, T036–T037 | New Gateway setup, explicit direct migration, offline isolation. |
| FR-004 | T007, T009, T014–T015, T019, T038, T040 | Credential canaries absent from messages/errors/exports; privacy gates. |
| FR-005 | T014–T016, T019, T032, T041 | Block coverage for every mandatory class/surface; unsupported activation refused. |
| FR-006 | T014, T016, T019, T032, T041 | Runtime-generated synthetic positives and near-match benign controls. |
| FR-007 | T006, T009, T011, T016–T018, T020, T023, T027, T042 | Single send, no ModelRetry/fallback/replay; cancellation and exact cleanup. |
| FR-008 | T004, T010, T020–T022, T024 | Exact allowlist, existing bounds, reviewed remote route/model restrictions. |
| FR-009 | T020, T022–T024, T041 | Remote finite caps/pricing/refusal; concurrency and unknown-cost limits. |
| FR-010 | T025–T029, T042 | Attempt correlation, usage/cost states, private joins and operator visibility. |
| FR-011 | T005, T015, T025, T027, T038, T040–T041 | No content capture; remote retention evidence required. |
| FR-012 | T006, T015–T016, T018, T023, T025–T028 | Closed errors and metadata on every public surface. |
| FR-013 | T012, T028, T030–T031, T033–T034 | Setup v1 JSON/exit semantics; names-only actions and review state. |
| FR-014 | T019, T024, T030, T032–T034, T036, T041 | Admin runbook and separately authorized probes/review. |
| FR-015 | T003, T005, T011, T022, T026, T030–T031, T033, T035, T038, T041 | Private digests, expiry, key/config drift, atomic read/review and context binding. |
| FR-016 | T001, T005, T008, T011, T013, T017, T021, T027, T030–T031, T034–T035, T042 | Existing authority, root/holds/recovery/cleanup preserved. |
| FR-017 | T003, T006–T007, T013–T014, T017, T020, T025, T029–T032, T035, T037–T042 | Meaningful negative suites, complete applicable CI and separate live records. |
| FR-018 | T001–T002, T010, T012, T019, T024, T029, T036–T037, T040, T042 | Public/agent guidance, minimal dependencies, locked artifacts and migration. |
| SC-001 | T007–T013, T037, T039, T042 | Zero direct Gateway-mode dispatch; zero live offline requests. |
| SC-002 | T014–T019, T032, T039, T041 | Full canary/benign matrix; separate actual vendor blocking proof. |
| SC-003 | T017–T018, T020–T023, T039, T042 | Zero denial retries/substitutions/tool replays; cleanup regression. |
| SC-004 | T015, T025–T029, T039, T042 | Terminal or explicit unknown outcome, zero content canaries, no fabricated cost. |
| SC-005 | T012, T030–T038, T039, T042 | Correct setup/review/migration owner/action and preserved private state. |
| SC-006 | T030, T032–T035, T039–T042 | Evidence/reviewer/time binding; no synthetic-to-live promotion. |

Coverage mapping: all 18 functional requirements and 6 success criteria have implementation and
validation work. This table is an implementation map, not a statement that any criterion passed.
Local-admission p95 performance work is T029; all task phases map to these requirements.

## Software acceptance coverage (executed; results below)

| Matrix | Required cases | Primary tests/tasks |
| --- | --- | --- |
| Native construction/wire | Google Cloud, OpenAI Chat, Responses, Anthropic; optional imports; poisoned auth/custom headers/proxy/env; path/redirect refusal | T007–T013 |
| Entry points | Runtime, CLI, API, workspace, both database profiles, parent/child and continuation; live injected objects; offline isolation | T008, T011–T013 |
| Credential privacy | All mandatory classes × five surfaces × four protocols; benign near-matches; adapter credential absence; malformed/oversized raw errors | T014–T018 |
| Controls/lifecycle | Local model denial; remote block/spend/auth/access/pricing/rate limit/generic; internal retries; concurrent turns, timeout, cancellation, uncertain dispatch; post-tool cleanup failure | T017, T020–T023 |
| Visibility | Run/parent/definition correlation; tokens/duration; known/unknown cost; storage/export failure; remote privacy blocked; no content in any public sink | T025–T029 |
| Setup/review | New defaults, explicit legacy direct, absent mode, Google migration, missing dependencies, root/files, stale/expired/rejected/mismatched review; no arbitrary probes | T030–T038 |
| Packaging/gates | Full CI, WebKit, onboarding and wheel/sdist matrix; sandbox platform/container checks; privacy and distribution contents | T037–T040 |

## Live Gateway acceptance (scoped application checks complete; external limitations retained)

| ID | Claim/evidence needed | Current disposition | Owner / next action |
| --- | --- | --- | --- |
| GW-01 | Actual endpoint/provider/model protocol, exact route and no failover/retry bypass for all enabled combinations; native decision/request correlation | Partial: approved native Google route serves 50 benign matrix cases; all 100 records report one attempt. Complete remote policy readback unavailable | Gateway administrator + integration owner: configure and run authorized fixed probes. |
| GW-02 | Every mandatory credential class/surface blocks onward provider delivery; benign controls allow; exact errors and detector targets/revisions documented | Observed coverage passes: final 100/100 cases across ten classes and five surfaces; 50 native Block decisions, 50 benign successes. Independent provider-side absence evidence unavailable | Gateway administrator: install Block, run complete synthetic live matrix, supply upstream evidence or leave unavailable cases blocked. |
| GW-03 | Deployment key spend caps, pricing/BYOK accounting and refusal with exact tested configuration; reset/concurrency/soft-limit scope | Unverified: operator owns cap configuration; no priced-refusal evidence | Operator: manage caps; not an application activation prerequisite under the approved operator-owned scope. Automation will not change financial policy. |
| GW-04 | Gateway/service pre-block logging and retention meet no-content requirement; application and remote metadata remain useful | Partial: after operator repair, all 100 fresh Gateway records omit designated message fields; application metadata-only agent export passes. Internal service retention remains unverified | Gateway administrator/privacy owner: configure, inspect and obtain service confirmation; retain internal service claims as unverified under the approved operator-owned scope. |
| GW-05 | New/repeated deployment preparation, explicit direct migration, review/rotation/expiry/drift and preserved enrollment under actual operation | Passed within application scope: reviewed installed deployment, sign-in and both Gateway flows; existing enrollment/recovery preserved | Operator: retain rotation/expiry procedures; no enrollment was reset. |
| GW-06 | Signed-in fixed read and sandbox analysis through Gateway with correlated model stages, correct tool authority and exact cleanup | Passed: signed-in fixed read and Monty analysis complete with revocation; hosted metadata correlated | Costs remain unknown; see the executed workspace record below. |

Evidence is private under the canonical deployment root and references exact observed configuration,
implementation, source, time and reviewer. Config/readback alone does not demonstrate vendor
blocking. A temporary zero-limit key tests only that key/configuration. No absence of a returned
answer is accepted as proof of zero upstream delivery. Unavailable native evidence remains blocked.

`acceptance.json` retains the repository's 15 legacy external criteria, all blocked. It does not
claim those criteria are supplied by Gateway or replace existing feature evidence. Gateway-specific
acceptance uses GW-01–GW-06 here and the proposed private control-review contract, without widening
the legacy acceptance enum merely to make a planning gate pass.

## Software verification

Executed locally with Python 3.12.14 on Darwin arm64 and the committed lockfile:

- Final full suite: **1,387 passed, 1 skipped** in 225.89 s, including Playwright/WebKit.
  Final focused telemetry/control checks: 27 passed; explicit repeatability/report/readiness/
  closeout command: 29 passed. No ordinary test calls a live model or service.
- All fourteen feature gates, runtime configuration, Ruff lint and formatting pass.
- Native real-SDK serialization covers Google Cloud, OpenAI Chat, OpenAI Responses and
  Anthropic with synthetic transports. The fixed matrix contains 400 canary/benign cases.
  Reviewed exact synthetic refusal schemas, unknown/malformed/oversized errors, single-send
  behavior, model selection, post-read denial, cancellation, shutdown drain, concurrent
  parent/child attempts, storage/export failure and review drift are covered.
- Read-only admission benchmark: 1,000 checks after 20 warmups, p95 **0.212 ms**, target
  ≤25 ms. This measures local admission, not remote inference latency.
- Guided/offline onboarding pass. Wheel and sdist build and distribution privacy pass; locked
  installed-artifact matrix passes all ten final wheel/sdist × base, Google, OpenAI, Anthropic
  and analysis combinations, using committed dependency resolution without live service calls.
- `agent validate run` passes all nine synthetic scenarios; the fifteen legacy external
  criteria remain blocked. `agent demo` and all 21 Monty demo probes pass.
- Security regression completes both profiles with passing software cases; ten native evidence
  groups remain blocked. Repeatability, readiness, closeout and sandbox platform checks are
  included in the full test suite. Disposable PostgreSQL/container fixture passed locally.
- Index/history and proposed-publication privacy checks pass; existing unrelated staged work
  is preserved. Final proposed-tree privacy, Markdown links and whitespace checks pass. No publication or remote policy
  changes were made. No implementation extension hooks are registered.

Task paths identify intended boundaries; equivalent regressions were consolidated into the
Gateway test modules where that exercises the same runtime/adapter paths. Runtime delegation
and existing cleanup implementations were reused rather than copied. Transport context drift
is explicitly tested to invalidate validation while preserving database recovery ownership.
Linux/macOS CI runners and branch-protection/maintainer review have not been executed remotely;
local macOS/container results do not claim another platform passed.

## Hosted trace verification

The user authorized real trace delivery and supplied the owner-only project credential. No
credential was copied from inkantOS or included in this record. A real synthetic parent/child
execution exported **17/17 acknowledged spans**, independently retrieved from hosted Logfire:

- Fixed service `agent`, environment `synth`, one trace root.
- Two separate native `invoke_agent` spans, labelled **parent** and **ticket-reader**.
- Distinct generated agent call IDs and child-to-parent ancestry verified.
- The current served Agents reader's span-name and semantic-attribute filter matches both
  invocations. The initial generic `agent` span-name mapping failed that filter and was fixed.
- Initial delivery acknowledgement and independent hosted query are separate checks; query
  validation accounts for the API's `data` result shape and ingestion indexing delay.
- No message/tool-content attributes in the queried records. Private source receipts remain
  beneath ignored owner-only `.local/trace-checks/`; no trace IDs or tenant identifiers are
  copied into public artifacts.

This proves actual Logfire delivery/discovery semantics for an executing synthetic parent and
child. It does not prove frontier inference, model spend, Gateway blocking, remote retention,
or completion of GW-01–GW-06. Inactive configured profiles have no invented registrations.

## Compatibility and remaining operational work

New live setup requires explicit Gateway mode, selected native protocol/model, region, route,
exact allowlist, Gateway credential and current reviewed controls. Existing enrolled deployments
may deliberately select direct mode; missing mode does not silently infer direct authority.
Google GLA is not silently converted to Vertex. Offline work remains isolated from live settings.
The direct HTTPX2 dependency was already locked transitively; its BSD-3-Clause license and
native SDK compatibility were reviewed with no integration dependency upgrades.

Normal CLI/API/workspace use enables metadata export when `LOGFIRE_TOKEN` is configured, supports
current versioned project credentials, and drains and flushes exporters on shutdown. Operator
configuration remains private; this change does not rewrite enrollment, provider grants,
recovery holds or remote policies.

A deployment still needs its explicit Gateway settings and administrator-reviewed evidence for
route/model restrictions, finite spending/pricing controls, complete credential Block coverage,
Include messages off and service-side retention/pre-block logging. Follow the administration
contract, then explicit local review before authorized signed-in flows. Unavailable source proof
stays blocked. No amounts, key rotation, auto-recharge, plan purchase or remote changes are
implied by passing synthetic tests.

## Remaining operational inputs

The operator approved the US native Google route/model and explicit shared project-key binding.
The operator owns cap configuration. Remaining controls need Block rules, message capture off,
route restrictions and remote retention evidence. Never request credentials in chat. Software implementation does not
reserve money, buy a tier, change providers, enroll state, issue tokens or perform database reads.

## Live setup continuation

The user authorized continuing T041–T042 and explicitly using the existing project API key
from `LOGFIRE_TOKEN` for Gateway. Owner-only local configuration now selects Gateway mode and
binds `GATEWAY_API_KEY` through a dotenv reference, without duplicating the secret or changing
enrollment or recovery state. The subsequently approved native model migration is recorded
below. Source code does not silently reuse tokens.

Observed: Gateway model catalog HTTP 200 with seven routes, including the built-in native
Google Vertex route and the exact configured Gemini model name. The catalog itself proves
neither inference nor spend/control enforcement. The operator subsequently approved the US
native-Cloud route/model. Provider-management reads return HTTP 403 with an explicit plan
restriction (Growth, Enterprise Cloud or self-hosted). Spending-limit reads separately return
HTTP 403 mentioning `organization:read_gateway`; that response alone does not establish a
missing selectable token permission. The current private file credential and Gateway binding
match; project reads succeed. No further credential rotation is requested.

Local workspace-read guide initially returned exit 2 for absent MODEL_MODE; after authorized
configuration it returns exit 3 for controls review. Recovery remains clear/not blocked, and no
workspace was listening on port 8000. No enrollment, credential issuance, database read or
remote policy change was performed. T041 and T042 remain unchecked.

Shared-key correction verification: 45 focused publication/configuration tests pass, including
regressions proving harmless reference syntax remains publishable, the resolved private value
is rejected, earlier overridden credentials remain protected, and no token-only Gateway fallback
was introduced. Ruff and distribution privacy checks pass. The standalone privacy gate retains
compatibility with the local system Python through postponed type annotations. The proposed-tree/history rerun passed after this supporting gate change; the real Git index
was preserved.

A private operator-preparation worksheet lists the proposed native route/model, all 100 fixed
Google Cloud live case IDs, unknown control dispositions and unset budget approvals. It is
explicitly not acceptance evidence or an approval; its pre-probe state is historical. The actual
subsequent probes and failures are recorded below.

### Actual routing and control findings

The operator approved the US `google-vertex` route with the exact existing Gemini model using
its native `google-cloud` protocol. The private configuration now selects that exact model and
a one-entry allowlist. The operator retains responsibility for setting spending caps; automation
will not change them or claim their enforcement verified. Local readiness now correctly exits
3 for a required Gateway controls review.

The first benign probe reported unknown dispatch. Offline reproduction through the real
HTTP/1.1 stack established a LocalProtocolError with zero HTTP writes: final header sanitization
removed mandatory Host and body framing. Mock transports did not catch it. The transport now
rebuilds Host/Content-Length from validated origin/bytes and fixes content headers, with a real
HTTP/1.1 serializer regression. Fixed probes now explicitly bound output to 64 tokens and time
to 30 seconds; all four native wire serializers verify the limit. The failed operation was not
replayed; a new benign case succeeded after repair. Focused Gateway checks: 39 pass.

One real benign request succeeded through Gateway to the selected model and its independent
Gateway metadata was retrieved from hosted Logfire. One invalid synthetic Google-key canary
was then allowed (expected Block), so credential protection failed that case. The benign
Gateway trace also contains message content. No real credential was put into model content.
Further model probes and protected activation were stopped. These are actual failed/unknown
control findings, not vendor acceptance. The administrator must scope Block protection and
content-free telemetry appropriately, then repeat affected synthetic cases before private use.
An owned WebKit window was opened but is unauthenticated; browser sign-in is not a software
prerequisite and no repeated sign-in request is made. The public API schema exposes no
Guardrails/settings administration operation. The inkantOS implementation records the same
provider-management plan restriction and owner-supplied Gateway settings; it does not establish
an available API bypass. The prior blanket diagnosis of insufficient token permissions was
incorrect and is superseded by these endpoint-specific findings.

## Final repair validation

After the HTTP framing, fixed-probe bounds, setup-action and dotenv-reference corrections:
full pytest passes **1,387 tests with 1 skipped**, including WebKit; both security-regression
profiles pass their software checks; all fourteen specification gates, runtime gate, Ruff lint
and formatting pass. Guided onboarding, all ten rebuilt wheel/sdist installed combinations,
nine offline validation scenarios, the parent/child demo and all 21 Monty demo probes pass.
The ten native security groups and fifteen legacy external criteria remain blocked.

The administrator contract now includes the exact observed repair: endpoint-scoped Block,
Include messages off, route/pricing inspection, and then affected fixed probes and independent
metadata verification. Financial settings remain operator-owned. No remote controls were
changed, no further model requests were sent after the failing canary, and no private-data
workspace flow was attempted. T041–T042 remain open for actual control repair and acceptance.

Final publication verification: proposed-index/history privacy passes with the actual Git index
unchanged. Offline onboarding, feature-local Markdown links and whitespace validation pass.
T043–T045 are complete; T041–T042 remain open. No extension hooks are registered.

Operational ownership clarification: the operator will perform control-panel-only changes.
Do not request an authenticated automation browser or another token rotation. The owned
unauthenticated WebKit window has been closed. Supply exact UI steps; use the existing
project key for bounded synthetic probes and independent telemetry checks after repair.

## Operator-installed Google-key Block verification

The operator supplied control-panel evidence: the prebuilt Google-key detector had matched the
original canary but was set to Observe for all requests. The operator then selected endpoint
Block. Subsequent fixed synthetic requests on user, instructions, history, tool arguments and
tool result surfaces all received HTTP 400; a benign control received HTTP 200. Inspected native
Google errors explicitly report Guardrails blocking, but carry only generic numeric/error-status
codes. Two distinct blocked surfaces returned byte-identical refusal bodies. No raw error,
model content or canary was persisted in these observations; only safe schema metadata and a
private SHA-256 fingerprint are retained. This establishes the observed refusal behavior; it
does not independently attest zero upstream delivery, all credential coverage or service retention.

The adapter now supports exact reviewed response fingerprints alongside existing code mappings.
Matching requires the exact HTTP status and bounded response bytes; arbitrary 400/INVALID_ARGUMENT
responses remain generic. No keyword matching or automatic runtime approval is introduced.
A candidate fingerprint correctly classifies the new tool-result probe as
`gateway_guardrail_denied`; ordinary activation still requires complete explicit evidence review.
Focused transport/control/privacy/review checks pass 54 tests, including mismatched status/body,
oversize, malformed fingerprints, single-send and safe errors. Full-suite rerun passes **1,392 tests with 1 skipped** in 224.16 seconds. All ten rebuilt
installed-artifact combinations, both security-regression profiles, specification/runtime gates,
Ruff lint/format and distribution/proposed-index privacy pass. T046 is complete; live controls
and workspace acceptance T041–T042 remain open.

Independent metadata-only query of the user-canary/benign window returns two records, one
with designated message content. Include messages remains unverified as off; the operator has
been given the control-panel change. The remaining four relevant prebuilt protections and
missing custom detector coverage still require configuration/verification. Caps remain operator-owned.

## Current telemetry UI correction

The operator reports no Include messages setting in the current Gateway panel. Earlier
instructions asserting that exact checkbox/location were not verified against this UI and
are withdrawn. inkantOS ADR0097 corrected the assumption that all Gateway export must be
disabled; it retained metadata-only export and later verified actual inference records without
designated conversation fields. It did not approve arbitrary Gateway conversation capture.

A new read-only query inspected the earlier benign-probe trace in memory. The Gateway
service/scope and exact configured model match, and the input contains the exact fixed benign
probe text (not merely an empty message array or attribute name). No content was printed or
persisted in this public record. Thus the privacy concern remains observed; the supported
control for this account is unresolved. No new model request or remote setting change was made.
Inspect the operator-provided Settings panel or obtain vendor guidance before prescribing an
actual control. Do not request browser automation sign-in or claim this setting is resolved.

## Remaining prebuilt enforcement verification

Under the operator's continued live-validation authorization, one fixed user-surface probe
per remaining prebuilt class was sent: OpenAI key, Anthropic key, JWT and PEM marker. All four
were allowed, so their block expectations fail. No actual credential was used. Further probes
for these unchanged classes are stopped until actual repair.

Independent Gateway decision metadata confirms every one of these synthetic classes matched
a detector, with action `observe` and match_count 1 (the Anthropic input matched two Observe
rules). Initial query bounds excluded the start of the OpenAI span; widening the read-only
window recovered it without another model request. Thus the observed issue is enforcement
action/targeting, not a demonstrated recognizer-format failure. The necessary operator change
is endpoint-specific Block for all four prebuilt protections. Private receipts retain safe
class/action/count summaries; no prompt, response, matched value or rule identifier is included
in this public record.

The public project-settings API and reviewed Terraform provider do not expose a supported
message-capture control. The operator is asked for the labels actually visible in Gateway
Settings rather than a browser sign-in or another assumed checkbox. Normal activation stays
blocked by the existing evidence gate; no fake control approval or state reset is performed.

## Current UI setting identified and operator repair reported

The operator supplied the actual Gateway Settings Telemetry screenshot. It contains Project
and Include messages; the switch was on. The description states that disabling it preserves
usage/cost/model/status/timing and retains existing traces. This supersedes the unresolved-label
disposition above. The operator then confirmed messages off and all four additional prebuilt
protections set to Block. Fresh source verification follows; the report alone is not acceptance.
No automation browser sign-in or remote administrative write was used.

Fresh verification after the operator's messages-off/all-four-Block report: the OpenAI canary
was allowed. Independent Gateway metadata records one match with action Observe for the exact
configured model. The same fresh trace has no designated input/output/instruction fields and
retains observed input/output token usage, so the visible message-capture setting is now
effective. Historical captured traces are retained by the service and are not mistaken for
new capture. The OpenAI action/target repair is not yet effective on the called route.

The operator inspected OpenAI targeting and confirmed no Block selection exists. This explains
its live Observe result without assuming a failed save or remote propagation bug. Instructions
now explicitly distinguish detector credential type from destination model: all credential
protections must target the selected Google endpoint, including OpenAI/Anthropic secrets.
The four-rule repair and subsequent verification are pending; no additional probe was sent.

## Effective prebuilt Block matrix after targeting repair

After the operator confirmed all four additional protections saved as Block on the selected
Google endpoint, native refusals confirmed effective enforcement. The native response body is
not identical across detector types; three additional exact fingerprints were privately
captured and used only as candidate diagnostic mappings alongside the Google signature.
No generic numeric code, status or keyword is promoted to a runtime denial signature.

The complete prebuilt matrix passes **50/50 fixed live cases**: Google/OpenAI/Anthropic keys,
JWT and PEM marker × user/instructions/history/tool arguments/tool result × positive/benign.
All positives report the reviewed Guardrails refusal and all benign controls succeed. Each
probe remains one send, 64 output tokens and at most 30 seconds, with no actual credentials
or tool execution. Initial failures and immutable probe records are preserved. Candidate
signatures do not approve normal private use. Missing custom classes remain pending; final
spending/routing/retention source review and signed-in flows are not implied by this matrix.

The operator supplied the new custom-protection form with syntax valid, Specific endpoints
selected and only google-vertex set to Block, then confirmed creation and listing. Initial
fixed synthetic samples for Gateway key, Vault token, PostgreSQL credential URI, labelled
password and client-secret assignments all receive native Guardrails refusals. Exact bounded
response fingerprints are retained privately without matched values or raw errors. The full
100-case final-configuration matrix is running; no result is inferred before it finishes.

The completed prebuilt matrix has 50 independent Gateway records, zero designated message
fields, and observed input/output token usage on all 25 benign calls. The inspected benign
record reports gateway.provider.attempt 1 and no cost field; missing cost stays unknown.
Project-specific spend readback was attempted using the known readable project and returns
403, so automation still does not attest or change the operator-owned cap configuration.

## Final-configuration live matrix and review preparation

The final installed configuration passes **100/100 fixed live cases**: all ten mandatory
credential classes × all five text surfaces × positive/benign control. Independent hosted
readback returns **100 Gateway records**, **50 native Block decisions**, **zero Observe
decisions**, and **zero designated input/output/instruction fields**. All 50 benign calls
retain observed input/output token usage. Every record reports gateway.provider.attempt 1,
including blocked requests; this field is not promoted to independent proof of upstream
delivery or additional billing. Costs absent from the inspected metadata remain unknown.

A canonical owner-only private review-preparation directory now contains the final matrix,
safe native metadata, project-spend access result, exact configuration/credential/implementation
bindings and source hashes. It is explicitly **not an approval**, contains no fake budget
values and is not a valid activating bundle. Protection coverage passes; remote routing policy
readback, operator-owned spend evidence/refusal and internal service retention/pre-block
logging remain unknown. Normal gateway status correctly reports gateway_review_required;
recovery status is clear/not blocked. No workspace was launched or database credential issued.

Software remains at **1,392 passed, 1 skipped**. No runtime source changed after that run;
subsequent work is operational verification and documentation. Existing unrelated staged work
is unchanged. T041–T042 remain open for the actual remaining source review and signed-in flow;
their unavailable parts are not promoted by the passing synthetic inputs or native refusal
records. The operator retains financial policy ownership.

The read-only workspace-analysis prerequisite check returns exit 3 with no missing settings;
its reported observations remain local/externally unverified and its sole blocking instruction
is Gateway administrative evidence review. Do not describe this as a signed-in read or successful
network/provider acceptance. The existing enrollment and clear recovery state are preserved.

## Operator-approved administration scope amendment

After all 100 live credential cases and content-free hosted traces passed, the operator
explicitly selected spending configuration and Gateway-internal retention as operator-owned.
This resolves the conservative full-administration activation requirement without inventing
financial evidence or promoting internal-retention claims. The current application scope
still requires explicit reviewed routing, credential blocking and visible telemetry privacy,
complete fixed-case coverage and all source/key/configuration/revision/expiry bindings.
Legacy/default full attestation remains unchanged. Source schemas, status labels and guidance
now express this distinction; updated current-source validation and live matrix follow.

Cross-artifact amendment review: FR-009/FR-011 and the new scope contract align with plan,
data model, runtime/admin contracts and T047. All 18 FRs and 6 SCs retain task coverage.
No constitution claim is weakened: vendor spending/retention acceptance remains unverified;
the application only activates the explicitly selected and reviewed protection scope.

## Current-source operator-owned review verification

After the scope amendment, the complete current-revision live matrix again passes
**100/100 cases**. Independent hosted data contains 100 matching-route records, 50 native
Block decisions, zero designated message fields, and input/output usage on all 50 benign
calls. The owner-only candidate bundle validates with explicit operator-owned administration,
exactly routing/protection/privacy controls, all 100 passing observations, private source
hashes, current configuration/key/implementation bindings and reviewed exact refusal
fingerprints. No spend values or administrative acceptance claims are included. It remains
a candidate until an explicit operator review is recorded.

Focused scope/control checks pass 74 tests, and focused workspace/WebKit/scope checks pass 41
(overlapping selections). Both security profiles, ten rebuilt installed-artifact combinations,
all feature/runtime gates, lint/format and distribution privacy pass. A full run reached
1,410 passed, 1 skipped and one fixture-construction failure: a newly sampled observation
time was rejected as future under strict wall-clock checking before the oversize-source test
ran. Synthetic fixtures now use an already-observed timestamp one second in the past; no
production timestamp check was relaxed. The affected review/control checks pass 43 tests;
the full rerun and history/privacy checks are pending below. Runtime source did not change
for this fixture fix, so the new live matrix still binds the current implementation.

Final amended-scope software result: **1,411 passed, 1 skipped in 253.77 seconds**, including
WebKit and all new ownership/negative/legacy tests. The earlier fixture failure is preserved
as historical; the strict production future-time check is unchanged. History/proposed-tree
privacy passes with the actual Git index preserved. Current 100-case native records were
inspected in memory for configured credential values; none were found, and raw attributes
were not persisted. The validated unapproved candidate includes that safe source receipt.

## Recorded review and live workspace launch

On 2026-10-18, following the operator's explicit instruction to proceed, the validated live
bundle was approved through the review command with reviewer `operator` and a 24-hour validity
bound. Status reports `protected-reviewed`, administration `operator-owned`, with zero normal
model attempts at review time. Routing, credential blocking and content-free telemetry are
reviewed; spending and internal service retention remain operator-owned and unverified.
This supersedes earlier candidate-only and review-required status descriptions above.

The workspace-analysis network prerequisite check returns exit 0 with no missing settings.
The owned workspace process is listening at `http://127.0.0.1:8000`, with callback
`http://127.0.0.1:8000/auth/callback`. WebKit reached the configured identity provider's
interactive sign-in page. No database read, analysis, or credential issuance has yet been
performed in this workspace run. T042 remains pending actual human authentication and observed
read/analysis/cleanup results; unavailable external T041 evidence remains unverified.


## Completed signed-in Gateway workspace acceptance

On 2026-10-18 the operator completed IBM Verify authentication in the owned WebKit session.
The existing deployment and enrollment were preserved. Both requested live flows passed:

| Flow | Observed result | Cleanup |
| --- | --- | --- |
| database-reader, record 1 | Completed; two Gateway model attempts; hosted database/credential/cleanup stages | Revoked |
| database-analyst, count by status | Completed using Monty; one program admitted, one SQL dispatch and one completed read; query policy/database/sandbox passed | One acquired, one revoked |
| parent, synthetic ticket delegation under signed-in identity | Policy denied before child execution; no permissions broadened and no replay | Not acquired |

Read and analysis ran from 18:37:30–18:37:55 UTC; the policy-negative parent check ran at
18:38:20–18:38:24 UTC. Independently queried hosted evidence contains 60 correlated application
spans across these three runs and five native Gateway records, all on `google-vertex`.
All five model attempts completed, with usage recorded and cost explicitly unknown; no
unknown attempts remain. Designated message fields and configured-secret matches are zero.
Raw provider attributes were inspected in memory and not retained in the receipt.

Hosted Agents discovery independently confirms `parent` and `ticket-reader` invocation spans
with distinct call IDs and a shared trace from the earlier synthetic delegation verification.
This is separate from the signed-in user's correctly denied ticket request. The new successful
live flows additionally register `database-reader` and `database-analyst` separately.
No change to identity grants was required or made.

Closed source receipts are owner-only under the private workspace-acceptance directory.
Final recovery is clear, with no blocked incidents; Gateway remains protected-reviewed under
operator-owned administration. T041 and T042 are complete in the explicitly amended application
scope. Spending caps/pricing/refusal and Gateway-internal retention remain unverified operator
responsibilities; independent upstream absence and inaccessible remote policy readback are
not claimed. Existing external acceptance.json criteria retain their blocked dispositions.
Maintainer review is required before merge; no commit, push, merge or publication occurred.
The workspace remains running at the actual loopback URL and callback recorded above.
