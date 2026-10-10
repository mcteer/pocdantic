# Implementation Plan: Provider detection and remediation

**Branch**: `feature/007-provider-remediation` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)
**Input**: `specs/007-provider-remediation/spec.md`

## Summary

Complete the software for remaining Function 10 controls on top of 006: a bounded,
enrolled native-event translator; exact Vault registration/native-token controls;
Verify tenant suspension/session controls; static-secret and isolated database-session
remediation; Teams Workflows notification; independent enforcement proof and safe recovery.
Provider deployment and reviewed live acceptance remain explicit gates, never synthetic passes.

## Technical Context

**Language/Version**: Python 3.12+, existing plain browser JavaScript.
**Primary Dependencies**: Existing Pydantic, httpx, PyJWT, optional FastAPI/Uvicorn,
psycopg, pytest and Playwright/WebKit. No new dependency or environment variable planned.
**Storage**: Private atomic response JSON schema 2; existing recovery v2 unchanged.
**Testing**: Network-denied deterministic suites, process/crash tests, synthetic HTTP/DB
adapters and WebKit; separately authorized private live probes.
**Target Platform**: Existing single-host macOS/Linux, loopback services.
**Project Type**: Python runtime/CLI plus optional workspace and response service.
**Performance Goals**: Existing 2s intake/cancel goals and 250ms watcher; 120s provider
attempt budget including drain, 10s calls, at most 3 read-only reconcile calls/action.
**Constraints**: Exact enrollment and immutable attribution; no blind retries; one live
DB effect owner; no credentials in model context, telemetry, browser or published artifacts.
**Scale/Scope**: 16 sources, 32 rules, 64 bindings, 16 non-settled incidents; exact C01–C18
constraints in [data-model.md](data-model.md). Public hosting, Function 11 and global IdP
administration excluded.

## Constitution Check

Reviewed before research and again after design against constitution 1.2.0.

| Principle | Pre-research / post-design disposition |
| --- | --- |
| I. Slim/configurable | Pass: existing extras; private mappings, no new vendor SDK |
| II. Verified trust | Pass: independent source authority, deterministic policy, exact actor/user/resource binding, scope restrictions |
| III. Secret isolation | Pass: fixed private stores, ephemeral proof credentials, strict projection/publication checks |
| IV. Native evidence | Pass: source authentication, mutation acknowledgment, observed denial and audit evidence separate |
| V. Bounded execution | Pass: resource/call/storage limits; uncertainty retained; drain/locking and retry rules specified |
| VI. Reproducibility | Pass: traceable security/crash/migration/browser tests and compatibility guide |

No design exception requested. Security-owner review and required checks remain delivery
requirements. The previously observed missing branch protection is an administrative
prerequisite, not changed by this planning branch. No provider mutation, push or merge is
part of this request. Native Vault audit remains unavailable on the Development tier.

## Architecture and decisions

### 1. Source translation and policy

Add `response/native.py` with scalar JSON-pointer projection and finite equality rules.
The new native route reuses the 006 pinned JWT verification rules and submit scope,
with its own enrolled audience and exact issuer/subject in the v2 source profile. A deployed trusted relay must authenticate the vendor delivery before
forwarding it using its scoped response identity. Hosting/configuring that external relay
is an operator prerequisite; no new public ingress is shipped. Its vendor transport,
schema version, fixture digest and collector proof are enrolled privately. The application
never guesses a universal VIP webhook. AuthMind polling and Verify SaaS notification
adapters are researched alternatives, not additional implementations or VIP substitutes.

One fixed source profile maps each native object to an enrolled definition/resource.
For root scope, a separately mapped correlation field must equal a host-registered request
ID for that exact definition/source binding; no root UUID is pre-enrolled. This prospective
lookup permits new roots without hot-editing policy. Missing correlation rejects root scope;
there is no event-selected action or URL. Authenticate before bounded parsing, derive
the canonical event from security-relevant fields, and persist hold/plan before acknowledgment.
Native source identity is separate from reviewed evidence that a real collector detected
it. Reject missing native enrollment; keep 006 normalized/local routes correctly labeled.

### 2. Durable extension without competing lifecycles

Add `response/providers/` for models, enrollment, planner, bounded worker and adapters.
`ResponseJournalV2` embeds the nonsecret provider policy and native action ledger; keep
source policy/anchor v1 and recovery v2 unchanged. Explicit stopped-process migration
preserves every old hold/action/generation and marks old incidents local-only. Enroll a
validated draft through one snapshot commit. Draft edits do not change active authority.

Shared records deduplicate by exact binding/resource generation/action; enrollment forbids aliases for one canonical resource.
Notices instead deduplicate by incident/revision/destination generation. Journal reservation
covers all planned results before intake succeeds. The legacy cleanup lifecycle remains
owned by 005/006. Provider token revocation that cascades to leases triggers reconciliation
of those exact attempts; it never invents cleanup receipts or submits duplicate revokes
because an accessor vanished. Preserve unresolved records until reviewed resolution.

### 3. Identity enforcement

Current delegated access sends an external OAuth JWT directly to Vault. The concrete
agent-wide control is exact Agent Registry registration deletion, gated by installed
capability and actor/entity mapping. Registry absence is readback, not complete denial
proof. Entity disable is not substituted without demonstrated OBO semantics. Capture
verified actor identity in `broker.py` and match enrolled registry bindings before effects.

Exact native service-token revocation uses a prospectively owned accessor, including
exclusive descendant ownership. Persist a NativeTokenAcquisition intent before `VaultClient.workload_login` dispatch,
requiring trusted ownership on enabled live paths. Resolve it to a binding before exposing
the returned token; lost replies/unbound acquisitions remain uncertain without an accessor
and block complete inventory/release. Keep this separate from recovery lease models.
The ordinary OBO path has no native token: report not_applicable, not revoked. A root's
shared actor/external JWT cannot be revoked independently by deleting a shared registry
entry. Root-only incidents preserve the healthy peer and report that limitation.

User policies are separate definition-level rules: exact verified issuer/subject maps to
a Verify tenant user. Suspend that tenant record and revoke its login sessions with
independent readbacks. Commit a subject hold in response state so every live admission
for the mapped identity is denied and workspace watchers close matching sessions; anonymous
and other-user sessions disclose no user detail. Upstream IBMid remains unsupported by
these controls; issued JWT behavior is measured separately.

### 4. Secret and database remediation

Reuse exact dynamic lease cleanup. Existing provisioning revocation SQL already terminates
sessions for the generated DB role. Verify its installed configuration/readiness rather
than silently reprovision it. Dedicated live probes hold an independent old connection and
try fresh logins before/after cleanup, bracketed by a healthy control connection.

Implement exact static-role rotation, distinct from database root rotation. Readiness reads
role metadata/capabilities only. The proof adapter reads old/new values only into memory;
if scheduled rotation or missing pre-state prevents attribution, mark it inconclusive.
For an enrolled isolated static DB username, a separate adapter snapshots database/role/PID/
backend_start and rechecks immediately before parameterized termination. If exclusive role
ownership or direct connection visibility cannot be established, no termination is sent.
Pooled/shared users remain unsupported. Existing dynamic records do not acquire guessed
usernames or session IDs. Rotation never restores a previous value.

### 5. Coordination, locks and uncertainty

Local hold/cancel always precedes external work. Subject/definition holds use the short
control transaction and cannot be blocked by provider waits. Normal owners drain and
reconcile before cleanup/provider effects take the existing effect lock. Worker lifetime
locks and effect descriptors are inherited by trusted subprocesses, preserving 006 parent-
death semantics. Network response/persistence uncertainty remains uncertain even after
killing the child; a server may already have committed the request.

Canonical nested acquisition order is workspace maintenance ownership (maintenance only)
→ response worker ownership → recovery effect ownership → response control → recovery
journal. Do not hold control and journal simultaneously unless a reviewed existing helper
requires that order; never await a network call, drain, effect or root lock under control.
Root lifetime locks are tested nonblocking for quiescence, not waited on under a store lock.
Status/intake need only short control access. The ordinary runtime may already hold effect
when reading control, which is consistent with this order.

The provider attempt's 120s budget includes drain and selected actions; the existing 60s
local coordinator budget is not multiplied per adapter. First block new definition/user
access, then handle existing tokens/leases/sessions and rotation in declared dependencies.
Independent effects may proceed after another failure; required dependencies cannot be
skipped. At deadline, undispatched work remains planned/blocked and dispatched work is
uncertain. Subsequent automatic attempts may run only previously undispatched work within
the same immutable plan. Mutations never retry automatically; read-only reconcile is bounded.

### 6. Proof, notification, presentation and recovery

A separate validation adapter may bypass the local execution hold only for explicitly
authorized, fixed provider denial probes. It never grants a model or browser a bypass.
Before-state probes release effect ownership before waiting for containment; their inert
observation connections cannot run application tools. The validation coordinator obtains
the same effect ownership for every active acquisition/mutation, so waiting for an event
cannot deadlock the responder. This isolated test arrangement does not add a production
DB effect owner. Each credential probe persists a separate ProbeAcquisition intent before dispatch. A
definitive authenticated 401/403 without credential material closes that probe as
denied_no_issuance, without changing 005 production recovery or claiming native audit
proof. Transport/malformed/missing-handle ambiguity remains unresolved. Unexpected
success durably stores the handle in the probe record, then adopts it into exact recovery
through a trusted cross-store handoff that preserves original intent/ownership/time. Keep
the probe pinned until adoption and cleanup receipt are confirmed; crash cannot drop or
duplicate the handle. Never expose successful probe credentials to the caller. Verification
of the same unexpired JWT, fresh issuance, native-token use, DB old/new login, open-session
loss and user sessions are distinct observations with healthy controls.

Use Teams Workflows' URL-only trigger for this increment. The capability URL is private
secret material in `.local/response/provider-secrets.json`; no Authorization header or
new Entra credentials. Local enrollment pins the HTTPS destination; never follow redirects.
Cards contain only C14 fields. 2xx is accepted; only independently reviewed workflow/message
receipt establishes delivered. Timeout is uncertain; an explicit resend creates a new
notice revision and records duplication risk. Notification is advisory for containment and
release; notification evidence is still required for its native acceptance criterion.

`status` is disk-only. `readiness` and `reconcile` use read-only provider queries; they never
read credential values or perform negative issuance probes. New report schemas provide
closed reasons, responsible role, precise action and rerun command. Workspace only shows
safe owned summaries. Add native observations to existing private evidence import/review/
closeout conventions without changing 005 exact cleanup proof rules.

External restoration is guided/manual. Re-registering the same actor could revive an old
JWT, so supported release requires independently reviewed evidence that old minting stopped
and its complete maximum token lifetime plus clock skew elapsed. Missing a finite bound
prevents release. Changing actor identity/client configuration is NOT a supported 007
recovery route: existing response/recovery environment digests seal those settings and
006 has no configuration migration. A future explicit multi-store migration is required;
do not suggest reinitializing or deleting state. User reactivation
and provider re-registration do not occur from a local release command. State restoration
must be checked through enrollment and old/fresh access probes; release commits a fresh
generation and cannot resume a held root. Retry and recovery decisions are revision-bound.

## Compatibility and migration

- Add `agent respond migrate`, `providers prepare/enroll/readiness/reconcile/retry/import/probe`
  under the existing CLI; exact flags and exit behavior in [contracts/runtime.md](contracts/runtime.md).
- Existing response v1 status and exact cleanup remain readable; new admission requires
  explicit migration. Old binaries reject v2. Existing source-policy/environment changes
  remain unsupported without a future explicit migration; no reenrollment or state reset.
- No new environment variables. Reuse existing Vault/Verify authority settings. Store new
  Teams URL and any DB proof DSN only in the fixed private secret file, referenced by alias.
  The enrolled digest detects endpoint changes; secret rotation requires explicit validation.
- Existing browser schema fields remain compatible; provider/subject restriction summaries
  are additive. No browser admin endpoints, new frontend framework or new root package.
- No runtime changes belong in this planning commit. Implementation updates module/function
  comments, usage/configuration docs and ADR 0009 with the security ordering rationale.

## Project Structure

```text
specs/007-provider-remediation/
  spec.md plan.md research.md data-model.md quickstart.md tasks.md
  contracts/runtime.md checklists/{requirements,security}.md acceptance.json validation.md
src/agent/response/
  models.py store.py coordinator.py commands.py api.py guard.py native.py
  providers/{__init__,models,enrollment,planner,worker,vault,verify,database,teams,proof,report}.py
src/agent/{broker,vault,cli,observability,telemetry}.py
src/agent/recovery/store.py  # trusted probe adoption, existing schema/proof rules preserved
src/agent/workspace/{app,models,sessions,runs}.py
src/agent/workspace/static/{app.js,index.html,style.css}
src/agent/validation/{scenarios,importers,report,closeout}.py
config/providers.example.json
tests/test_provider_{models,migration,enrollment,native,planner,worker,vault,verify,database,teams,proof,cli,privacy}.py
tests/test_provider_{crash,concurrency,acceptance}.py
tests/browser/test_workspace_provider_response.py
scripts/{publish_policy,check_privacy,check_distribution}.py
docs/{usage,configuration}.md docs/adr/0009-provider-remediation.md
```

**Structure Decision**: Extend the response package; adapters share typed action/observation
contracts while existing recovery remains the sole lease lifecycle. Each story is independently
testable through enrolled synthetic bindings before native environment preparation.

## Implementation sequence

Foundation: schema/migration/enrollment, immutable plans and bounded execution. US1: native
projection/intake and replay controls. US2: Vault/Verify controls and subject admission. US3:
static rotation/session control and proof. US4: Teams, reports, evidence and deliberate
recovery. Finish adversarial tests, privacy/distribution checks, docs and honest live dispositions.

## Complexity Tracking

No constitutional exception. A journal version change and prospective inventory are necessary
to keep old binaries and restart from bypassing new holds. New SDKs, public hosting, arbitrary
mapping code, parallel live DB owners and blind retries were rejected.
