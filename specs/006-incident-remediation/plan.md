# Implementation Plan: Incident containment and exact cleanup

**Branch**: `feature/006-incident-remediation` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)
**Input**: `specs/006-incident-remediation/spec.md`

## Summary

Implement the first Function 10 increment with a small private response coordinator:
trusted signal intake, durable root/definition holds, prospective credential ownership,
exact cleanup reconciliation, safe status, and operator release. Reuse 005 recovery
instead of introducing another credential lifecycle. Native VIP, external JWT/user
blocking, static-secret rotation, notifications, and shadow enrollment remain follow-ons.

## Technical Context

**Language/Version**: Python 3.12+; existing plain browser JavaScript.
**Primary Dependencies**: Existing Pydantic, httpx, PyJWT, optional FastAPI/Uvicorn,
Pydantic AI Slim and pytest/Playwright; no new dependency or lockfile change expected.
**Storage**: Owner-only atomic JSON snapshots under `.local/response/`; recovery
JournalV2 under existing `.local/recovery/`; advisory locks, fsync, strict schemas.
**Testing**: Deterministic pytest, controlled subprocess/crash tests, WebKit. Live
provider calls only in explicitly authorized optional validation.
**Target Platform**: Existing single-host macOS/Linux workspace; loopback response
service. No public hosting, multi-host consensus, or Windows flock portability work.
**Project Type**: Python CLI/runtime with optional browser and bearer services.
**Performance Goals**: 2s durable-intake response, 2s local cancel request under tested
healthy storage, 250ms watchers; 60s per incident worker, 10s provider calls.
**Constraints**: Existing single live effect owner, no duplicate network effects,
exact attributable cleanup, fail-closed storage, no secret-bearing event/report payloads.
**Scale/Scope**: One configured workload definition, up to 16 trusted source mappings,
16 queued/non-settled incidents, 1000 retained roots/incidents; exact C01–C20 limits.

## Constitution Check

Reviewed before research and after design; no design exception requested.

| Principle | Design disposition |
|---|---|
| I. Slim runtime | Existing packages/extras only; tenant mappings private; offline baseline remains usable |
| II. Trusted boundaries | Verified source JWT and private policy authorize intake; trusted root binding and every-effect guards; no model-selected authority |
| III. Secret isolation | Fixed private stores, strict public projections, no tokens/raw sources in telemetry or publication |
| IV. Evidence | Software tests, live observations and native acceptance separate; no automatic manifest promotion |
| V. Bounded execution | Queue/storage/network limits, independent cancellation path, durable effects and uncertainty |
| VI. Reproducible delivery | Traceable negative/crash/browser tests, migration guide, source/function comments, focused review and CI |

Maintainer review and required branch protections remain pre-merge requirements. The
last observed main branch lacked server-side protection; planning does not change or
waive that condition. Confirm current protections and review at delivery; no merge is
part of this request. Development-tier audit absence is a documented environment limit,
not a constitution exception or completed acceptance criterion.

## Architecture and boundaries

1. **Private response store**: `response/models.py` and `store.py` own source policy,
   run bindings, generation holds, incidents/actions, reservation limits, retention and
   strict atomic snapshots. Independent short control.lock prevents active work from
   blocking the very signal that must cancel it. Initialization is explicit.
2. **Intake**: `response/auth.py` uses existing OAuth/JWT components with the response
   audience and exact source mapping. `response/api.py` exposes only loopback incident
   submission/status; it has no browser cookies, CORS, model tools or remote release.
   A trusted external relay, if later deployed, owns TLS and vendor translation.
3. **Guard and watcher**: `response/guard.py` registers roots from verified context,
   acquires per-root lifetime locks and checks holds/generation across all live runtime
   entry points. A 250ms task cancels affected work and invalidates approvals. Child
   delegation inherits root identity. Every new effect checks durable control state.
4. **Recovery v2**: Add immutable ownership before `RecoveryStore.begin` persists
   intent. Retain v1 anchor/receipts/public projections; migrate only the state snapshot.
   Admission rejects v1 without issuing credentials; old cleanup commands still work.
5. **Coordinator**: `response/coordinator.py` commits containment first and queues a
   bounded worker. It waits for ordinary owners to finish; confirms their existing
   cleanup receipts; then acquires effect ownership and calls exact 005 cleanup only
   when configured. It stores submitted intent before each provider operation. It never
   acquires credentials or delegates an LLM to choose remediation.
6. **Operator actions**: `agent respond init/submit/status/reconcile/release/serve`
   provide private administration. Reconcile reads durable receipts and normalizes
   abandoned ownership; it does not retry provider calls. Existing `agent recover
   revoke/import` are explicit recovery actions for uncertain cleanup. Definition release
   is local-only, generation/revision checked, and cannot resume old roots.
7. **Presentation**: Browser operations and job views receive additive safe containment
   summaries for owned roots. The anonymous view shows only an aggregate restriction.
   Workspace does not administer incidents or accept an admin credential. Job history
   stays unchanged. CLI reports show each control outcome and valid measured timings.

### Admission and effect ordering

All live workspace, CLI, batch, bearer API, direct trusted broker and live-validation
paths require response enrollment, current mapped policy, and registered ownership.
Offline demo/synthetic suites inject in-memory guards and remain credential/network-free.
Identity verification precedes root registration; registration precedes model execution.
A contained identity cannot bypass the guard with another profile of the same workload.

Guard checks occur at admission, before/after model requests, before delegation,
approval consumption, after awaited actor/delegated token verification, immediately
before credential HTTP dispatch and immediately before SQL. Reads/checks may happen
while effect ownership is held, but never await that ownership under control.lock.
Containment that commits after an effect's final guard cannot cancel its past dispatch;
that operation's eventual handle/result must be reconciled. Cleanup uses the original
ownership under separate cleanup authorization and bypasses the execution-deny guard.

Watchers operate in every live owning process, not just the response service. A dead
owner's OS lock can be acquired only after its production child workers exit: pass the
applicable root/effect lock descriptors into those workers and never explicitly unlock
before drain. Matching unresolved attempts remain blocked. A process
that cannot read control state latches a local block and cancels its work. Response
server startup does not adopt effects already submitted by an old worker.

### Release and configuration changes

Only the local CLI can release a definition. It acquires nonblocking effect ownership,
then control.lock, verifies all targeted run lifetime locks are free, rereads current
journals and the complete hold set, and commits the next generation. A new incident or
root registration racing release causes serialization or revision rejection. Because
registration checks the same control lock, no old-generation run may enter the gap.
Root holds remain terminal; pruning old terminal roots never makes their IDs reusable.
New runs are always allocated by the host, not accepted from caller input.

Policy digest/environment mismatch blocks new work and response mutation; existing
known-handle recovery stays available through original configuration. No automatic
policy migration, force reset, or external enablement is provided in this increment.
Enrollment records configured versus not_configured recovery. In the latter mode only,
reconcile/release use root/control ownership and cleanup is not_applicable. Missing
previously configured state never bypasses recovery. Cross-store retention pins roots
for unresolved attempts and recovery records matching non-settled incident scopes from
durable intake, including before cleanup actions exist; also pin receipts referenced
by unconfirmed response actions. Hold
effect then control ownership while deciding pruning, and retain on corrupt references.

## Threat and boundary review

Untrusted: relay body, model/task content, browser requests, provider responses, private
files until validated, and concurrent processes. An authenticated source still needs
an exact configured scope and definition; run IDs must resolve to the trusted registry.
Cross-source event collisions, target injection, giant bodies, stale timestamps, JWT
confusion, SSRF destinations, replay and capacity exhaustion have explicit rejection paths.

Automatic cleanup must be explicitly enabled in private policy and uses separate
existing Vault operator authority. Deployments should minimize that token's privileges
using provider-supported ACLs; local exact-handle selection does not itself prove a
provider-enforced per-lease ACL. Broad demo admin tokens confer no extra selectable
operation. Admin credentials never flow into runtime delegation or the model. No provider
policy changes, registry deletion, user suspension, rotation, or notification adapter
is part of 006. Reusing `VaultClient` does not misclassify administrative cleanup as
credential acquisition in telemetry; give response actions their own safe observer events.

Storage protects against accidental corruption/concurrency, not a hostile local admin
rewriting all files/code. Recovered legacy records stay unattributed. Missing native
proof cannot be replaced by operator acknowledgment, a TTL guess, or an empty lookup.
Provider HTTP completion and source-system audit linkage remain separate evidence.

## Compatibility and migration

- `agent recover migrate` is a new explicit offline command. Stop workspace/response
  processes before migration. Anchor/receipt v1 stays unchanged; state becomes v2 via
  one atomic replacement. V1 status/import/revoke continue for recovery; new issuance
  requires v2 and the trusted ownership supplied by the runtime.
- `agent respond init --prepare` creates a private draft with current definition,
  issuer and environment digest; a relay operator supplies trusted source mappings.
  `agent respond init` enrolls prospective roots and validates the completed policy.
  Local_only mode needs no relay identity; relay mode requires explicit source mappings.
  A v1 recovery state must be migrated first when database access is configured. No
  arbitrary root-path flags or `reset` commands are added.
- All live entry points now require response enrollment, including non-database tasks;
  return a concrete initialization instruction. Offline demo and deterministic tests
  remain independent. Public CLI/task flags remain valid.
- No new environment variables are required. `VAULT_TOKEN` remains optional for automatic
  cleanup; ordinary delegated reads never fall back to it. One private JSON policy holds
  source mappings, response audience, definition/environment binding and cleanup opt-in.
- Existing browser schemas retain version 1; containment fields/routes are additive.
  Normal sign-out/session expiry behavior continues; no recovery operation recreates a
  session. Default host remains loopback; port defaults to 8002 for response service.

## Project Structure

```text
specs/006-incident-remediation/
  spec.md plan.md research.md data-model.md quickstart.md tasks.md
  contracts/runtime.md checklists/{requirements,security}.md
  acceptance.json validation.md
src/agent/response/
  __init__.py models.py store.py auth.py guard.py coordinator.py commands.py api.py
src/agent/recovery/{models,store,lifecycle,commands,workers}.py
src/agent/{runtime,security,capabilities,broker,cli,api,observability,telemetry}.py
src/agent/validation/scenarios.py
src/agent/workspace/{app,models,runs}.py
src/agent/workspace/static/{index.html,app.js,style.css}
config/response.example.json
scripts/{publish_policy,check_privacy,check_distribution}.py
tests/test_response_{models,store,migration,auth,intake,guard,coordinator,cli,crash,privacy}.py
tests/test_{broker,adapters,api,runtime,validation_scenarios}.py
tests/browser/test_workspace_containment.py
docs/{usage,configuration}.md
docs/adr/0008-incident-containment.md
```

**Structure Decision**: A focused coordinator package; reuse credential cleanup rather
than add a second provider credential system. Keep source adapters behind the relay
contract until real vendor configuration is known. Existing packaging already includes
`src/agent`; example configuration is a maintained artifact, never live mapping data.

## Implementation sequence

Foundation: strict policy/models, durable store, recovery migration, root ownership.
US1: authenticated intake, held definitions/root cancellation, every-effect guards.
US2: drain/cleanup coordinator, uncertain-action reconciliation and bounded restart.
US3: private report, operator release, browser summaries and timing. Finish security,
publication, regression, documentation and a separately labeled live disposition.

## Complexity Tracking

No design exception. Durable state, root lifetime locks and a separate worker are
necessary for restart-safe cancellation and exact ownership. Distributed queues,
new database dependencies, broad provider administration, a new frontend framework,
and automatic replay/re-enablement were rejected as outside this increment.
