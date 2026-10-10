# Implementation Plan: Operational reliability

**Branch**: `feature/005-operational-reliability` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)
**Input**: `specs/005-operational-reliability/spec.md`

## Summary

Add factual diagnostics and guided recovery to the local browser workspace. Put a
private durable journal at the shared database credential boundary, so a lost response
or restart cannot erase an unresolved attempt. A separate operator CLI can establish
exact cleanup proof while the browser retains its valid session. Recovery never
replays a task, changes provider settings, or grants user authority.

The user also requested a root `AGENTS.md` on this branch. That companion documentation
is already drafted, linked from `CONTRIBUTING.md`, and allowed by an exact root-file
publication rule. Its credential-leak regression passed with the publication suite
(26 tests). It is a contributor-documentation change, not implementation of this plan.

## Technical Context

**Language/Version**: Python 3.12+, existing plain JavaScript/CSS browser assets.
**Primary Dependencies**: Existing Pydantic AI Slim, Pydantic, HTTPX; existing optional
FastAPI/Uvicorn and psycopg. No new dependency or frontend framework.
**Storage**: New bounded JSON recovery snapshot under project-root `.local/recovery/`,
stdlib filesystem locks and atomic durable replacement. Existing sessions remain memory-only.
**Testing**: pytest/pytest-asyncio, subprocess crash injection, controlled HTTP transports,
Playwright/WebKit, existing publication and distribution gates.
**Target Platform**: macOS and Linux on a local filesystem supporting `flock`, atomic
replacement, file fsync, and directory fsync; remote/network filesystems unsupported.
**Project Type**: Python runtime/CLI with optional local browser workspace.
**Performance Goals**: Diagnostics 10 seconds per check, 30 seconds total; one active
check per workspace; operator provider calls 10 seconds each, 30 seconds per command.
**Constraints**: No browser admin authority; no persisted authentication secrets; exact
lease cleanup; fail closed on ambiguous proof, storage failure, and configuration mismatch.
**Scale/Scope**: One workspace process and one live database effect per state root;
1,000 retained attempts maximum, 2 MiB journal maximum, 100 unresolved attempts maximum.

Research resolved the native-proof format, synchronous revocation, storage/lock design,
diagnostic bounds, and initialization/migration choices. See [research.md](research.md).

## Constitution Check

Pre-research assessment against constitution 1.2.0: the proposed scope preserves all
six principles; native proof and durable storage required research before design approval.
Post-design assessment: PASS for implementation planning with the controls below.

| Principle | Design and verification |
|---|---|
| I. Slim runtime | Stdlib persistence, existing extras, no dependency/lock changes planned. |
| II. Trusted boundaries | Journal at trusted broker; strict evidence verifier; exact sync cleanup; no new browser authority; negative tests. |
| III. Secret isolation | Private identifiers only; no persisted tokens/passwords or raw responses; public projections; source and distribution review. |
| IV. Evidence | Synthetic results separate from native acceptance; no automatic acceptance.json promotion; absent native linkage stays blocked. |
| V. Bounded execution | Serialized effects, bounded checks/storage/imports, cancellation containment, no issuance retries, confirmed cleanup. |
| VI. Delivery | Traceable tasks and tests, migration notes, owner boundary review, full offline CI and privacy gates before delivery. |

Existing delivery condition: main lacked required branch protections at the last merge.
This plan does not waive that constitution requirement or reuse the expired 004 merge
direction. Before a later PR can merge, verify required `validate`, PR review, stale
approval dismissal, and force-push/deletion prevention, plus actual maintainer review.
No merge, provider change, or protection change is part of this planning request.
Implementation and evidence disposition can finish independently of a later delivery gate.

## Architecture and boundaries

1. `recovery/store.py` owns initial enrollment, snapshot validation, durable transitions,
   retention, and locks. Resolve the root once using the existing project-root convention;
   all entrypoints use the same `.local/recovery` root. Tests inject isolated roots through
   constructors. Add no environment variable and no user-facing alternate-root flag.
2. `recovery/lifecycle.py` is injected into the shared live `DatabaseBroker` and
   `VaultClient.credentials` path. Acquire the environment effect lock, validate the
   journal gate, and persist intent before the credential GET. Persist any returned
   handle before SQL. Persist cleanup intent and completed synchronous cleanup before
   resolving. Acquisition has no automatic retry, even though its HTTP method is GET.
3. `recovery/proof.py` accepts bounded private native records with a versioned strict
   schema. It requires exact environment, path, operation, IDs, and evidence digest
   agreement. Existing 002/003 permissive correlation is not recovery authorization.
4. `agent recover` provides initial enrollment, safe status, strict evidence import/review,
   and explicit exact-lease synchronous cleanup. It uses a separately supplied operator
   token only in that short-lived process. The browser only reads verified durable state.
5. `workspace/diagnostics.py` validates configured prerequisites and performs bounded
   unauthenticated reachability checks. It uses fixed known targets from Settings,
   no browser-selected URLs, no database password attempts, and no credential issuance.
6. Workspace operational status separates authentication, connection observations, and
   recovery. Login is blocked only by active work, not by recovery quarantine. New task
   admission reads the durable journal and still performs normal identity/policy checks.
   Recovery never mutates the old job's result or reconstructs discarded sessions.

A workspace without a configured database integration keeps its existing non-database
behavior and reports recovery as not_configured. Enrollment is needed when live database
access is configured. An existing unresolved journal still blocks that workspace even if
database settings are removed; disabling configuration is not recovery.

All live database entrypoints (workspace, `run`, `batch`, bearer `/runs`) share this
credential gate; they cannot bypass it by avoiding the browser. Offline demo/synthetic
validation remains independent. This does not redesign the bearer API or add its UI.
An entire workspace is blocked for new jobs while its shared journal has unresolved
incidents, even if a selected profile would not access the database; CLI/API effects
are additionally contained at the database boundary.

Known-handle recovery needs a successful synchronous exact-lease revocation receipt.
Unknown-handle recovery needs a unique native audit pair to identify the lease first,
or a documented pre-execution ACL denial proving non-issuance. Generic errors, missing
records, TTL expiry, or an absent database role do not prove either outcome.
No audit export means unknown-handle recovery remains unsupported in that environment.

## Compatibility and migration

- Add `agent recover init` as explicit prospective enrollment before any live database
  acquisition. Existing CLI flags and bearer routes remain; uninitialized state returns
  a safe initialization-required error with that command. Offline commands are unchanged.
- Missing state blocks instead of auto-initializing. Existing partial/damaged state cannot
  be replaced by `init`; no force/reset/acknowledge-to-clear option is provided.
- Enrollment establishes coverage for subsequent operations only. It does not resolve or
  import the two historical 004 attempts, which remain unclosed in their validation ledger.
  Never recommend initialization or deletion as a recovery action for a recorded incident.
- Add `sync=true` to cleanup requests and narrowly bind that parameter in delegated
  authorization and the provisioning policy/schema. Deployment policy updates are manual,
  separately authorized work; incompatible providers/policies remain safely blocked.
- Existing workspace response fields remain valid; new optional operational fields and
  routes are additive. Existing job error codes keep working, with new closed reason codes
  for recovery. Details are in [contracts/runtime.md](contracts/runtime.md).
- Changing configured Vault/database/workload targets with unresolved state is rejected.
  Version 1 has no automatic environment migration; operator must retain/restore the
  original configuration to reconcile it. This limitation is documented, not bypassed.

## Threat and boundary analysis

Untrusted inputs include model output, browser requests, provider error bodies, native
artifact content, and concurrent processes. Model/browser input cannot select recovery
paths, handles, proof outcomes, or admin credentials. Imported artifacts are untrusted
until schema, identifiers, uniqueness, provenance review, and digest checks pass.
The reviewer is the local operator, as in existing evidence review; this is not a
cryptographic attestation of provider provenance or reviewer identity.

Use owner-only directories/files, reject symlinks, hardlinks and nonregular files,
validate identity before replacement, and serialize journal updates. Hold an effect lock
through cleanup, including surviving cleanup workers. Cleanup still runs with in-memory
handles if persistence fails, but no durable success is invented. Persist no authority
needed to resume a task. Signed-out clients lose protected incident details.

A malicious administrator who deletes all state and reenrolls, edits trusted code, or
uses a different installation is outside this local containment claim. Local storage
is crash-safe, not rollback-proof or a centralized cross-host policy service. A source
artifact never supplies a destination URL; all network targets come from trusted config.

## Project Structure

### Documentation (this feature)

`specs/005-operational-reliability/` contains spec, checklist, plan, research, data model,
contracts/runtime.md, quickstart, tasks, acceptance.json, and a sanitized validation ledger.

### Source Code (repository root)

```text
src/agent/recovery/                 # new models, store, lifecycle, proof, commands
src/agent/workspace/diagnostics.py  # new read-only checks and safe guidance
src/agent/workspace/{app,models,runs}.py
src/agent/workspace/static/{index.html,app.js,style.css}
src/agent/{cli,broker,vault,api}.py
config/vault-path-access.schema.json
scripts/provision_database.py
tests/test_recovery_{models,store,lifecycle,proof,cli}.py
tests/test_workspace_diagnostics.py
tests/test_recovery_{crash,privacy}.py
tests/recovery_support.py
tests/test_workspace_{app,runs,auth,security}.py
tests/test_{broker,adapters,api,publication}.py
tests/browser/test_workspace_{diagnostics,recovery}.py
docs/{usage,configuration}.md
docs/adr/0007-operational-recovery.md
```

**Structure Decision**: Small shared recovery package beneath the existing runtime;
workspace-specific presentation stays in the workspace package. Reuse private-file
primitives where their guarantees match, not the older evidence acceptance semantics.

## Implementation sequence

Foundation establishes models, secure storage, and shared credential containment. US1
adds diagnostics; US2 adds operator proof and browser recovery; US3 verifies and hardens
restart/concurrency/retention. Finish documentation, offline gates, security review, and
an honest live-validation disposition. Story tests and explicit coverage are in tasks.md.

## Complexity Tracking

No design exception requested. Durable state and three narrow locks are justified by
crash containment, concurrent entrypoints, and recovery without restarting the browser.
A privileged HTTP recovery endpoint, background retries, and provider auto-repair were
rejected because the local operator CLI meets the clarified scope with less authority.
