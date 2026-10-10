# Implementation Plan: Signed-in agent workflow

**Branch**: `feature/004-signed-in-workflow` | **Date**: 2026-10-09 | **Spec**: [spec.md](spec.md)
**Input**: `specs/004-signed-in-workflow/spec.md`
**Status**: Design only; implementation is explicitly deferred to the next model.

## Summary

Add `agent workspace`, a local browser UI backed by a separate optional FastAPI app. Reuse the
existing runtime, identity verifier, database broker, policy and Verify adapter. Server memory
holds bounded sessions and jobs; the browser gets an opaque cookie and safe status projections.
Authorization-code login uses PKCE, state and nonce. A fresh, verified subject token is selected
before each run, with enough lifetime reserved for cleanup. Approval retries execute one frozen
server-held simulated action with new identifiers; they do not replay the model task.

## Technical Context

**Language/Version**: Python >=3.12; static HTML, CSS and JavaScript with no frontend build chain.
**Primary Dependencies**: Existing Pydantic AI Slim 2.55.0, httpx, PyJWT, Pydantic; existing optional
FastAPI/Uvicorn `server` extra. No new runtime dependency. Add Playwright to a separate `browser`
development group, resolve and lock its version during implementation, and review transitive
licenses. Playwright is Apache-2.0; browser binaries remain test tooling outside distributions.
**Storage**: Process memory only; no token files, browser storage, persistent sessions or jobs.
**Testing**: pytest/pytest-asyncio, mock transports and deterministic models; Playwright WebKit.
**Target Platform**: Local macOS operator; Linux CI. One process, one loopback origin.
**Project Type**: Optional local web interface over the existing Python package.
**Performance Goals**: Visible state within 2 seconds using 1-second polling; ten deterministic
read workflows within their run budgets; one global active job including admission and cleanup.
**Constraints**: Four authenticated sessions, sixteen pending login/browser bootstraps, twenty
jobs per session, 8,000-character tasks, 32,000-character result summaries; no automatic effect
retry, no cross-session access, no remote serving. Exact constraints are in data-model.md.
**Scale/Scope**: One operator on one machine; local session history; existing simulated write and
delegated database read only. No chat conversation memory, provider administration or new connectors.

## Constitution Check

| Principle | Pre-research check | Post-design check |
|---|---|---|
| I. Slim runtime | Existing optional server boundary retained | Browser tooling isolated; no runtime dependency added |
| II. Trusted boundaries | Verified credentials and deterministic effects required | Separate access/ID validation, admission recheck, exact-action retry and negative tests |
| III. Secret isolation | No private inputs in artifacts | Memory-only tokens, opaque cookies, scoped asset allowlist, output/log canaries |
| IV. Evidence before acceptance | 003 gaps stay incomplete | Controlled browser tests separate from live observations; 15 criteria remain blocked |
| V. Bounded execution | Runtime and cleanup limits retained | Global admission gate covers cleanup; terminal approval invalidation; bounded state |
| VI. Reviewed delivery | Planning only | Tests, dependency review, threat review, privacy/build and CI tasks before delivery |

No design violation requires a constitution exception. Before a future merge, inspect actual
protection/review enforcement and satisfy the constitution or obtain a new explicit, recorded
owner exception. The PR #4 exception expired with that merge and does not authorize 004 delivery.
Planning and local implementation may proceed independently of that later delivery gate.

## Research decisions

See [research.md](research.md) for primary references and alternatives. The main integration gaps:

- OAuthClient supports code exchange but TokenResponse currently drops ID/refresh tokens; extend
  compatibly and add refresh grant. Login client settings must not replace the actor/exchange client.
- JWTVerifier validates access tokens only. Add separate OIDC ID validation with nonce and login
  audience; compare issuer/subject with the independently verified access token.
- Runtime generates its run UUID internally. Introduce a trusted run context so the workspace can
  register/contain the run before any work; reject reused IDs internally, never accept browser IDs
  as runtime authority. Existing callers continue to receive generated IDs by default.
- Verify currently collapses denial/failure/expiry to bool and leaves polling timeout pending.
  Add typed outcomes and atomic invalidation while preserving existing bool adapter entry points.
- Model output cannot establish approval, cleanup or effect completion. A memory status sink and
  trusted approval/effect facts determine workspace status and retry eligibility.
- Vault already shields cleanup. Normalize cleanup failures and drain cancelled cleanup tasks;
  retain credentials and admission ownership until cleanup terminates. Quarantine unresolved
  cleanup rather than admitting another job.

## Project Structure

### Documentation (this feature)

`spec.md`, `checklists/requirements.md`, `plan.md`, `research.md`, `data-model.md`,
`contracts/runtime.md`, `quickstart.md`, `tasks.md`, `acceptance.json`, `validation.md`.
Analysis is reported in the conversation without altering the analyzed artifacts.

### Source Code (repository root)

```text
src/agent/workspace/
  __init__.py
  app.py                 # separate FastAPI app, lifespan and routes
  auth.py                # login client, ID validation and renewal coordination
  models.py              # internal state and safe response models
  sessions.py            # bounded login/session registry and expiry
  runs.py                # global admission, ownership, deduplication and status sink
  security.py            # loopback, Host/Origin/CSRF and response headers
  static/index.html
  static/app.js
  static/style.css
src/agent/cli.py          # workspace command, optional import only
src/agent/settings.py     # three short login settings with legacy aliases
src/agent/oauth.py        # compatible token fields and refresh grant
src/agent/runtime.py      # trusted run context and exact-action entry point
src/agent/approval.py     # typed decision and atomic terminal invalidation
src/agent/capabilities.py # shared trusted approval/execution helper
src/agent/services.py     # typed Verify adapter bridge
src/agent/verify.py       # exact native decision classification
src/agent/vault.py        # bounded cleanup drain and classification
src/agent/broker.py       # exact read/cleanup stage projection
src/agent/observability.py# safe trusted lifecycle additions, if needed
src/agent/validation/     # compatibility mappings only where shared outcomes change

tests/test_workspace_models.py
tests/test_workspace_security.py
tests/test_workspace_auth.py
tests/test_workspace_sessions.py
tests/test_workspace_runs.py
tests/test_workspace_retry.py
tests/test_workspace_app.py
tests/browser/conftest.py
tests/browser/test_workspace.py
```

The existing `api.py` bearer `/runs` surface remains independent. Shared runtime changes must
retain its response schema. Assets use an exact publication allowlist and package resources;
no `chat/`, broad frontend tree, browser state, trace archive or screenshot is made publishable.

## Execution and state architecture

1. `agent workspace --port 8000` validates local configuration and binds `127.0.0.1` only. Print
   the workspace URL and exact callback; do not run an external browser automation service.
2. `GET /workspace/session` bootstraps an opaque browser cookie plus CSRF token; `POST /auth/login`
   returns the trusted authorization URL for browser navigation. The single-use callback creates a rotated
   authenticated session. ID and access tokens are never returned to browser JavaScript.
3. Job admission reserves the global slot, locks session renewal, verifies freshness and lifetime,
   allocates IDs, stores the immutable submission and starts one task. A failed admission frees
   the slot. Duplicate same-key/same-body submissions return their original job.
4. One workspace-owned Runtime preserves process-wide policy/containment; its event sink is
   selected only while the global job gate is held and reset after drain. Each job has a
   credential snapshot, runtime context, bounded status sink and immutable task
   payload. Refresh reads status only. No cookies are accepted by the existing bearer API.
5. Sign-out/expiry immediately disables session admission, contains the run, invalidates approvals
   and cancels execution. Cleanup keeps its credential snapshot. The busy gate is released only
   after cleanup terminates; a surviving cleanup task quarantines the process against new work.
6. A typed unconfirmed approval may produce a retry candidate only with exactly one frozen action,
   zero simulated writes, zero uncertain other effects, and complete cleanup. The retry handler
   atomically consumes that candidate and runs the trusted action helper under new identity checks.
7. Session/result memory is discarded on sign-out or expiry after drain. Restart has no recovery
   or replay. Local sign-out does not claim provider-wide token/session revocation.

## Implementation sequence

Foundation contracts and publication boundaries → US1 login/session → US2 jobs/UI → US3 typed
approval and explicit retry → US4 complete database workflow → software validation and separate
live/delivery records. Tests precede security-sensitive changes. Browser tests use in-process
service fixtures and local test servers; no production bypass flag exists.

## Validation strategy

Negative auth/CSRF/ownership tests, deadline and race tests, exact effect counts, secret canaries,
WebKit keyboard/status/reload tests and packaged asset checks are required. Ten deterministic read
workflows prove the bounded path. Full existing tests, lint/format, all-feature/runtime gates,
privacy/history, offline validation/demo, build and distribution checks remain required.
Live login/read observation is attempted only with configured authorized services. If unavailable,
record the stage/owner and leave that live task open while completing software work. Phone pushes
require an individually selected operator action; CI never sends them.

## Complexity Tracking

No constitution exception. Memory-only sessions avoid database/encryption/keychain provisioning;
plain bundled assets avoid frontend dependencies. Exact-action retry requires a trusted runtime
entry point because whole-task replay could repeat unrelated tools. That additional seam is bounded
to the existing simulated restart and does not expose a generic browser effect executor.
