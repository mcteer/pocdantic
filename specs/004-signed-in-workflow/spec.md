# Feature Specification: Signed-in agent workflow

**Feature Branch**: `feature/004-signed-in-workflow`
**Created**: 2026-10-09
**Status**: Clarified; ready for planning
**Input**: Add browser sign-in, task submission and visible results/status, clear approval failures
with an explicit retry action, and one complete read-only task through the existing agent and
database. Complete specify, clarify, plan, tasks and analyze; stop before implementation.

## Clarifications

### Session 2026-10-09

- Q: Should sign-in, task submission and results all happen in a local browser page? → A: Local browser workspace.

## User Scenarios & Testing

### User Story 1 - Sign in and stay ready (Priority: P1)

An operator starts a local workspace, signs in with the configured identity provider and can
run tasks without copying credentials. The workspace explains when sign-in is needed again.

**Why this priority**: Repeated manual token copying and expiry interrupted the live workflow.
**Independent Test**: Complete sign-in, renew a short-lived credential, then sign out against a
controlled identity service, without any model, database or phone calls.
**Acceptance Scenarios**:
1. Given a configured workspace, when the operator selects Sign in and finishes provider login,
   then the workspace shows a verified signed-in state and enables task submission.
2. Given a renewable session, when a new task needs fresh credentials, then renewal occurs
   without copying a token; failed renewal shows Sign in again and starts no task. If the
   refreshed credential is still too short for execution and cleanup, the workspace explains
   the configuration problem and starts no run.
3. Given sign-out, expiry or restart, when an old session is used, then protected work is refused.
4. Given a forged, replayed or unrelated login completion, then no signed-in session is created.

### User Story 2 - Run a task and inspect its result (Priority: P1)

The signed-in operator submits one task, sees progress, and reads the result or a concrete next
step on failure. Refreshing the page must not submit the task again.

**Why this priority**: Turns the existing harness into a repeatable usable workflow.
**Independent Test**: Run a deterministic read task through the workspace and inspect its result;
reject duplicate submissions and attempts to inspect another session's work.
**Acceptance Scenarios**:
1. Given valid identity and configuration, when a task is submitted, then one bounded run starts
   and its status becomes completed, denied, failed or interrupted.
2. Given a completed task, when the page is refreshed, then the existing result remains visible
   within the same local session, without rerunning the model or tools.
3. Given a second submission while one run is active, then the workspace explains it is busy and
   starts no additional run. Sign-out cancels active work and allows credential cleanup.
4. Given an unavailable integration or model, then the workspace identifies the failed stage and
   supplies a safe, concrete next action rather than raw provider text.

### User Story 3 - Understand and retry approval failures (Priority: P2)

The operator can tell whether a privileged simulated action is awaiting a decision, was denied,
or received no confirmed decision. A retry is a deliberate new attempt.

**Why this priority**: A phone application error must not be mistaken for a denial or approval.
**Independent Test**: Drive controlled approved, denied, pending, failed and expired outcomes;
prove no uncertain attempt performs a privileged effect and no duplicate retry sends two prompts.
**Acceptance Scenarios**:
1. Given an approval request, then the workspace shows the requested simulated action and that a
   phone decision is awaited; confirmed denial is distinguished from an unconfirmed decision.
2. Given a timeout or provider failure with no confirmed decision, then no write occurs, the old
   attempt becomes terminal, and a retry is available only after cleanup finishes.
3. Given explicit retry, then one new run requests a fresh approval for the same frozen action;
   the old approval cannot authorize it. Successful or explicitly denied actions are not retried.

### User Story 4 - Demonstrate a complete database read (Priority: P2)

The operator signs in, requests an allowed read through the existing agent, sees the result and
can inspect safe run correlation and cleanup status.

**Why this priority**: Proves the workspace connects the already implemented components.
**Independent Test**: A deterministic full workflow proves read and cleanup contracts; a separately
recorded live walkthrough uses configured services when available.
**Acceptance Scenarios**:
1. Given a permitted read, then the agent reads using delegated authority and releases its leased
   credential before reporting a successful result.
2. Given missing permission, invalid identity or failed cleanup, then the result is denied or
   failed as appropriate; the workspace never substitutes synthetic success.
3. Given an external service failure, then the walkthrough records the exact blocked stage and
   software delivery can proceed with that live evidence explicitly incomplete.

### Edge Cases

Expired sign-in; provider login cancellation; refresh rotation or rejection; concurrent tabs;
double-click and network retry; old login callbacks; malicious cross-site submissions; stolen or
unknown run identifiers; model/tool content containing markup; late approval after timeout;
application restart; disconnect; shutdown during credential cleanup; unavailable optional extras.

## Requirements

### Functional Requirements

- **FR-001**: Provide a local single-operator workspace with sign-in, task input, status, result
  and sign-out. Start-up explains missing configuration before opening a broken workflow.
- **FR-002**: Complete provider sign-in using verified credentials and bind login completion to
  the initiating browser; reject forged, expired, replayed or mismatched login responses.
- **FR-003**: Keep access and renewal credentials in trusted server memory only. Renew before a
  new run when supported; otherwise require sign-in again. Never submit or replay a task as part
  of sign-in or renewal, and never renew credentials in the middle of a run. Admit work only when the credential has
  sufficient remaining lifetime for execution and cleanup.
- **FR-004**: Recheck identity and expiry at run admission and preserve existing deterministic
  policy, delegated authority, approval binding, containment and cleanup controls.
- **FR-005**: Support sign-out, bounded idle/absolute session expiry and restart invalidation;
  cancel active work before discarding the credentials needed for cleanup.
- **FR-006**: Submit one task at a time with explicit status and session-owned result retrieval.
  Duplicate delivery of the same submission must return the same run without another effect.
- **FR-007**: Bound task size, retained results, concurrent work and execution time. Refresh or
  reconnect retrieves status; it does not resume or replay execution after server restart.
- **FR-008**: Present plain-language errors and concrete next actions for sign-in, configuration,
  model, database, approval and cleanup failures, without raw provider responses or secrets.
- **FR-009**: Show approval waiting, confirmed approval, confirmed denial, and unconfirmed decision
  distinctly. Only a trusted matching approval may authorize the exact privileged action once.
- **FR-010**: Allow deliberate retry only for a terminal unconfirmed approval attempt after
  cleanup. Freeze the action, rerun authorization and request fresh approval without rerunning the original model task; prevent duplicate
  retries, reuse of old decisions and automatic retry of uncertain effects.
- **FR-011**: Isolate local sessions and reject cross-site changes, arbitrary destinations and
  remote access. Render task/results as inert text and avoid credential-bearing browser storage.
- **FR-012**: Provide the existing delegated database read through the workspace, preserving
  exact lease cleanup and safe request/run correlation. Live evidence remains distinct from
  deterministic verification and from customer acceptance.
- **FR-013**: Preserve existing CLI, bearer HTTP and validation workflows and optional service
  dependencies. Keep setup concise and use short configuration names with clear defaults.
- **FR-014**: Provide keyboard-operable controls, visible focus, readable errors and announced
  status changes, including signed-out, running, waiting, terminal and empty-result states.
- **FR-015**: Validate security boundaries with negative tests and the complete browser workflow
  with automated browser checks. Keep tests free of customer credentials and live service effects.
- **FR-016**: Record software completion separately from live walkthrough and repository delivery.
  Existing 003 vendor blockers do not block the new workflow's software build or become passes.

### Key Entities

- **Login attempt**: Browser-bound, short-lived, single-use sign-in transaction.
- **Workspace session**: Verified identity, server-held credentials and bounded lifetime.
- **Workspace run**: Session-owned task, submission identity, progress, safe result and cleanup.
- **Approval attempt**: Frozen action, requesting identity/run, expiry and trusted decision;
  linked to an earlier attempt only when retry was explicitly selected.
- **Workflow observation**: Safe status and correlation; not an independent acceptance decision.

## Success Criteria

### Measurable Outcomes

- **SC-001**: A configured operator reaches a signed-in workspace with one Sign in action plus
  provider interactions and no credential copying; supported renewal needs no further action.
- **SC-002**: In controlled browser tests, submission acknowledgment and visible state changes
  occur within two seconds of their server-side event; all ten repeated read workflows
  complete within the configured runtime budget, with no leaked leases.
- **SC-003**: All tested invalid login, session, cross-site, cross-session, duplicate and stale
  approval cases produce zero unauthorized effects and zero exposed credential values.
- **SC-004**: Each approval outcome has an unambiguous user-facing state; one explicit eligible
  retry creates one new attempt, and a late old decision never executes the action.
- **SC-005**: A full read workflow covers sign-in, task, result and cleanup; live service gaps are
  recorded by stage and owner without changing the fifteen existing customer dispositions.
- **SC-006**: Existing software gates and base installation remain valid, and the whole new
  workflow is operable with the keyboard in the automated browser suite.

## Assumptions

- Initial delivery runs on the operator's computer; shared hosting, multi-user deployment,
  mobile UI, provider administration and production infrastructure writes are outside 004.
- Sign-in, task submission and results all use a local browser workspace, as selected by the operator.
- The configured identity provider can issue access tokens already accepted by the runtime.
  Renewal is conditional on provider support; graceful reauthentication is mandatory.
- Task history lasts only for the current local session/server lifetime; no durable chat history.
- Existing database integration and simulated infrastructure action are reused. No new target
  connector, replacement phone application, Vault tier upgrade or acceptance automation is added.
- Security tests precede security-sensitive implementation; all new behavior receives meaningful
  tests. Live walkthroughs record limitations and do not gate otherwise verified software.
