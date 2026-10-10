# Feature Specification: Operational reliability

**Feature Branch**: `feature/005-operational-reliability`
**Created**: 2026-10-10
**Status**: Clarified; ready for planning
**Input**: Proceed with specification, clarification, planning, tasks, and analysis for clear connection diagnostics, safe recovery from uncertain credential acquisition, and fewer unnecessary sign-ins in the local browser workspace.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Understand a blocked workspace (Priority: P1)

As a workspace user, I want a failure to tell me what failed, what is known, and exactly what to do next, so I can recover without guessing at provider menus or repeatedly signing in.

**Why this priority**: Feature 004 encountered a healthy-looking database with a network ban. A generic credential failure obscured both the connection problem and the separate uncertainty about credentials issued during the failed request.

**Independent Test**: Present controlled connection, authorization, expiry, and unknown failures and verify the browser gives the correct safe explanation and action without creating credentials or running a task.

**Acceptance Scenarios**:

1. **Given** an interrupted credential request, **When** I view the workspace, **Then** it identifies the failed stage, states that issuance is uncertain, and explains that restored connectivity alone cannot clear the block.
2. **Given** only a provider timeout, **When** diagnostics finish, **Then** they describe a timeout and possible next checks without asserting that a network ban has been confirmed.
3. **Given** provider repair is needed, **When** I open its instructions, **Then** I see a concrete supported navigation path or configured provider link and the expected result; unavailable access is stated explicitly.
4. **Given** an expired sign-in and a separate recovery block, **When** I view status, **Then** both are shown and the next action does not misleadingly suggest that signing in clears the recovery block.

### User Story 2 - Recover safely and continue (Priority: P1)

As an operator, I want to check whether an interrupted operation has been safely resolved, then let the user submit a new task while retaining any still-valid sign-in.

**Why this priority**: Recovery must distinguish a working connection from proof that temporary access was never issued or has been removed.

**Independent Test**: Supply controlled provider evidence for a known credential, a correlated failed issuance, and an unresolved issuance. Only sufficient evidence clears the corresponding block; an existing failed task is never replayed.

**Acceptance Scenarios**:

1. **Given** an exact temporary-access handle and authorized cleanup capability, **When** recovery confirms removal, **Then** that incident is resolved and the original task remains failed or canceled.
2. **Given** issuance with no returned handle, **When** authoritative evidence identifies all access created by that attempt and confirms its removal, or proves the attempt created none, **Then** that incident can be resolved with a recorded review.
3. **Given** missing, unauthorized, ambiguous, or unrelated evidence, **When** recovery is checked, **Then** it stays blocked and reports what evidence or access is missing; a healthy service, elapsed time, or a manual acknowledgement alone is insufficient.
4. **Given** all incidents are resolved and my sign-in still meets the existing admission rules, **When** I submit a new task, **Then** it proceeds without another sign-in; no task starts merely because recovery completed.
5. **Given** recovery finishes after sign-out, **When** it updates the incident, **Then** it does not restore the user session or permit an unauthenticated task.

### User Story 3 - Preserve the safety decision through interruption (Priority: P2)

As an operator, I want unresolved temporary access to stay visible after a crash or restart, so restarting is a reliable diagnostic step and cannot silently bypass recovery.

**Why this priority**: Feature 004 keeps the recovery block only in memory. Persistent recovery state is required before its recovery controls can be trusted.

**Independent Test**: Interrupt execution before and after credential issuance and cleanup, restart, and verify unresolved attempts still prevent new effects while browser sign-in and task history remain ephemeral.

**Acceptance Scenarios**:

1. **Given** a credential request may reach the provider, **When** the process crashes at any point before a durable resolution, **Then** restart retains an unresolved incident and issues no replacement credentials.
2. **Given** missing, damaged, incompatible, or unwritable recovery storage for an established workspace, **When** it starts or accepts work, **Then** it fails closed with a repair instruction rather than inventing a clean state.
3. **Given** a fresh installation, **When** storage is initialized, **Then** it establishes an empty recovery record without restoring credentials, sessions, prompts, or task results.
4. **Given** a second workspace process targets the same recovery state, **When** it starts, **Then** it cannot race the first process or erase its unresolved incident.

### Edge Cases

- Reachability and authorization differ; a reachable service can deny access.
- Cancellation, timeout, or process death happens before a handle is returned, after it is returned, or during cleanup.
- Multiple incidents exist, or two checks use the same evidence; only the matched incident changes and repeat handling is idempotent.
- A dependency stays slow; bounded checks do not accumulate hidden work.
- Provider settings change during evidence review; old evidence cannot clear another environment's incident.
- Sign-out, admission, and recovery completion race; recovery never grants user authority.
- Reloads and repeated checks neither repeat a failed task nor issue temporary credentials.
- Provider audit is unavailable; unsupported reconciliation stays blocked with a specific required next step.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The workspace MUST show connection readiness, recovery status, and sign-in status separately, with a failed stage, stable incident reference, and concrete next action for each blocking condition.
- **FR-002**: Diagnostics MUST classify configuration, reachability, timeout, authorization, expired sign-in, and unresolved issuance/cleanup using observed facts; unavailable and inconclusive checks MUST be distinguishable from healthy checks.
- **FR-003**: Diagnostic checks MUST be read-only, bounded to 10 seconds per check and 30 seconds per request, with at most one request active per workspace. They MUST NOT issue credentials, deliberately try invalid credentials, replay tasks, or change provider settings.
- **FR-004**: Provider repair guidance MUST state an actionable location or configured link, required access, and expected result. A network ban MUST NOT be asserted solely from a timeout or a healthy provider dashboard.
- **FR-005**: The system MUST durably record an attempt before requesting temporary access and retain uncertainty through cancellation, sign-out, crash, and restart until sufficient recovery evidence resolves it.
- **FR-006**: Recovery MUST resolve an incident only from authoritative evidence tied to the exact environment and acquisition attempt: all resulting temporary access is removed, or the attempt is proven not to have issued access. Known handles require exact-handle confirmation; unknown handles require authoritative attempt correlation and explicit operator review.
- **FR-007**: Restored connectivity, elapsed credential lifetime, missing database users, restarting, or an operator acknowledgement alone MUST NOT clear unresolved issuance or cleanup. Partial resolution MUST leave every other unresolved incident blocked.
- **FR-008**: The workspace MUST offer a repeat-safe recovery status check; privileged cleanup and evidence review MUST remain operator actions outside ordinary browser user authority. Failed or insufficient recovery MUST preserve the block and identify the missing evidence or access.
- **FR-009**: Recovery MUST never replay or change the result of an original task. After all incidents are resolved, a new explicitly submitted task MUST pass the existing identity, policy, and credential-admission checks.
- **FR-010**: In-process diagnostics and recovery MUST preserve a still-valid user session. Expired, signed-out, or restarted sessions MUST continue to require existing provider authentication or supported renewal; recovery MUST NOT extend, restore, or bypass user authority.
- **FR-011**: Durable recovery state MUST contain only the minimum private operation identifiers, state transitions, and evidence provenance. Recovery code MUST NOT persist user tokens, provider passwords, prompts, task results, or raw provider responses, or expose them through diagnostics, browser responses, logs, source control, or distribution artifacts. Operator-held private source evidence remains subject to the existing evidence-storage rules.
- **FR-012**: Established recovery storage that is missing, corrupt, incompatible, inaccessible, or full MUST prevent new credential acquisition with an actionable storage error. Concurrent processes MUST NOT race state ownership. A fresh installation MUST have a defined initialization path.
- **FR-013**: Diagnostic and recovery records MUST be bounded, with defined retention and pruning for resolved records; unresolved records MUST never be silently evicted. Public status MUST expose sanitized references and reason codes only.
- **FR-014**: Recovery and diagnostics MUST retain the workspace's existing ownership, request-origin, anti-forgery, and sign-out controls. Browser users MUST NOT provide provider addresses, privileged credentials, native lease handles, or arbitrary evidence paths.
- **FR-015**: The feature MUST include deterministic tests for failure classification, interrupted acquisition and cleanup, restart, duplicate recovery, session expiry, sign-out races, storage failures, and negative authorization boundaries, plus browser validation of the user flows.
- **FR-016**: Validation MUST distinguish completed software checks from live provider acceptance and legacy unresolved incidents. Live claims require private source evidence and a recorded review; unavailable provider capabilities MUST remain explicitly blocked without misreporting software completion.

### Key Entities *(include if feature involves data)*

- **Diagnostic report**: A bounded set of observed checks, their freshness, safe outcomes, and recovery instructions.
- **Recovery incident**: An environment-bound acquisition attempt with a public reference, private correlation details, lifecycle state, and unresolved or resolved disposition.
- **Recovery evidence**: Authoritative provider facts associated with one incident, their private provenance, review, and exact resolution basis.
- **Admission decision**: The combination of connection readiness, unresolved recovery state, and existing user authority determining whether a newly submitted task may start.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All six failure categories in FR-002 produce the expected explanation and next action in controlled browser validation, with zero unsupported root-cause claims.
- **SC-002**: Every diagnostic request finishes or reports a timeout within 30 seconds; repeated checks produce zero credential acquisitions and zero task executions.
- **SC-003**: Across interruption tests at each issuance and cleanup boundary, 100% of unresolved attempts remain blocked after restart and no replacement task starts automatically.
- **SC-004**: Recovery accepts all supported authoritative resolution cases and rejects all ambiguous, unrelated, duplicated-for-another-incident, or unauthorized evidence cases in the validation matrix.
- **SC-005**: A recovered workspace permits one newly submitted task without an additional sign-in when the current session remains admissible; expired and signed-out sessions permit zero new effects.
- **SC-006**: No forbidden secrets or customer payloads appear in durable state, diagnostic output, browser content, logs, or publication artifacts in seeded privacy tests.
- **SC-007**: All documented storage and concurrency failures preserve the safety block; pruning removes zero unresolved records.
- **SC-008**: The validation record identifies every live scenario as passed, failed, or blocked with its source and reviewer status, independently of software task completion.

## Clarifications

### Session 2026-10-10

- Q: When a provider needs repair, should the workspace give exact steps and then check recovery, or also change provider settings automatically? → A: Exact repair steps + recovery checks. Provider configuration changes remain operator actions outside the workspace.

## Assumptions

- The existing local, single-operator browser workspace remains the interface. Remote hosting, multiple simultaneous task slots, and general service administration are out of scope.
- As confirmed during clarification, provider repair is guided by the workspace and performed by an operator using existing provider tools. Automatic network unbanning, provider reconfiguration, broad credential revocation, and automatic resubmission are out of scope.
- Authentication lifetimes and conditional renewal are preserved. Fewer unnecessary sign-ins means retaining a valid in-process session during diagnostics and recovery; login sessions are not restored across restart.
- Recovery depends on provider capabilities and authorized operator access that may be unavailable in the current environment. Missing audit evidence cannot be manufactured.
- The observed network ban explains the connection failure only after provider evidence and the successful unban check. Its original cause is unknown.
- Two uncertain acquisitions from 004 and native audit/denial gaps from 003 remain separately recorded; 005 does not retroactively resolve them or claim vendor acceptance.
- Automated tests use controlled services and synthetic evidence. Live provider mutation, destructive tests, implementation, and delivery are outside this planning request.
