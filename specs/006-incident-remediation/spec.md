# Feature Specification: Incident containment and exact cleanup

**Feature Branch**: `feature/006-incident-remediation`
**Created**: 2026-10-10
**Status**: Specified and clarified; implementation not started
**Input**: Continue the supplied build roadmap after 005, beginning the next unbuilt security-response workflow in Function 10.

## Context and scope

A trusted security signal must be able to stop a particular execution or an entire
agent definition, clean up attributable temporary credentials, and show exactly which
controls completed. Existing local containment disappears on restart and the recovery
journal does not yet record which execution owns an attempt.

006 delivers the first independently testable Function 10 increment: authenticated
incident intake, durable local run/definition containment, prospective ownership,
exact dynamic-lease cleanup, reconciliation, and elapsed-time reporting. It also
provides an explicit operator release of local definition containment after cleanup.
A risk signal cannot select administrative destinations or expand the configured scope.

The rest of Function 10 remains a visible follow-on: native VIP event translation and
collector proof, provider-wide blocking of existing/fresh JWTs, compromised-user session
termination/suspension, static-secret rotation, Teams notification, and downstream
session-loss proof. Shadow-agent discovery and enrollment are Function 11. This feature
does not claim completion of UC3 or any of those deferred controls.

## Clarifications

### Session 2026-10-10

- Q: What defines the scope of the next feature? → A: Use the plans already supplied in the private design folder.
- Planning interpretation: Function 10 is the next unbuilt security-response workflow; 006 delivers its durable local containment and attributable cleanup foundation as a bounded first increment.
- Existing decisions carried forward: the local browser is the user workspace; provider troubleshooting remains operator-guided; Development-tier Vault audit logs are unavailable in this environment. This increment adds explicitly configured incident response, not automatic provider configuration repair.
- Design defaults: target a root execution and its descendants or the stable workload definition; use one trusted automation relay contract without asserting it is a native VIP payload; preserve current serialized live database effects.

## User Scenarios & Testing

### User Story 1 - Contain a trusted incident (Priority: P1)

A security operator configures a trusted automation source. When it sends a supported
risk signal, the application durably blocks the targeted root execution and descendants,
or all local executions of the named definition, before acknowledging acceptance.

**Why this priority**: A restart or another entry point must not bypass an incident.
**Independent Test**: With synthetic concurrent executions, a signed source signal
stops the target, leaves a healthy sibling eligible under normal limits, rejects
new definition work when appropriate, and survives a process restart.

**Acceptance Scenarios**:
1. **Given** a configured source and known root execution, **When** a valid signal arrives, **Then** its target is blocked before acknowledgment and pending model/tool/approval work is canceled or denied.
2. **Given** an unauthorized, stale, malformed, or unmapped signal, **When** it is submitted, **Then** no containment or provider operation occurs.
3. **Given** a duplicate signal, **When** it is received again, **Then** the original incident is returned without repeating actions; reuse of the same identifier with changed content is rejected.
4. **Given** active definition containment, **When** the service restarts or a caller uses CLI, batch, or bearer ingress, **Then** the same durable block applies.
5. **Given** two healthy executions sharing a definition, **When** one is contained, **Then** its sibling remains eligible unless a separately reported shared recovery block or existing concurrency limit applies.

### User Story 2 - Clean up only attributable credentials (Priority: P1)

An incident worker waits for targeted execution cleanup to drain and reconciles only
those credential attempts durably bound to the selected root or definition. It uses
separate configured cleanup authority when normal runtime cleanup did not complete.

**Why this priority**: A local stop must not be mistaken for credential revocation,
and an incident must not revoke a healthy execution's credentials.
**Independent Test**: Controlled provider and crash tests prove that only bound handles
are revoked, no new credentials are acquired, and ambiguous outcomes remain blocked.

**Acceptance Scenarios**:
1. **Given** a known target lease, **When** ordinary cleanup completes, **Then** the worker observes the existing receipt without sending another revoke.
2. **Given** a drained target and an unresolved known handle, **When** authorized cleanup runs, **Then** only that exact handle is synchronously revoked and completion is persisted.
3. **Given** unknown issuance, an old unbound attempt, missing authority, or a denied/timed-out revoke, **When** remediation runs, **Then** the incident retains a specific incomplete result and containment remains active.
4. **Given** a process crash after a provider request, **When** the worker restarts, **Then** it does not blindly replay the operation or report success.
5. **Given** live database execution is serialized, **When** remediation competes with an active owner, **Then** it waits within its deadline and never races the owner's SQL or cleanup.

### User Story 3 - Understand and resolve the incident (Priority: P2)

The operator can inspect local cancellation, credential cleanup, remaining restrictions,
and measured timings independently. A signed-in workspace user sees safe information
for their own work. After cleanup, a local operator can explicitly release a definition
for fresh work; the original execution never resumes.

**Why this priority**: Users need a concrete next step without confusing partial
operational recovery with provider-wide revocation or vendor acceptance.
**Independent Test**: Private command reports and browser tests distinguish blocked,
partial, and completed actions, preserve failed job history and valid sessions, and
reject stale or unsafe release attempts.

**Acceptance Scenarios**:
1. **Given** a completed local cancellation but uncertain lease cleanup, **When** status is inspected, **Then** both results and an exact repair command are shown independently.
2. **Given** an active incident, **When** a different or signed-out browser session requests status, **Then** it cannot see another user's incident details or private mappings.
3. **Given** all attributable attempts are resolved and no affected process is active, **When** the local operator releases the current definition revision, **Then** only that local hold is removed; old run IDs, approvals, and old job results remain unusable.
4. **Given** a clock discontinuity or missing source time, **When** latency is reported, **Then** unsupported durations are labeled unavailable rather than invented.
5. **Given** the current cluster cannot export native audit records, **When** evidence status is reported, **Then** that known platform limitation remains visible without another audit-access troubleshooting loop.

### Edge Cases

- Containment races with token exchange, acquisition, SQL, child delegation, approval consumption, sign-out, process exit, and definition release.
- A source reuses an event identifier, changes its target, sends an oversized body, or supplies an unknown definition/run.
- A journal write fails, a private file is replaced, a worker crashes, or multiple processes contend for locks.
- A legacy recovery record has no ownership; neither timestamps nor a shared database path establish ownership.
- Cleanup authority expires, a provider accepts work but loses the response, or an effect worker ignores cancellation temporarily.
- A held definition changes its configuration or credentials, an event arrives during release, or a completed record reaches retention limits.

## Requirements

### Functional Requirements

- **FR-001**: Accept only authenticated, explicitly allowlisted automation sources and locally authorized operator input; reject ordinary task/browser/model authority for incident mutations.
- **FR-002**: Validate bounded, versioned risk signals with source/event identity, occurrence time, supported reason, and exactly one mapped root-run or stable-definition target. Signals cannot contain executable instructions, destinations, provider credentials, or native lease handles.
- **FR-003**: Persist the signal identity, immutable target, and local containment decision before acknowledging acceptance or starting asynchronous response actions.
- **FR-004**: Deduplicate source/event identifiers durably; identical redelivery returns the original result, while conflicting reuse fails without effects.
- **FR-005**: Enforce durable containment at every live admission and trusted effect boundary, including descendants, approvals, token transitions, credential acquisition, and SQL. Cleanup remains possible under containment.
- **FR-006**: Cancel matching active local executions within a bounded interval; target one root tree or one stable workload definition and preserve unaffected execution eligibility subject to existing recovery/concurrency controls.
- **FR-007**: Bind prospective credential attempts to trusted root-run, request, definition, and verified user ownership before issuance. Preserve old unbound attempts without inferring their owner.
- **FR-008**: Migrate existing private recovery state explicitly and safely, preserving every unresolved record and rollback detection within the existing local trust model; partial migration or missing established state blocks effects.
- **FR-009**: Let the existing execution owner drain cleanup before separate remediation acquires effect ownership. Reconcile successful durable receipts and revoke only unresolved exact handles attributable to the incident.
- **FR-010**: Use independently configured cleanup authority and fixed provider targets for incident cleanup. Never acquire credentials, execute SQL, revoke a prefix, force-revoke, alter policies, or substitute this authority into normal delegated work.
- **FR-011**: Persist intent and result for each response action; distinguish confirmed, pending, denied, failed, and uncertain effects. Duplicate intake/restart must not blindly retry provider operations.
- **FR-012**: Keep containment active across restarts and partial failures. Provide explicit operator reconciliation using existing recovery proof/cleanup, with no reset or acknowledge-to-clear bypass.
- **FR-013**: Allow an explicit revision-checked local definition release only after relevant cleanup is complete and active work has drained; retain terminal run blocks, old results, and consumed approvals. Release never changes provider state or resumes old work.
- **FR-014**: Report local execution containment, exact-lease cleanup, and out-of-scope external controls separately, including safe reason codes and concrete next steps.
- **FR-015**: Record source, receipt, containment, and cleanup timestamps plus valid elapsed measurements; never label local timing as native detection latency or lease cleanup as external JWT/session revocation.
- **FR-016**: Keep identifiers, user mappings, native handles, credentials, raw signals, and private evidence out of public responses, model context, telemetry, Git, and distribution artifacts. Browser detail access is session-owned; anonymous status is aggregate only.
- **FR-017**: Bound accepted payloads, queues, retained records, worker lifetime, and lock waits; reject over-capacity submissions before acceptance while retaining unresolved holds and reserved result capacity.
- **FR-018**: Supply deterministic negative, concurrency, replay, crash, privacy, and WebKit validation, plus a documented optional live workflow. Preserve explicit unavailable native-audit and deferred Function 10/11 acceptance dispositions.

### Key Entities

Trusted source policy; normalized risk signal; incident; durable definition hold;
root execution and descendant ownership; credential attempt binding; response action;
operator release record; private incident report; safe session-owned incident summary.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Every unauthorized, malformed, unmapped, stale, or conflicting test signal causes zero containment or provider effects; duplicate accepted signals cause zero repeated effects.
- **SC-002**: With two controlled executions, root containment blocks only its execution tree; definition containment rejects every matching new execution across supported entry points and restart. Local cancellation is requested within two seconds of durable acceptance in the controlled test environment.
- **SC-003**: Every credential request after enrollment has trusted ownership recorded before issuance, and every cleanup action uses only its attributed exact handle. Unknown and legacy ownership remains explicit.
- **SC-004**: All crash checkpoints retain containment and accurate action uncertainty; no restart, duplicate delivery, or ordinary status check repeats a submitted provider operation.
- **SC-005**: A reviewer can identify the triggering signal, target, distinct control outcomes, measured timings, and remaining limitations from one private report; no secret or cross-user detail is exposed by tested public surfaces.
- **SC-006**: A valid operator release permits a fresh eligible execution while stale releases, unresolved cleanup, active ownership, and old-run replay remain rejected.
- **SC-007**: Locked offline validation covers the complete incident path without live credentials; optional live outcomes and the original acceptance criteria retain independent dispositions.

## Assumptions

- The host is a single-machine local workspace with trusted administrators. It is not a distributed policy authority and does not defend against an administrator rewriting code or deleting all private state.
- The host's live database effect remains serialized. Concurrency isolation is proved with controlled executions; a claim of two simultaneous live database leases is outside this increment.
- A configured relay translates a provider event into the application's supported signal. Relay authentication does not itself prove native VIP detection. No VIP endpoint or payload shape is invented.
- One private configuration file holds nonsecret source/target mappings. Existing credential settings supply secrets; no broad new environment-variable namespace is introduced.
- Auditing is unavailable on the recorded Development-tier cluster. Missing historical audit linkage is an acknowledged environment limitation, not a prerequisite to software implementation.
- Full provider-wide kill switch, compromised-user response, static-secret remediation, notifications, and shadow governance require subsequent scoped work and native integration evidence.
