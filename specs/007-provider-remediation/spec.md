# Feature Specification: Provider detection and remediation

**Feature Branch**: `feature/007-provider-remediation`
**Created**: 2026-10-10
**Status**: Planning complete; implementation not started
**Input**: Continue Function 10 of the supplied design after 006: connect trusted risk
detection to provider enforcement, affected-user response, secret remediation and
redacted Teams notification, with independent proof and measured loss of access.

## Scope and terminology

006 supplies durable local containment and attributable dynamic-credential cleanup.
007 adds configured provider response around that foundation. **VIP** means IBM Verify
Identity Protection. A **root** is one execution and its descendants; a **definition**
is the durable configured agent shared by roots. A **provider action** changes an
external security control. A **proof** observes the specific resulting behavior;
accepting a request alone is not proof. An **enrolled policy** is a local operator's
explicit selection of trusted event sources, exact targets and permitted actions.

Build the software and deterministic tests for all stories. Live acceptance additionally
requires enrolled test resources, an actual VIP event route and independent observations.
Missing deployment capabilities produce actionable blocked dispositions; they do not
remove adapter implementation or test tasks. Planning does not authorize a live mutation.

Out of scope: Function 11 shadow discovery/enrollment; global IBMid administration;
ServiceNow; public ingress hosting; tenant-wide revocation; arbitrary event-supplied
commands or destinations; automatic re-enablement; restoring prior secret values;
turning the existing demo cluster into an audit-capable Vault tier; changing sealed actor/
client configuration through an unimplemented cross-store migration.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Respond to an attributable risk signal (Priority: P1)

An operator enrolls a known VIP event route and narrowly scoped response policy.
A qualifying event automatically creates or joins an incident and starts its authorized
response without another human click. Untrusted, ambiguous or repeated events cannot
create broader or duplicate effects.

**Why this priority**: Automatic response needs a trustworthy cause and target first.
**Independent Test**: Feed a verified synthetic source event through an enrolled mapping;
observe one durable incident and local hold. Separately demonstrate real collector
receipt before labeling the source as native VIP evidence.

**Acceptance Scenarios**:

1. **Given** a verified source, enrolled rule and exact target, **When** a qualifying
   fresh event arrives, **Then** containment commits before provider work and the
   originating source, decision and incident remain linked privately.
2. **Given** repeated delivery or restart, **When** the same event returns, **Then** it
   returns the existing incident; changed content under the same identity is rejected.
3. **Given** absent collector enrollment, invalid authentication, unmapped identity,
   stale event, disabled rule or full queue, **When** intake is attempted, **Then** no
   external effect occurs and the operator sees the missing condition and repair step.

### User Story 2 - Block affected agent and user access (Priority: P1)

An operator enables separate policies for a single root, a complete definition, and a
specifically mapped compromised user. Only enrolled controls run; reports show which
existing and fresh access paths actually fail.

**Why this priority**: Local cancellation cannot prevent external credential reuse.
**Independent Test**: Exercise provider doubles, then isolated live accounts to compare
healthy and affected roots and retry the same still-unexpired credential at the provider.

**Acceptance Scenarios**:

1. **Given** two roots sharing a definition, **When** a root-only incident occurs,
   **Then** only attributable credentials are revoked; the peer remains usable and no
   shared definition/user control changes. A shared credential stays explicitly unrevoked.
2. **Given** a definition incident, **When** response executes, **Then** fresh issuance
   is blocked by an enrolled provider control and attributable existing credentials are
   handled. Unknown or usable paths prevent a complete-block claim.
3. **Given** an exactly mapped user and enabled user policy, **When** its event fires,
   **Then** tenant suspension/session termination executes; tenant sessions, issued
   credentials, local sessions and upstream identity-provider sessions remain separate.
4. **Given** uncertain completion, **When** the worker restarts, **Then** local holds
   persist and effects are reconciled without blind replay or automatic re-enablement.

### User Story 3 - Remove database access and remediate a misused secret (Priority: P2)

An operator uses isolated enrolled database resources to revoke affected temporary
credentials, close specifically owned sessions where supported, and rotate a misused
static credential. Existing and new connection outcomes are shown separately.

**Why this priority**: Revocation/rotation alone does not prove an open connection stopped.
**Independent Test**: Controlled fixtures prove exact session selection, old/new value
behavior, rotation uncertainty and refusal of shared or unattributed targets. Live
proof uses dedicated disposable resources and an independent healthy connection.

**Acceptance Scenarios**:

1. **Given** attributable dynamic credentials, **When** containment occurs, **Then**
   ordinary/incident cleanup share one result; fresh-login and open-session denial are
   observed independently of application cancellation.
2. **Given** an enrolled isolated static secret, **When** its rule fires, **Then** rotation
   is submitted once and old-value denial plus replacement-value usability are tested
   without exposing either value in stored evidence or reports.
3. **Given** shared identities, reused session IDs, unsupported termination, timeout or
   ambiguous rotation, **When** response is attempted, **Then** unsafe targets are refused,
   uncertainty remains visible and concrete reconciliation steps are supplied.

### User Story 4 - Report, notify and recover deliberately (Priority: P2)

An operator sees per-control outcomes, receives a redacted Teams incident notice, and
can distinguish missing configuration, request acceptance, proven effect and uncertainty.
Recovery requires review of all applicable holds and provider state.

**Why this priority**: A single green status must not conceal partial provider failure.
**Independent Test**: Simulate partial outcomes, notification timeout, receipt replay,
clock skew and restart; verify private reports, safe workspace summaries and release gates.

**Acceptance Scenarios**:

1. **Given** mixed outcomes, **When** status is read, **Then** each control has its own
   state, provenance and next step; Teams receives only safe incident/outcome metadata.
2. **Given** accepted notification transport, **When** channel delivery is unobserved,
   **Then** it remains accepted, not delivered; uncertain sends are not auto-replayed.
3. **Given** valid origin and denial observations, **When** closing out, **Then** detection,
   decision, revoke and observed block times are separate; skewed/missing intervals are
   unavailable instead of estimated.
4. **Given** externally restored access, **When** local release is requested, **Then**
   unresolved actions, old-token reuse risk or new holds prevent release. Authorized
   recovery admits fresh roots only, never old executions or previous secret values.

### Edge Cases

- Another tenant's target, extra fields, source text containing secrets, reused event ID,
  or changed policy while intake/provider work is in flight.
- Concurrent incidents reference one resource; revoked parent token cascades to leases;
  timeout or storage failure follows successful provider mutation.
- A still-valid signed credential passes validation but is policy-denied; alternate token
  types or identity bindings bypass the tested route.
- Verify suspension leaves upstream IBMid or issued credentials usable; an external
  session is outside the enrolled inventory.
- Database process ID reuse, pooled/shared users, scheduled rotation confounding attribution,
  or missing health control prevents a trustworthy denial observation.
- A Teams workflow loses its owner, returns acceptance without delivery, or receives
  duplicate evidence; notification failure cannot prevent containment.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Enroll exact sources, rules, target mappings, capabilities, permitted actions
  and recovery expectations before automatic response is enabled.
- **FR-002**: Authenticate source intake separately from browser/model identity; map only
  allowed fields and retain normalized provenance without raw event payloads.
- **FR-003**: Reject stale, conflicting, unauthorized, oversized or unmapped events;
  deduplicate unchanged events across retries/restart within the retention contract.
- **FR-004**: Commit the 006 hold before provider dispatch, preserve root/definition
  ownership and prioritize cancellation while another effect owner drains.
- **FR-005**: Select effects solely from enrollment; verify exact target, source, tenant,
  scope and configuration revision at dispatch.
- **FR-006**: Root-only response MUST preserve healthy peers and prohibit shared definition
  controls, user suspension and static-secret rotation; unsupported exact revocation is explicit.
- **FR-007**: Definition response MUST block fresh provider issuance and inventory configured
  existing paths; unknown/unusable-to-test paths prevent a complete-block claim.
- **FR-008**: Revoke attributable native tokens and dynamic leases through a coordinated
  lifecycle; never infer ownership from message text, lease strings or timestamps.
- **FR-009**: Prove denial of the same still-unexpired external credential and fresh issuance
  using provider requests; distinguish validation, policy and native-token denial.
- **FR-010**: Support enrolled tenant user suspension/session termination using exact
  verified-user mapping and separate local, tenant and upstream dispositions.
- **FR-011**: Rotate an enrolled isolated static secret using its supported control; check
  old-value denial and replacement usability without persisting either value.
- **FR-012**: Support exact database-session termination when authorized and supported;
  prove open-session/fresh-connection loss separately and refuse ambiguous targets.
- **FR-013**: Persist intent before dispatch; serialize conflicting resource actions across
  incidents, preserve crash uncertainty and forbid automatic mutation replay.
- **FR-014**: Provide bounded read-only reconciliation and explicit revision-bound operator
  retry/recovery; provider restoration and local release remain separate.
- **FR-015**: Send one redacted Teams notice per incident notification revision; separate
  transport acceptance from observed delivery and contain notification failure.
- **FR-016**: Report per-control outcomes and detection/decision/revoke/block times,
  comparing valid trigger-to-observed-loss measurements with the 30–60 minute baseline.
- **FR-017**: Readiness/recovery instructions MUST name the missing capability, responsible
  role, exact action and check to rerun; unsupported capabilities remain explicit.
- **FR-018**: Preserve session-owned browser summaries, secret-free telemetry and private
  evidence; restrict provider administration to the local operator boundary.
- **FR-019**: Version state/policy changes explicitly, preserve 006 holds/uncertainties
  through migration and prevent older processes from ignoring provider holds.
- **FR-020**: Bound event, storage, queue, provider-call and proof resources; fail closed
  on corruption/stale policy/capacity exhaustion while preserving known-handle recovery.
- **FR-021**: Require deterministic positive, negative, concurrency, crash, migration,
  privacy and browser tests; live checks remain isolated and separately authorized.
- **FR-022**: Keep software completion separate from reviewed native acceptance for each
  Function 10 test; unavailable audit, collector or provider evidence cannot become a pass.

### Key Entities

- **Provider enrollment**: exact revision, capabilities, identity mappings and allowed controls.
- **Source event**: authenticated source, event identity, rule, time and mapped target.
- **Resource binding**: trusted relationship between a root/definition/user and provider handle.
- **Provider action**: incident/resource identity, intended effect and dispatch/reconciliation state.
- **Observation**: independent time-bounded result for one path with private provenance.
- **Notification receipt**: transport or channel observation bound to a notice revision.
- **Recovery decision**: operator choice bound to current holds, resource state and revision.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Every accepted qualifying test event creates/joins exactly one incident;
  invalid events cause zero provider mutations, including after restart.
- **SC-002**: Healthy local tests commit containment within two seconds of intake and
  request cancellation within two seconds of commit.
- **SC-003**: Every supported path has a separate before/after result; root tests preserve
  a healthy peer and full-block claims require denial on all applicable paths.
- **SC-004**: All crash/timeout tests preserve unresolved work and repeat no mutation
  automatically, including rotation and notification.
- **SC-005**: Every missing/unsupported capability has a concrete action and recovery
  check; no secret/raw payload appears in public output or artifacts.
- **SC-006**: In an authorized live demonstration, a real source event starts response
  without a human click and measured privileged-access loss is below 30 minutes;
  absent origin or loss observations leave this outcome unproven.
- **SC-007**: Notices have distinct accepted/delivered dispositions; all release tests
  retain old-root denial and reject unresolved or concurrently changed holds.

## Assumptions

- The supplied Function 10 checklist determines scope. Existing 006 exact cleanup,
  enrollment, local guard and evidence conventions remain authoritative.
- Automation requires explicit local enrollment of isolated test resources, without an
  additional per-event human click. Broad production administration is excluded.
- User suspension affects the configured tenant, not global IBMid or necessarily every
  already-issued external credential.
- Live source enrollment requires actual tenant configuration/evidence; general product
  documentation cannot certify a deployed tenant.
- Development-tier Vault audit remains unavailable. Behavioral probes can prove specific
  effects, but cannot satisfy an audit-specific requirement.
- Single-host operation, one live database owner and existing packages/extras continue.
