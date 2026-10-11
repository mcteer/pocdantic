# Feature Specification: Shadow Agent Governance

**Feature Branch**: `feature/008-shadow-agent-governance`
**Created**: 2026-10-10
**Status**: Draft — specified and clarified for planning
**Input**: Continue the supplied design's Function 11 after merged 007: observe an
unknown agent before registration, review its owner and permitted purpose, enroll it,
verify its workload identity independently, and demonstrate limited permissions.

## Context and scope

An operator needs to distinguish a workload first seen by an identity-protection
collector from a workload already approved to use the agent platform. Discovery is
an observation, owner review is an authorization decision, registration governs specific
Vault access paths, and a SPIFFE identity document identifies an authenticated workload.
Each claim needs its own evidence. None establishes code integrity or safe behavior.

This feature covers Function 11 and its seven acceptance tests. It adds a bounded
local governance workflow for one controlled unknown workload at a time, reusable
across enrolled sources and candidates. The operator controls enrollment; incoming
findings and model text never grant credentials or register agents automatically.
Native Vault issuance is the default. Existing deployment features must be verified
before activation; missing features yield specific setup instructions.

Out of scope: a general network scanner, public ingress hosting, automatic discovery
inference from runtime traces, policy/identity-provider administration, a new external
identity issuer, automatic restoration of 007-revoked registrations, destructive rollback,
Function 12/13 project-wide closeout, and a claim that unavailable demo-tier audit exists.

## Clarifications

### Session 2026-10-10

No questions were needed. The supplied design and accepted project decisions resolve
the scope: native collector evidence must precede registration; independently authenticated
workloads use native Vault issuance; enrollment needs an accountable owner and explicit
limited authority; external issuer support needs a later approved alternative. Operator
setup of provider prerequisites follows the existing guided-repair convention. A reviewed
one-candidate registration action is supported; broad provider configuration is external.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Observe an unknown workload (Priority: P1)

An operator runs a controlled workload that has no agent registration, observes the
collector's finding, and can see when, where and with what confidence it was identified.
The original observation survives later enrollment or a corrected classification.

**Why this priority**: Discovery before enrollment is the distinctive requirement;
creating a local candidate cannot substitute for being detected by the provider.
**Independent Test**: Deliver an authenticated synthetic collector fixture and duplicate;
verify one immutable first observation, no authority granted, and synthetic provenance.

**Acceptance Scenarios**:

1. **Given** an authorized isolated unregistered workload, **When** the real collector
   identifies it, **Then** the finding records source, time, attribution, confidence,
   notification evidence and the independently observed pre-registration state.
2. **Given** the same finding delivered twice, **When** selected security content agrees,
   **Then** it joins the same observation; changed content under the same identity is rejected.
3. **Given** untrusted, stale, malformed or ambiguous evidence, **When** intake occurs,
   **Then** it grants no authority and either rejects it or records an explicit limitation.
4. **Given** generic traffic or operator-entered data, **When** the operator reviews it,
   **Then** it cannot silently become a native agent-discovery pass.

### User Story 2 - Review and enroll one agent (Priority: P2)

The operator associates the observed workload with an accountable owner, purpose,
stable verified identity and limited permission ceiling. A concrete review previews
one registration; explicit application and readback establish its actual state.

**Why this priority**: Enrollment is a privilege boundary that must preserve the discovery
history and remain safe under a lost response, changed configuration or concurrent action.
**Independent Test**: With a seeded finding and provider fixture, review/apply/read back
one registration; interrupt submission and prove restart does not issue it twice.

**Acceptance Scenarios**:

1. **Given** a reviewed candidate and independently verified identity, **When** the
   operator approves an exact registration, **Then** only that identity, owner and
   permission ceiling can be enrolled; changes invalidate the review.
2. **Given** no owner review or no authenticated bootstrap, **When** a workload requests
   enrollment or identity issuance, **Then** it cannot grant those privileges to itself.
3. **Given** a lost registration response, **When** the process restarts, **Then** the
   outcome stays uncertain until exact readback; no automatic resubmission occurs.
4. **Given** a contained definition or a mismatched existing registration, **When**
   enrollment is attempted, **Then** it is blocked with a concrete repair step.

### User Story 3 - Verify a short-lived workload identity (Priority: P2)

After enrollment, the already authenticated workload obtains an identity document
for one relying service. That separate service verifies the issuer's trust material,
exact workload identifier, intended recipient, lifetime and approved identity provenance.
The operator receives a safe result rather than a bearer credential.

**Why this priority**: Issuance alone is insufficient; the design requires another
service to verify identity and reject forged or misdirected documents.
**Independent Test**: A separate relying process accepts a synthetic valid document
and rejects modified signatures, unknown keys, wrong recipients, expired documents,
spoofed workload identifiers and wrong entity provenance.

**Acceptance Scenarios**:

1. **Given** a reviewed authenticated workload and an available native issuer,
   **When** it requests its approved identity, **Then** an independent relying service
   accepts only the exact approved identity and recipient within the permitted lifetime.
2. **Given** an unregistered or unauthenticated workload, **When** it requests identity
   through the governance workflow, **Then** issuance is denied before privileges are granted;
   actual provider denial is measured independently where claimed.
3. **Given** an unavailable issuer, invalid trust material or an interrupted request,
   **When** the operator checks status, **Then** the result explains the missing prerequisite
   or uncertainty without emitting the document or assuming revocation.
4. **Given** changed trust or enrollment, **When** an older proof is evaluated,
   **Then** it cannot certify the new configuration.

### User Story 4 - Prove permissions and close out each claim (Priority: P3)

The operator compares delegated and ordinary access, sees each allowed and denied
operation, and follows the same workload from first observation to reviewed registration.
The browser shows a safe summary for its authorized owner. Missing provider evidence
has an exact next step and remains separate from successful software checks.

**Why this priority**: The completed story must explain where access was constrained,
without mistaking local policy denial or registration status for provider enforcement.
**Independent Test**: Synthetic before/after delegated and ordinary access fixtures
produce separate dispositions; unavailable audit and unproven discovery remain blocked.

**Acceptance Scenarios**:

1. **Given** a registered agent, **When** allowed and excessive delegated operations
   are tested, **Then** actual Vault decisions demonstrate the registration ceiling;
   an application-only denial cannot pass that provider claim.
2. **Given** ordinary authenticated access, **When** allowed and forbidden operations
   are tested, **Then** baseline Vault permissions receive independent results.
3. **Given** a managed or triaged native finding, **When** its evidence is linked,
   **Then** first-observed evidence remains intact and native versus local status is explicit.
4. **Given** a signed-out session or another owner, **When** the workspace is viewed,
   **Then** candidate details are absent; raw identifiers, credentials and provider text
   never appear in browser responses or telemetry.

### Edge Cases

- An existing registration, ambiguous actor aliases, shared bootstrap identity, clock skew
  or untrusted source cannot establish detection of a previously unknown workload.
- Duplicate findings, out-of-order lifecycle updates and source corrections preserve
  first-observed evidence; local triage never rewrites the provider's state.
- Provider edition, licensing, collector schema or permitted endpoints may be unavailable.
  Planning and synthetic checks can finish while the affected native claim stays blocked.
- Permission changes, entity merges, role-template changes, signing-key rotation and
  configuration drift invalidate the affected readiness, approval and proof records.
- Expiry, network failure, cancellation and malformed replies are distinct from provider
  denial. No mutation or identity issuance is automatically replayed after uncertainty.
- Workload identity may be shared by co-located executions; no per-process attestation is
  inferred. Identity documents are short-lived credentials with their own expiry semantics.
- Containment arriving during enrollment or proof stops further work; no governance action
  clears an existing hold or restores a revoked registration.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Preserve authenticated source observations, first-observed time, confidence,
  classification limitations, attributable workload identity and notification evidence;
  explicitly distinguish native, synthetic and operator-supplied provenance.
- **FR-002**: Authenticate enrolled sources, enforce bounded input and exact configured
  projections, deduplicate equivalent redelivery and reject changed security content.
- **FR-003**: Establish the unknown-before-registration sequence using independently
  reviewed absence and collector evidence with clock uncertainty; ambiguous chronology
  cannot pass native discovery.
- **FR-004**: Provide a controlled safe activity workflow with explicit isolated target
  selection, existing trusted execution limits and no automatic enrollment or credential
  issuance on discovery.
- **FR-005**: Require accountable owner, purpose, stable verified workload mapping,
  independent authentication and an approved permission ceiling before enrollment.
- **FR-006**: Preview and bind the enrollment decision to exact provider configuration,
  candidate and revision; apply only one explicitly reviewed registration and read it back.
- **FR-007**: Persist intent before remote effects, retain uncertainty after lost replies,
  bound execution, reconcile read-only and prevent duplicate or broadened retries.
- **FR-008**: Verify provider capability, role configuration and least-privilege authority
  before activation; missing prerequisites yield exact operator instructions and rechecks.
- **FR-009**: Issue only a short-lived, audience-bound native workload identity for the
  approved already-authenticated entity; no discovery finding or unverified claim can
  substitute for bootstrap authentication.
- **FR-010**: Independently verify signature, trust origin, exact workload identifier,
  audience, time bounds and approved entity provenance; reject tampering, unknown trust,
  spoofing, replay of a consumed proof and malformed inputs.
- **FR-011**: Keep identity credentials in trusted process memory and protected transport;
  track possible issuance through its conservative expiry bound without claiming immediate
  revocation or retaining bearer values in journals, output, browser data or traces.
- **FR-012**: Test actual pre-registration direct OAuth denial, post-registration allowed
  and excessive delegated access, and ordinary allowed/denied access separately with
  healthy controls; distinguish permission source and limit all successful probe effects.
- **FR-013**: Link discovery, accountable owner, registration, identity verification and
  provider decisions; record native managed/triaged state only from qualifying evidence
  and retain the original unknown finding.
- **FR-014**: Present safe owner-scoped workspace summaries and operator commands with
  concrete missing-prerequisite steps, without exposing secrets or native identifiers.
- **FR-015**: Preserve 005–007 recovery, configuration binding and containment. Governance
  must not clear holds, change existing actor/client configuration or restore revoked
  registrations; conflicting actions must be serialized or refused.
- **FR-016**: Keep private state and source evidence out of Git, packages and telemetry;
  protect files against unsafe links/permissions, enforce retention and capacity limits,
  and reject private artifacts even when renamed.
- **FR-017**: Assess every F11-T1 through F11-T7 independently with source evidence,
  reviewer and time; preserve unavailable audit and deployment limitations without
  promoting acceptance from synthetic results or local checks.
- **FR-018**: Add meaningful deterministic security, concurrency, cancellation, crash,
  replay and browser-isolation coverage; document modules/functions, configuration,
  operational commands and compatibility, using the existing dependencies where possible.

### Key Entities

- **Observation**: Immutable source finding and provenance, source identity, first-seen
  interval, confidence/classification and notification reference.
- **Candidate**: Local handle joining an observed workload to independently reviewed
  stable identity, accountable owner and purpose without granting authority.
- **Enrollment review and attempt**: Exact registration preview, evidence references,
  reviewer/time, configuration revision, remote intent and readback disposition.
- **Trust profile**: Approved issuer, workload identifier, recipient, entity provenance,
  bootstrap constraints and maximum identity-document lifetime.
- **Proof**: Bounded before/after provider observations, independent relying result,
  healthy controls and explicit source/implementation revisions.
- **Governance report**: Safe per-claim status, immutable-history links and next action,
  scoped to the authorized viewer.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In every duplicate, spoofed-source and changed-replay test, at most one
  original finding survives and zero unauthorized enrollments or issuances occur.
- **SC-002**: Every enrollment test binds exactly one reviewed identity and ceiling;
  crashes or stale reviews never cause automatic repeat mutations or loss of uncertainty.
- **SC-003**: All seven identity-negative classes—unauthenticated mint, modified signature,
  wrong recipient, expired identity, spoofed identifier, wrong entity and untrusted key—
  are rejected, while the valid independent-verification case succeeds.
- **SC-004**: Reports separately account for pre-registration denial, delegated allow/deny,
  ordinary allow/deny and native lifecycle evidence; none can pass from another path's result.
- **SC-005**: At the supported limit of 1,000 candidates and 10,000 observations, a local
  status report completes within five seconds excluding provider I/O; each external
  operation terminates within its documented bound and preserves unresolved work.
- **SC-006**: Credential/native-data canaries remain absent from all public outputs,
  browser views, telemetry, staged content and distribution artifacts; sign-out clears
  the displayed governance data.
- **SC-007**: All seven native Function 11 tests receive a reviewed pass/fail/blocked
  disposition with concrete evidence or exact missing prerequisites; unavailable
  source evidence and demo-tier audit never receive a synthetic pass.

## Assumptions

- The supplied Function 11 checklist determines scope; prior 007 live checks remain
  independent and do not block implementing this software.
- One local operator authority administers private configuration and explicit actions;
  local reviewer labels document decisions and are not remote human authentication.
- Dedicated test resources, provider configuration and an independent workload bootstrap
  must be supplied by their administrators. The workflow gives exact steps and rechecks.
- The existing local browser workspace is retained for safe status; security-sensitive
  setup and effects use explicit operator commands, consistent with current operations.
- Native Vault SPIFFE availability is verified rather than inferred from edition branding.
  An external issuer is a separately approved future scope, not an automatic fallback.
- Automated tests must deny live network and ambient credentials. Real discovery,
  enforcement and audit acceptance require actual provider evidence and review.
