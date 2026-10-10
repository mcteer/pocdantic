# Feature Specification: Live readiness and evidence closure

**Feature Branch**: `feature/003-live-evidence-closure`
**Created**: 2026-10-09
**Status**: Clarified; planning only
**Input**: Define 003 around live integration verification and evidence closure; add
readiness and closeout commands, then stop before implementation for a model change.

## Context and scope

Feature 002 provides bounded scenario execution, private imports, correlation and per-run
reviews. Operators still lack a precise local readiness check and one reproducible view of
separately executed database and witnessed phone cases. Native export differences can also
prevent usable source evidence from being recognized.

003 adds a local readiness report, compatibility with documented native export shapes, and
an immutable closeout snapshot of explicitly selected runs and their existing reviews.
It reuses the four live cases: delegated database read, actor-only denial, phone approval,
and phone denial. It fixes only integration defects demonstrated by these paths and keeps
unknown vendor linkage blocked. The operator executes cases; the reviewer judges evidence.
One person may hold both roles, but executing a case never supplies its review.

The unfinished real database/receipt and witnessed phone checks remain owned by 002 T036
and T037. 003 links the resulting observations and closes those tasks only when their
original proof requirements are met. Delivery controls from 002 T039 remain a separate
pre-merge gate. Merging code did not establish live acceptance.

Out of scope: automated export collectors, new read-token configuration, automatic login,
provisioning or policy changes, real infrastructure writes, workload attestation/SVIDs,
VIP discovery/remediation, external token/session revocation, Teams notifications, a UI,
automatic reviewer decisions, and automated acceptance-file publication.

## Clarifications

### Session 2026-10-09

- Q: Should 003 add a small reusable readiness/closeout workflow or only run existing live checks and fix observed gaps? → A: Add readiness and closeout commands.

The remaining scan found no critical ambiguities requiring another question. Existing
session decisions retain short configuration names, the agent package/command, private
source evidence, explicit phone selection and a configurable telemetry project. Manual
exports remain the evidence input; unavailable external proof is an execution blocker.

| Category | Status | Resolution |
| --- | --- | --- |
| Functional scope and behavior | Resolved | Readiness plus closeout; existing live scenarios reused. |
| Domain and data model | Clear | Four case slots, explicit run references, immutable revisions. |
| Interaction and outcomes | Clear | Local checks; separate live invocations; explicit existing reviews. |
| Quality attributes | Clear | Bounded local work, privacy, no effects during readiness/closeout. |
| Integrations | Clear | Documented export formats; unsupported linkage stays blocked. |
| Edge cases | Clear | Mixed contexts, incomplete exports, stale reviews, tampering and conflicts. |
| Constraints and tradeoffs | Clear | No collectors, provisioning or expanded customer claims. |
| Terminology | Clear | Readiness, observed operation, source evidence and acceptance are distinct. |
| Completion signals | Clear | Software completion and live evidence closure reported separately. |
| Placeholders | Clear | No unresolved scope decisions. |

## User Scenarios & Testing

### User Story 1 - Prepare a live check without triggering it (Priority: P1)

An operator selects a database or phone case and sees which local prerequisites are
configured, missing or invalid, and which checks still need a real invocation or export.

**Why this priority**: It prevents trial runs merely to discover missing configuration.
**Independent Test**: With network and effects denied, inspect complete, incomplete and
invalid synthetic settings for each live case; receive only safe prerequisite labels.

**Acceptance Scenarios**:

1. Given a selected live case, when readiness runs, then all applicable local execution
   and evidence prerequisites are listed without contacting services, acquiring credentials,
   sending a phone request or creating a validation run.
2. Given syntactically complete configuration, when readiness succeeds, then it explicitly
   says identity validity, permissions, reachability and remote receipt remain unverified.
3. Given missing optional evidence access, when readiness runs, then execution readiness
   remains distinguishable from evidence readiness; missing export access cannot prove failure
   of the underlying service.
4. Given an invalid value or a secret embedded in an error, when readiness reports a blocker,
   then only the registered field label and safe reason appear.

### User Story 2 - Recognize real source exports accurately (Priority: P1)

An operator imports bounded native exports from the configured credential and telemetry
services and sees exact matches, conflicts or specific unsupported-evidence blockers.

**Why this priority**: Closeout must reflect actual source data, including documented formats.
**Independent Test**: Import synthetic fixtures shaped like documented native exports; verify
exact linkage, contradictory fields, missing spans, project mismatch and protected lease IDs.

**Acceptance Scenarios**:

1. Given a documented credential-service export, when imported, then request/response and
   exact lease evidence are read from supported native fields; conflicting field values fail.
2. Given either supported telemetry JSON envelope, when imported, then it yields the same
   normalized records; missing expected spans cannot become verified receipt.
3. Given a renamed telemetry project, when evidence is checked, then configured source
   identity and explicit native identity fields must agree; a name and an identifier are
   never treated as interchangeable without a private explicit binding.
4. Given protected lease values, incomplete exports, or identity-provider events without a
   documented operation link, when imported, then the corresponding claim stays blocked.
   A verified phone transaction remains distinct from independent provider audit evidence.

### User Story 3 - Close out explicitly selected live observations (Priority: P2)

An operator selects runs covering the four live cases and generates one immutable summary
of operation results, evidence gaps and existing customer reviews, without rerunning effects.

**Why this priority**: Phone decisions occur in separate runs; evidence must be reviewed together.
**Independent Test**: Build a closeout from deterministic private run fixtures; repeat with
missing/duplicate cases, mixed deployments, changed inputs, conflicting reviews and an interrupt.

**Acceptance Scenarios**:

1. Given explicit run IDs, when closeout runs, then it reports all four required case slots,
   supplied observations and absent slots; it never silently chooses the latest run.
2. Given inconsistent deployment contexts or multiple observations for a slot, when closeout
   runs, then it blocks the combined conclusion and identifies the safe reason.
3. Given unchanged live evidence and existing reviews, when closeout runs, then it shows all
   15 customer criteria exactly once with every selected run's applicable review disposition.
   It creates no new customer pass/alternative and does not collapse conflicting decisions
   into a single passing result.
4. Given changed, missing, interrupted or tampered source data, when closeout rebuilds, then
   it blocks or fails the affected conclusion; old snapshots remain available as historical
   observations rather than current proof.
5. Given successful observed cases but unsupported native audit linkage, when closeout runs,
   then operational completion and the remaining evidence/customer gates are shown separately.

### User Story 4 - Complete and record the live walkthrough (Priority: P2)

An operator performs the four authorized cases, imports genuine exports and records which
original 002 gates are satisfied, blocked or failed using the new workflow.

**Why this priority**: Software validation cannot replace real service enforcement evidence.
**Independent Test**: Follow the documented live walkthrough with fresh verified human
credentials and individually witnessed phone decisions; reconcile the resulting private records.

**Acceptance Scenarios**:

1. Given valid delegated access, when the database case runs, then the fixed read and exact
   lease cleanup are observed; actor-only denial attempts no database read and yields no
   usable credential. Unexpected credential issuance fails and triggers exact cleanup.
2. Given one explicitly selected phone case and a witness, when it runs, then approval
   permits only the simulated action and denial permits no action; each case has its own run.
3. Given missing credentials, permission, receipt or a witness, when the walkthrough cannot
   continue, then the corresponding live task remains open with an owner and safe reason.
4. Given source review is complete, when the ledger is updated, then each original 002 task
   links its proof or blocker without automatically changing tracked customer acceptance.

### Edge Cases

Invalid/expired tokens; absent extras; invalid TLS or discovery configuration; changing settings
between readiness and execution; aliased project names versus IDs; conflicting native fields;
empty/paginated/delayed exports; incompatible audit HMAC contexts; missing parent spans; forged
manifest provenance; stale code/catalog revisions; mixed deployments; duplicate observations;
changed evidence during closeout; concurrent writers; symlinks; interrupted capture or cleanup;
secret canaries in malformed inputs; and larger-than-allowed files must fail predictably.

## Requirements

### Functional Requirements

- **FR-001**: Provide scenario-specific local readiness with execution and evidence sections,
  registered check labels, safe reasons and explicit unverified external checks. Readiness
  must not perform network calls, obtain tokens/leases, send pushes, invoke models or persist runs.
- **FR-002**: Reuse selection and configuration validation, including short names and legacy
  aliases. Reject unknown/duplicate cases and invalid phone selection before reading credentials;
  report malformed configuration without revealing values. Execution rechecks prerequisites.
- **FR-003**: Preserve verified human/actor delegation, deterministic authorization, exact-action
  phone approval and exact-lease cleanup; no synthetic or administrative fallback, effect retry,
  automatic human decision or live security-policy weakening is allowed.
- **FR-004**: Accept the documented native credential-service lease field and supported telemetry
  row envelopes in addition to existing supported inputs; contradictory aliases and malformed
  envelopes fail. Existing import size, depth, count, provenance and privacy limits remain.
- **FR-005**: Verify receipt only from exact expected source/trace/run/span and parent linkage;
  distinguish native source IDs from display names. Write-key export acknowledgment alone is
  insufficient. Manual exports require no new runtime read credential.
- **FR-006**: Keep unsupported identity-provider audit linkage and protected-lease comparisons
  blocked with an evidence owner/reason; transaction responses cannot claim independent audit proof.
- **FR-007**: Capture an immutable private deployment-context identity for new live runs without
  credential values. Closeout must reject mixed contexts; legacy runs lacking it remain readable
  individually but cannot silently qualify for combined closeout.
- **FR-008**: Build closeout solely from 1–4 explicitly supplied distinct live run IDs, with at
  most one observation for each of the four fixed case slots. Show missing slots as blocked,
  preserve every supplied result and never choose a preferred retry automatically.
- **FR-009**: Revalidate execution integrity, source bytes, normalized evidence and review
  applicability before closeout finalization. Bind the snapshot to exact input revisions;
  changed inputs, missing inputs or concurrent edits cannot yield a passing closeout.
- **FR-010**: Display separate operational and evidence closure outcomes plus all 15 customer
  criteria with per-run review dispositions. Closeout grants no review, waiver or acceptance;
  unsupported, unreviewed and stale items remain visible, and contradictions are never hidden.
- **FR-011**: Keep contexts, source evidence and immutable closeout snapshots in owner-only ignored
  private storage. Public output permits only generated IDs, registered labels, enums, counts,
  UTC times and digests; native IDs, paths, setting values and review prose stay private.
- **FR-012**: Bound local readiness and closeout work; define explicit nonzero results for invalid,
  blocked, failed and interrupted work. Do not rerun operations or delete evidence on recovery.
- **FR-013**: Provide a reproducible walkthrough linking actual observations to 002 T036/T037,
  with software and live task completion recorded separately. Preserve all customer dispositions
  until explicit evidence review and deliberate publication.
- **FR-014**: Add deterministic boundary, privacy, cancellation and backward-compatibility tests;
  retain the slim dependency model, network-free CI and all existing software/publication gates.
- **FR-015**: Record compatibility, threat boundaries, remaining evidence owners and delivery
  prerequisites. Required checks, owner review, stale-review dismissal and default-branch
  protections must be verified before any later merge; planning does not configure them.

- **FR-016**: Verify every native transaction and operation binding belongs to its containing run,
  selected observation, source and exact approved action. Phone denial requires an observed human
  deny decision; expiry, timeout, cancellation or service failure cannot satisfy that case.
  Review eligibility must require relevant operation phases and exact referenced evidence, not
  merely source-kind presence; no new customer criterion is enabled by this feature.

### Key Entities

Readiness report and check; private deployment context; existing validation run, observation,
source artifact and per-run review; closeout snapshot containing four case slots, input revision
references and 15 criterion rows; sanitized live validation ledger.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Each of the four cases produces a complete local readiness report within two seconds
  on CI, with zero network/effect attempts and zero secret-canary leakage.
- **SC-002**: Equivalent supported source representations produce identical normalized evidence;
  every tested conflicting field, project, missing span and unsupported link avoids false receipt.
- **SC-003**: Rebuilding the same selected inputs yields the same closeout content revision,
  four case slots and 15 criterion rows; every mutation/conflict fixture prevents false closure.
- **SC-004**: Closeout of four maximum-supported run fixtures completes within ten seconds on CI
  excluding file I/O; readiness and closeout never execute or retry a live case.
- **SC-005**: All four live case slots have genuine observations or explicit blockers; a live gate
  is complete only after its actual proof is reviewed. Every acquired lease is revoked or has
  an explicit cleanup-failure outcome; denied phone actions execute zero writes.
- **SC-006**: All software gates pass without live credentials, and no raw evidence, source identity,
  credential or reviewer prose enters public output or publication artifacts.

## Assumptions

The existing configured PoC services and externally acquired human token are reused. The
operator can manually export source records with an authorized tool; this feature does not
grant that permission. Project naming remains private configuration. Readiness establishes
only local configuration sufficiency, never token validity or service entitlement. No fixed
maximum evidence age is invented: observation times and exact revisions remain visible for
review. Exports may arrive later, requiring a new immutable snapshot. Live prerequisites can
block execution without blocking implementation of deterministic software behavior.
