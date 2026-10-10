# Feature Specification: Observable, repeatable security validation

**Feature Branch**: `feature/002-security-validation`
**Created**: 2026-10-09
**Status**: Planned; tasks generated; awaiting implementation
**Owner**: maintainer
**Input**: Turn the completed secure agent harness into a repeatable customer demonstration with live telemetry proof, security scenarios, cross-system audit correlation and reviewer-controlled acceptance reporting.

## Context and scope

Feature 001 established the reusable harness and demonstrated real delegated database access
and exact-lease cleanup. Operators now need a repeatable way to exercise its security boundaries,
explain each outcome, and distinguish an observed result from reviewed customer acceptance.
The operator runs validations; a named reviewer assesses evidence. The same person may perform
both roles in this PoC, but an explicit review action is always required.

In scope: repeatable scenario selection, bounded execution, metadata-only observability,
source evidence correlation, private evidence handling and sanitized reports. Supported live
services are the configured identity provider, credential service, database and telemetry
project. Provider-specific evidence may be supplied through explicit private exports.

Out of scope: new workload attestation/SVID deployment, VIP discovery or remediation,
external session/token revocation, production infrastructure changes, a new frontend,
unattended human approval, automated service provisioning and automated acceptance signoff.
The local chat stays excluded from publication. Deployment remains configurable.

## Clarifications

### Session 2026-10-09

The initial clarification scan needed no new questions. The accepted scope and prior user decisions establish
configurable deployment, simulated infrastructure writes, an ignored frontend and private
source evidence. This scan retained documented defaults: offline automation, explicitly
selected live/interactive scenarios, manual source exports where read access is unavailable,
and an explicit reviewer action separate from observed execution success.

| Category | Status | Resolution |
| --- | --- | --- |
| Functional scope and behavior | Clear | Four stories; explicit exclusions. |
| Domain and data lifecycle | Clear | Stable definitions, unique runs, evidence-bound review. |
| Interaction and outcomes | Clear | Operator invocation and reviewer action; terminal states. |
| Quality attributes | Clear | Repeatability, bounded execution and zero-canary leakage. |
| Integrations | Clear | Existing services; optional private evidence imports. |
| Edge cases | Clear | Interruption, stale/missing evidence and export failures. |
| Constraints and tradeoffs | Clear | Slim dependencies, no provisioning, configurable deployment. |
| Terminology | Clear | Execution outcome differs from customer acceptance disposition. |
| Completion signals | Clear | Six measurable outcomes; explicit proof requirements. |
| Placeholders | Clear | None remain. |

- Q: Apply explicit single-scenario phone selection and constrain output to ignored .local/ before the model switch? → A: Apply both fixes. Phone runs require exactly one named scenario; output must stay beneath the project private .local/ root, verified ignored when inside Git.

## User Scenarios & Testing

### User Story 1 - Run a repeatable security demonstration (Priority: P1)

An operator selects a named suite and receives one result per scenario plus an overall report,
without writing a new test script for each customer.

**Why this priority**: Repeatable scenarios provide the foundation for every later evidence claim.
**Independent Test**: Run the offline suite twice without credentials or network access; each run
has new identifiers and the same expected scenario outcomes.

**Acceptance Scenarios**:

1. Given an offline suite, when it runs, then it exercises delegated reads, policy denial,
   attempted injection, approval denial/replay/mutation, cleanup failure and cancellation,
   asserting the trusted effect boundary rather than the model's wording.
2. Given a configured live read suite and valid human authorization, when it runs, then it
   verifies delegated identity, obtains a database credential, reads a fixed record and
   proves explicit revocation of that exact lease before the scenario can pass.
3. Given missing credentials, optional packages, expired identity or unavailable services,
   when a live scenario cannot run, then its prerequisite failure is reported as blocked
   without substituting a synthetic result.
4. Given a selected live phone scenario, when the operator starts it explicitly, then it
   requests a real human decision for the simulated action; no automated decision is invented.
5. Given a failure or interruption, when execution terminates, then completed results remain
   available, pending work is identified and acquired leases receive bounded cleanup attempts.

### User Story 2 - Inspect a confidential-data-free execution trace (Priority: P1)

An operator supplies a telemetry project key and follows a validation from the initiating
request through the parent, child, trusted authorization, approval and credential lifecycle.

**Why this priority**: The demonstration needs to explain why an effect was allowed or denied.
**Independent Test**: Capture spans locally with synthetic canaries, verify their correlation
and absence of sensitive content, then verify receipt of a real run in a configured project.

**Acceptance Scenarios**:

1. Given a write key, when validation emits telemetry, then all selected lifecycle events use
   stable definitions and distinct invocation identifiers with consistent parent relationships.
2. Given secret canaries in credentials, messages, tool results and upstream errors, when
   local spans, console output and reports are inspected, then none of those canaries appear.
3. Given telemetry export success alone, when the report is produced, then it does not claim
   remote receipt; matching project evidence is required for a received disposition.
4. Given telemetry failure, when the operational scenario otherwise succeeds, then credential
   cleanup still completes and the required observability check remains blocked or failed.

### User Story 3 - Correlate trustworthy source evidence (Priority: P2)

An operator supplies private source exports and sees which assertions have matching evidence
from the harness, identity provider, credential service and telemetry project.

**Why this priority**: Application logs alone cannot prove enforcement by another service.
**Independent Test**: Import synthetic exports with known identifiers, then prove that matching,
missing, ambiguous, stale and tampered evidence produce distinct, correct dispositions.

**Acceptance Scenarios**:

1. Given source events with matching service operation identifiers and a run binding, when
   correlation runs, then it records the exact link and evidence provenance.
2. Given only similar timestamps, mismatched identifiers or duplicate conflicting events,
   when correlation runs, then the claim remains blocked or fails with a specific safe reason.
3. Given unavailable audit export permissions or an unsupported provider format, when a
   report runs, then it names the missing evidence and owner without fabricating a match.
4. Given an import containing credentials or unrecognized fields, when it is processed,
   then raw material stays private and only allowlisted metadata reaches reports or telemetry.

### User Story 4 - Review and reproduce acceptance decisions (Priority: P2)

A reviewer examines scenario results and source evidence, records a decision, and produces
an acceptance report whose findings can be traced to a specific run and evidence revision.

**Why this priority**: A successful demonstration must not silently promote customer acceptance.
**Independent Test**: Build and review a report from fixtures; reject local-only acceptance,
missing reviewer data and stale reviews after evidence changes.

**Acceptance Scenarios**:

1. Given completed scenarios, when the report is generated, then execution outcomes and
   customer acceptance dispositions are separate, with a result for every selected scenario
   and every existing customer criterion.
2. Given a passing observation without review, when acceptance is evaluated, then it remains
   blocked; a named, timestamped review must bind the exact evidence revision.
3. Given changed or missing evidence after review, when acceptance is reevaluated, then the
   stale review cannot authorize a pass or alternative disposition.
4. Given another PoC configuration, when the same suite runs, then customer endpoints and
   credentials come from configuration and no source changes are needed.

### Edge Cases

Missing/expired identity; endpoint denial; rate limits; duplicate selection; an unknown scenario;
interruption during cleanup; a second interrupt; model refusal without a tool attempt; source
clock skew; delayed trace export; malformed/oversized evidence; overlapping identifiers;
concurrent report writers; failed atomic writes; filesystem links escaping the private root;
old report formats; a changed suite revision; unavailable optional extras; and evidence changed
after review must yield bounded, explicit outcomes without secret leakage or false success.

## Requirements

### Functional Requirements

- **FR-001**: Provide named, versioned suites and scenario selection with declared prerequisites,
  expected effects and evidence requirements; reject unknown or duplicate selections before effects.
  A live phone invocation requires exactly one explicitly named scenario.
- **FR-002**: Default to an entirely offline mode that ignores local live credentials and telemetry
  configuration. Live mode requires explicit selection; CI executes offline mode only.
- **FR-003**: Cover allowed delegated reads, forbidden actions, injection attempts, approval denial,
  expiry, replay and changed parameters, cleanup failure and cancellation. A negative scenario passes
  only when the expected denial and absence of the forbidden effect are both observed.
- **FR-004**: Live database scenarios must use genuine verified human/actor delegation and the
  existing least-privilege path, with no operator-token fallback. Real phone checks require a
  selected interactive scenario and must retain exact-action approval and simulated writes.
- **FR-005**: Bound scenario count, time, model/tool usage, retained evidence and cleanup time;
  preserve partial results on interruption and never report success after cleanup failure.
- **FR-006**: Emit a correlated metadata-only lifecycle covering request, parent/child runs,
  trusted decisions, approvals and credential acquisition/use/revocation when those stages occur.
- **FR-007**: Allow telemetry export to any supported project by a write key and configurable
  region/base endpoint. No read credential is required merely to run or export.
- **FR-008**: Distinguish export attempted, export acknowledged and receipt verified. Receipt
  verification needs a matching private project export or explicitly configured read access;
  missing read access alone must not prevent normal agent execution.
- **FR-009**: Exclude credentials, bearer tokens, lease values, customer identifiers, prompts,
  model output, tool payloads, SQL data and arbitrary upstream errors from telemetry, stdout and
  sanitized reports. Automated canary checks must exercise both success and failure paths.
- **FR-010**: Import bounded, versioned private evidence from the supported services with source,
  observation time, content digest and operation/run bindings. Treat imported content as untrusted.
- **FR-011**: Correlate using exact source identifiers bound to a run; timestamps may support a
  match but never establish one alone. Missing evidence is blocked; contradictory or tampered
  evidence fails the relevant check.
- **FR-012**: Produce versioned machine-readable and human-readable reports with selected and
  completed counts, expected versus observed outcomes, source strength, correlation, limits,
  safe error codes and missing prerequisites. Non-success must produce a nonzero process result.
- **FR-013**: Keep execution results separate from the 15 existing customer acceptance criteria;
  scenario mappings contribute evidence and never automatically set customer pass/alternative.
- **FR-014**: Require live source evidence, a named reviewer, review time, observation time and
  an unchanged evidence digest for a customer pass/alternative. Review records are attributed
  local records, not cryptographic proof of the reviewer's identity.
- **FR-015**: Preserve customer-neutral reusable configuration. No provider administration,
  permission changes or production writes occur as a side effect of validation.
- **FR-016**: Keep private imports, evidence mappings, reports and review records under a private
  ignored .local/ root with owner-only access. Reject output roots outside that private root or
  not ignored by Git before writing. Public summaries use opaque evidence references and
  require deliberate selection for publication; no automatic Git staging or upload occurs.
- **FR-017**: Add meaningful deterministic regression, boundary and interruption tests and
  verify wheel/source-package privacy while preserving the optional integration dependency model.
- **FR-018**: Record each unsupported or unverified vendor capability with an owner and reason;
  retain configurable deployment and the existing semantics of lease, token and session revocation.

### Key Entities

Suite and scenario definitions; validation run; scenario observation; correlated lifecycle event;
private source evidence; correlation result; reviewer decision; acceptance disposition; sanitized
report. Definitions remain stable across runs; runs and observations have distinct identifiers.

## Success Criteria

### Measurable Outcomes

- **SC-001**: A single invocation runs the selected suite and produces both report formats with
  exactly one terminal result per selected scenario, including blocked and interrupted cases.
- **SC-002**: Ten consecutive offline runs produce identical expected outcome classifications
  with distinct run identifiers, use no network and each complete within 30 seconds on CI.
- **SC-003**: Every covered negative boundary demonstrates zero forbidden effects, and every
  acquired test lease is either explicitly revoked or reported as a cleanup failure.
- **SC-004**: Every required lifecycle stage in the live demonstration is linked to its run;
  receipt/correlation claims with missing or mismatched source evidence never pass.
- **SC-005**: All seeded confidentiality canaries are absent from exported telemetry, console
  output and sanitized reports across success, denial, exception and cancellation cases.
- **SC-006**: All 15 customer criteria retain explicit dispositions; no pass/alternative survives
  missing review, local-only proof or changed evidence. Two PoC configurations use the same suite
  without source edits.

## Assumptions

The operator controls the private workspace and is authorized for configured PoC resources.
A fresh user token is acquired by an existing host and supplied privately; this feature does not
build another login UI or access the ignored chat's memory/control socket. Live phone scenarios
may wait for a human. Fault injection is confined to offline adapters; it never disables a live
security policy. Live receipts may arrive after execution and be attached during report assembly.
An unavailable export/API permission blocks the affected evidence claim rather than software work.
The existing 15-criterion catalog remains the customer acceptance baseline. Raw exports are
operator-supplied private inputs; automated collectors and retention-policy administration are
future work. Routine cleanup deletes no operator evidence automatically.
