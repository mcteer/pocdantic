# Feature Specification: End-to-End PoC Closeout

**Feature Branch**: `feature/010-poc-closeout`
**Created**: 2026-10-10
**Status**: Software implemented; native acceptance remains blocked
**Input**: Complete the design checklist's Function 13 after merged 009: guided four-use-case
validation, a fifteen-criterion evidence matrix, controlled client-count reconciliation,
reproducible handoff and witnessed acceptance decisions.

## Context and scope

Features 001–009 provide the runtime and operational checks. Their separate reports do not
provide a single reviewable record of the target environment, all four demonstrations, actual
client measurements and customer decisions. The existing live closeout covers four database
and phone cases, not all four use cases.

010 provides an operator closeout workflow which freezes the reviewed environment, guides
existing live commands, collects and validates their evidence, calculates measurements and
prepares a private review package. It covers F13.01–F13.13, F13-T1–T6 and phase exit gates
P4-G1–G5. The final review keeps three distinct facts: observed behavior, sufficiency of proof,
and the human acceptance decision. Successful package creation never means customer acceptance.

Actors are the operator/PoC lead, agent engineering reviewer, Verify/Vault/VIP owners and
customer security reviewer. A role label records a person's attestation; it does not authenticate
that person. Source evidence and the actual witnessed review are required for native acceptance.

In scope: guided execution, environment snapshots, immutable evidence revisions, per-criterion
proof rules, local review records, four client-count scenarios, a private reproducible handoff,
and safe progress summaries with concrete next actions. Existing provider workflows remain
the execution surfaces. A missing native prerequisite results in a usable blocked package.

Out of scope: a new live execution engine, automatic user provisioning, provider configuration
changes, triggering phone prompts or destructive drills from closeout commands, a new browser
administration interface, commercial pricing predictions, changing original criteria to create
a pass, automated customer signoff, or publishing evidence. Operator CLI guidance complements
the existing browser sign-in/task workflow.

## Clarifications

### Session 2026-10-10

- Q: Should the new closeout workflow guide existing live commands and collect evidence, or
  also launch provider demos and the 100-user experiments itself? → A: Guide existing commands
  and collect evidence. No new authority to run live operations is added.

Earlier decisions continue to apply: use the local browser for user sign-in/tasks and WebKit
for browser validation; provide exact repair instructions; retain unsupported demo-cluster
audit as blocked; never substitute local tests for native proof. One question was asked and
answered. All ten ambiguity categories are clear after this decision: scope, domain/lifecycle,
interaction, quality, dependencies, failure behavior, tradeoffs, terminology, completion and
placeholders. Provider availability is an explicit operational prerequisite, not an unresolved
implementation choice.

## User Scenarios & Testing

### User Story 1 - Prepare and follow a complete demonstration (Priority: P1)

The operator freezes the intended environment and gets the steps, prerequisites, evidence to
capture and expected outcomes for UC1–UC4 before involving a customer or sending a phone prompt.

**Why this priority**: A missing prerequisite should be visible before an interrupted demo.
**Independent Test**: Create an isolated dossier with synthetic inventory and missing providers;
all four guides and fifteen criteria appear with concrete blockers and zero network dispatch.

**Acceptance Scenarios**:

1. Given a reviewed inventory, when a dossier is created, then versions, edition capabilities,
   identities, policy and dataset fingerprints, owners and source locations bind one revision.
2. Given an unsupported audit source or unavailable phone approval, when the operator inspects
   UC1/UC2 guidance, then it names the missing proof, responsible owner, exact action and recheck;
   it does not invent a dashboard path or launch a prompt.
3. Given UC3 and UC4, when guidance is requested, then it includes actual risk-event origin,
   independent revocation mechanisms, timing, pre-registration discovery and identity/ceiling
   evidence; local containment is not labeled native enforcement.
4. Given a changed environment or a stalled run, when evidence is gathered again, then the old
   revision remains inspectable and the operator is directed to explicit recovery/retest steps.

### User Story 2 - Assess all acceptance criteria from attributable evidence (Priority: P1)

Reviewers inspect one matrix containing all fifteen original criteria, measured outcomes,
source references, ownership and gaps, without mistaking a successful component for an accepted
end-to-end use case.

**Why this priority**: The matrix is the basis of every closeout decision.
**Independent Test**: Assemble synthetic representations of all supported evidence families;
missing, contradictory, stale, unrelated and forged-reference inputs cannot produce a pass.

**Acceptance Scenarios**:

1. Given valid evidence for a subset of criteria, when a snapshot is assembled, then all fifteen
   rows remain visible and incomplete rows are blocked with explicit owner/action information.
2. Given independently correlated native records, when a criterion is reviewed, then its exact
   proof obligations determine eligibility; an operator statement or uploaded screenshot alone
   cannot replace native enforcement evidence.
3. Given a provider denial caused by policy after revocation, when UC3-01 is evaluated, then
   the original JWT-validation requirement remains unmet; any agreed alternative is separate.
4. Given a later contradictory observation, changed member revision, unavailable input or stale
   observation, when inspection occurs, then the historical assessment is preserved and current
   applicability is qualified. A reviewer cannot hide a contradiction by selecting an older pass.

### User Story 3 - Reconcile controlled client-count experiments (Priority: P2)

The PoC lead compares actual resolved identities and client-activity exports for four controlled
scenarios, explains additional clients and reports which licensing assumptions remain unproven.

**Why this priority**: Agent invocation counts alone cannot establish provider client counts.
**Independent Test**: Analyze synthetic native-format exports and identity rosters covering
reused subjects, delayed exports, other consumers, multiple clusters and non-entity clients.

**Acceptance Scenarios**:

1. Given baseline activity and a scoped environment inventory, when a measurement is prepared,
   then its cluster, namespace, auth mounts, reporting interval, baseline consumers and cohort
   are fixed before any scenario evidence is admitted.
2. Given complete evidence, when the four scenarios are evaluated, then the report distinguishes
   100 executions of one agent, 100 humans using agent-only access, 100 distinct delegated humans,
   and 100 distinct direct clients; expected controlled cardinalities are 1, 1, about 101 and
   about 100 respectively, with reused identities and reporting semantics explained.
3. Given only a total count, fewer than 100 distinct required participants, synthetic identities,
   incomplete pagination/export, missing baseline or reporting lag, when analyzed, then the
   measurement remains blocked or failed rather than extrapolated into a measured pass.
4. Given duplicate exports, overlapping periods, activity from other consumers or a multi-cluster
   dataset, when reconciled, then sets are deduplicated within their documented provider scope;
   totals are not summed into an unsupported global or invoice prediction.

### User Story 4 - Review and hand over a reproducible closeout (Priority: P2)

The PoC lead gives reviewers a bounded private package containing the matrix, run instructions,
measured timing/counts, approved evidence attachments and a short readout, then records each
reviewer's actual decision against exactly that package.

**Why this priority**: Completion requires a reviewable handoff and explicit owner decisions.
**Independent Test**: Build and inspect a synthetic package, record all required role decisions,
and demonstrate that missing witnesses, changed bytes or unresolved original criteria prevent
unqualified final acceptance.

**Acceptance Scenarios**:

1. Given an assembled revision, when packaged, then it contains reproducible commands, fixture
   and reset guidance, sanitized configuration summaries, evidence locators, reviewed attachments,
   measured results, gaps and a concise readout; raw credentials never enter a package.
2. Given a witnessed meeting, when its decisions are recorded, then date, reviewer roles,
   attestation references and the exact evidence/package revision are mandatory; no command
   assumes attendance or approval from a label or elapsed time.
3. Given an agreed changed criterion, when decisions are recorded, then customer and relevant
   vendor agreement are captured without overwriting the original requirement or calling it Pass.
4. Given missing approval or current evidence, when final status is inspected, then it states
   ready-for-review, blocked, failed, accepted-with-exceptions or accepted as applicable, with
   the exact remaining step. All generated packages stay private until separately shared.

### Edge Cases

- Same source ID with different bytes; reused IDs across different provider instances; unrelated
  runs presented as one end-to-end demonstration; overlapping or mixed environment revisions.
- Provider evidence becomes too old during a meeting; a historical capture still has value but
  cannot assert that the live control is currently healthy.
- Interrupted imports/packaging; concurrent operators; hostile JSON, filenames, links or Markdown;
  over-limit inputs; a package or source changes while it is read.
- A screenshot is reviewed as sanitized but does not prove native causality; it remains supporting
  evidence. Reset steps cannot erase uncertain issuance, leases, holds or historical failures.
- One physical reviewer holds multiple roles; each role's explicit attestation is still required.
- Client activity export lags or lacks needed fields; human subjects reuse identities; agent
  definition, namespace, auth mount or cluster changes between baseline and observation.

## Requirements

### Functional Requirements

- **FR-001**: Provide a complete Function 13 inventory mapping thirteen build items, six tests,
  five exit gates, four use cases and all fifteen criteria to evidence and accountable owners.
- **FR-002**: Freeze a versioned environment inventory before gathering evidence: implementation,
  dependencies, product editions/capabilities, identity mappings, policy/dataset fingerprints,
  source instances and test scope; changed inputs require a new revision.
- **FR-003**: Provide concrete ordered UC1–UC4 guides using existing supported commands, exact
  required evidence, expected results and cleanup/recovery instructions; guides launch no effects.
- **FR-004**: Represent every prerequisite gap with an owner role, specific reason, executable
  local recheck or documented provider action, and expected recovery result; unavailable audit
  remains explicit and never becomes an ambiguous request for a token.
- **FR-005**: Import only explicitly selected, bounded evidence with source kind, identity,
  observation time, format and digest; validate reference closure and correlation before use.
- **FR-006**: Assemble exactly fifteen criterion rows with original meaning, observed outcome,
  proof sufficiency, measured result, source event/locator, owner, decision and exception links.
- **FR-007**: Define criterion-specific native proof obligations; simulations, acknowledgements,
  missing cleanup, local guard denials or screenshots alone cannot establish native acceptance.
- **FR-008**: Preserve independent distinctions among JWT validation, policy denial, token/lease
  revocation, existing database sessions, new login/issuance and application containment.
- **FR-009**: Bind evidence to its environment, revisions and point-in-time evaluation; preserve
  immutable historical assessments and report current drift/missing evidence independently.
- **FR-010**: Treat contradictory evidence and failed cleanup as failures; preserve all attempts,
  surface newer contradictions within the same scope, and prohibit cherry-picked older passes.
- **FR-011**: Prepare each client-count experiment with baseline export, exact scope and cohort,
  period/reporting semantics, other consumers and expected identity-to-entity mapping.
- **FR-012**: Require measured evidence for all four 100-execution/participant scenarios, distinct
  per-execution token/trace references and actual resolved entity identity; no automatic user
  provisioning, experimental execution or synthetic promotion occurs in closeout commands.
- **FR-013**: Reconcile actual activity sets, cohort and baseline with reuse, duplicate records,
  other consumers, non-entity clients, multiple clusters and reporting delay; explain every delta
  and block incomplete measurements without predicting an invoice.
- **FR-014**: Compute incident timing from correlated source timestamps and clock bounds; show
  uncertainty and actual duration against the original 30–60-minute baseline, not request latency.
- **FR-015**: Build a bounded private package with sanitized summaries, reproducible commands,
  fixture/reset guidance, evidence index, explicitly reviewed attachments and a short readout of
  functionality, security evidence, timing, counts, production gaps and sizing assumptions.
- **FR-016**: Record witnessed criterion and role decisions against exact evidence/package digests,
  with reviewer, role, date and attestation reference; required roles are agent engineering,
  Verify, Vault, VIP and customer security. Local labels do not authenticate reviewers.
- **FR-017**: Preserve the original criterion when an alternative is agreed; require explicit
  customer and relevant vendor decisions; compute final acceptance only from complete, applicable
  evidence and role decisions. Accepted exceptions are reported separately from full acceptance.
- **FR-018**: Keep original provider records, native identifiers, reviewer prose and generated
  packages private; safe summaries use fixed labels and opaque local references. No raw token,
  credential, customer payload or unreviewed attachment is allowed in a handoff package.
- **FR-019**: Bound reads, storage, parsing, computation and concurrency; interrupted operations
  cannot seal a complete revision, inspection has no effects, and partial artifacts remain visible.
- **FR-020**: Preserve existing CLI/schema contracts and native enforcement controls; add no
  dependency or environment variable unless separately justified; never alter tracked acceptance
  records automatically or change provider settings from the closeout workflow.
- **FR-021**: Supply meaningful positive, negative, privacy, drift, concurrency and interruption
  tests with isolated synthetic data; normal tests must produce zero provider dispatch.
- **FR-022**: Keep software implementation completion separate from native execution and witnessed
  signoff; deliver a complete usable workflow even when external proof remains unavailable.

### Key Entities

- **Dossier and environment revision**: stable local identity, intended test environment, bounded
  inventory and immutable revisions with accountable owners.
- **Evidence member**: source reference, original digest, normalized measurements, provenance,
  correlation and capture/evaluation times.
- **Criterion assessment**: one original criterion, proof obligations, evidence references,
  measurements, contradictions, blockers and human disposition.
- **Client experiment**: scenario, baseline/cohort/period, actual execution and activity identities,
  measured sets, explained differences and completeness.
- **Review and exception**: explicit person/role attestation against exact evidence and scope;
  alternative agreement does not rewrite the original criterion.
- **Package and final decision**: sealed evidence index, safe summaries, reviewed attachments,
  frozen readout and applicable role decisions with historical/current distinction.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Every new dossier lists all 13 build items, 6 tests, 5 exit gates, 4 use cases and
  15 criteria with no omitted or duplicated identifiers.
- **SC-002**: Every missing prerequisite in the supported catalog includes owner, action and
  expected recheck result; guide/inspect/import/package/review operations make zero provider calls.
- **SC-003**: Tests prove that every unsupported, synthetic-only, contradictory, stale, incomplete
  or unreviewed native claim cannot become an unqualified accepted result.
- **SC-004**: All four client scenarios distinguish execution count from entity/client cardinality,
  verify the required cohort, and account for every observed delta or explicitly block the result.
- **SC-005**: A 15-row report plus 10,000 normalized activity records assembles within 5 seconds
  excluding file I/O; each local operation ends within 30 seconds including cleanup, and interrupted
  writes are never reported complete.
- **SC-006**: Re-inspecting an unchanged package yields identical content/digests; any changed
  evidence, attachment or review dependency is detected. Full acceptance requires all 15 original
  criteria and all five role decisions; documented exceptions produce a distinct final result.

## Assumptions

- The supplied Function 13 design establishes scope; private source documents are not copied
  into public artifacts. Public descriptions are sanitized summaries.
- Operator workflows run locally on the existing macOS/Linux environment; current browser
  sign-in and provider commands remain usable and retain their separate authorization controls.
- Existing source exports and explicitly reviewed native attachments are the supported input
  mechanism. Provider data unavailable in the demo tier is a documented blocker with an owner.
- Four 100-participant experiments may require separately provisioned test identities, entitled
  reporting access and a suitable measurement period. Creating these resources is owner work.
- An actual witnessed meeting and external acceptance can occur after software delivery; their
  absence does not excuse unfinished implementation, and implementation cannot fabricate them.
