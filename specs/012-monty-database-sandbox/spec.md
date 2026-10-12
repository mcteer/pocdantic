# Feature Specification: Monty Database Sandbox

**Feature Branch**: `012-monty-database-sandbox`

**Created**: 2026-10-12

**Status**: Draft — requirements reviewed; implementation not started

**Input**: Incorporate local Pydantic Monty so a language model can generate Python
containing a PostgreSQL query, use temporary Vault credentials through a trusted tool,
and demonstrate useful computation and prevention of unauthorized host access.

## Context

An IBM employee should be able to ask a database question, watch generated code execute
in Monty, and explain which boundary allowed or rejected each operation. Merely replacing
a fixed query with generated SQL would not demonstrate Monty's isolation. The demonstration
therefore includes successful query-and-compute work, blocked attempts to access the host,
and rejected database requests, each attributed to the responsible boundary.

Vault remains responsible for supplying temporary database credentials. The trusted database
tool obtains and uses them for the signed-in user. Generated code and the model receive
permitted records and computed results, never credentials or a connection object.

## Clarifications

### Session 2026-10-12

- Carried forward from the discussion: Monty must allow the trusted tool to obtain Vault
  credentials; only generated code and model context are excluded from credential custody.
- No additional questions were needed. Read-only first scope, optional local execution,
  the browser workflow and visible sandbox demonstrations follow the agreed direction.
  Exact dependency APIs, query grammar and enforcement budgets are design decisions.
- User scenario refinement: a database query agent is asked to execute commands on a remote
  Linux host. Show both the natural-language request and a controlled generated-code probe;
  a model refusal alone is not evidence that Monty rejected an operation.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Ask and compute over permitted records (Priority: P1)

A signed-in employee selects a database-analysis profile and asks a question about the
configured PoC records. The model generates a program containing a read-only query and
computations over returned results. The employee sees the answer and an optional execution
explanation. Existing fixed-record demonstrations remain available.

**Why this priority**: Establishes the useful business flow and the reason to run code.

**Independent Test**: With a synthetic records dataset and real local Monty execution,
run filtering, grouping and percentage examples; compare their results with known answers.
Separately repeat the positive flow with an authorized live provider and database.

**Acceptance Scenarios**:

1. **Given** permitted records and a signed-in user with database read permission, **When**
   the user asks for the percentage of records in each status, **Then** generated code
   requests a supported query, computes percentages, and returns the correct bounded answer.
2. **Given** a different request to list IDs above a supplied threshold, **When** it runs,
   **Then** the query and parameters reflect that request rather than selecting a predefined
   whole-query template, and only permitted records are returned.
3. **Given** a valid query, **When** the trusted tool obtains Vault credentials, **Then**
   it connects and reads, closes the connection and independently confirms applicable lease
   and native-token cleanup; generated code sees neither credential.
4. **Given** no matching rows, **When** computation completes, **Then** the user sees an
   empty result with no fabricated facts or divide-by-zero error.

### User Story 2 - Show exactly what the sandbox blocks (Priority: P1)

A presenter asks the database query agent to run a command on a remote Linux host,
and runs repeatable demonstrations of generated code attempting that prohibited access. The outcome identifies Monty's boundary, the query tool's boundary, or the provider's
boundary, so viewers understand what has actually been demonstrated.

**Why this priority**: Makes Monty's contribution visible and avoids claiming SQL inspection
or provider enforcement from sandbox isolation alone.

**Independent Test**: Execute fixed hostile programs in real Monty with controlled synthetic
host callbacks and counters; verify every forbidden effect count is zero.

**Acceptance Scenarios**:

1. **Given** a program that tries to read a file, environment secret, open a socket or launch
   a process, **When** executed, **Then** host access is unavailable and no Vault or database
   call occurs in each isolated test; the report attributes the result to the sandbox.
2. **Given** code calling the exposed query tool with a write, unapproved table, unsupported
   expression or extra statement, **When** submitted, **Then** the tool rejects it before
   acquiring credentials and the report attributes rejection to query policy.
3. **Given** looping, allocating, printing or repeatedly calling code, **When** it exceeds
   a documented limit, **Then** it stops within its bound and cannot obtain further authority.
4. **Given** successful allowed work followed by a rejected operation, **When** the run ends,
   **Then** prior effects remain visible and the run cannot be labelled a wholly denied,
   zero-effect request or a fully successful execution.
5. **Given** a request to run a command on a remote Linux host, **When** the model declines
   without submitting code, **Then** report model refusal and sandbox not exercised. When a
   controlled probe attempts process launch, a network connection or an unexposed remote-command
   function in Monty, report the sandbox denial and zero remote connections or credential calls.

### User Story 3 - Contain interrupted work and preserve cleanup (Priority: P1)

An operator can cancel, sign out or recover after a failed sandbox run without leaving
usable authority silently abandoned or replaying database effects.

**Why this priority**: Generated programs must preserve the existing credential lifecycle.

**Independent Test**: Interrupt execution before acquisition, during a database read and
after its return; verify exact cleanup and durable uncertainty on lost responses.

**Acceptance Scenarios**:

1. **Given** active work, **When** the user signs out or cancels, **Then** new callbacks stop,
   an in-flight query is cancelled, connection cleanup and credential revocation are attempted,
   and the worker cannot resume or affect a subsequent user's session.
2. **Given** a worker crash or lost provider response, **When** the run finishes, **Then**
   it reports failure or unresolved cleanup accurately and existing recovery blocks replay.
3. **Given** a second user or a restarted process, **When** starting analysis, **Then** no
   generated variables, data, credentials or authority from the earlier run are reused.

### User Story 4 - Run the demonstration on a colleague's machine (Priority: P2)

A colleague follows the setup guide, adds optional sandbox support, and runs the demonstration
on macOS or Linux without deploying an additional service. Existing PoCs work without it.

**Why this priority**: Keeps employee PoCs portable and repeatable.

**Independent Test**: Follow the documented install and offline demonstration on both platforms,
then open the workspace; an installation without the extra gives an actionable unavailable state.

**Acceptance Scenarios**:

1. **Given** sandbox support is installed, **When** running the offline demonstration,
   **Then** real Monty executes the programs with synthetic records and no provider traffic.
2. **Given** support is missing or incompatible, **When** selecting analysis, **Then** setup
   names the missing prerequisite; code is never executed by an unrestricted fallback.
3. **Given** the execution explanation, **When** inspecting the result, **Then** the user can
   see whether generation, sandbox execution, query authorization, database execution and
   cleanup succeeded, failed, were skipped or remain unresolved.

### Edge Cases

- Invalid generated syntax, unsupported imports, disguised tool calls and fabricated tool results.
- Malicious instructions embedded in returned status text; all database content remains untrusted.
- Multiple statements, writable expressions inside reads, comments, quoting, Unicode identifiers,
  catalog access, functions with side effects, expensive queries and row-locking clauses.
- Oversized source, parameters, rows, result cells and final output; empty and truncated results.
- Expired identity, changed policy, concurrent callbacks and a revoked session between callbacks.
- Timeout during issuance, query, cleanup or model response; worker exit while host work is pending.
- Repeated submissions, caught exceptions, old sandbox state and unavailable optional packages.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Offer an explicit optional analysis profile in the existing workspace and CLI;
  ordinary fixed-record profiles and both existing authentication routes MUST remain compatible.
- **FR-002**: Generate code from the user's question and a curated schema description. Support
  filtering, selecting fields, grouping/counting and calculation over results for the existing
  PoC records dataset. The model MUST generate the query, rather than choose only a fixed query.
- **FR-003**: Execute generated code only through local Monty with supplied input and the single
  approved database-query tool. Host files, environment, sockets, process launch, arbitrary
  imports and credentials MUST be inaccessible; no unrestricted execution fallback is allowed.
- **FR-004**: Resolve the human identity and policy outside generated code and enforce them
  before each database effect. A model assertion, generated identity or previous successful
  callback MUST NOT grant authority for a subsequent request.
- **FR-005**: Enforce a documented, narrow read-only query language against explicitly permitted
  tables and columns before credential acquisition. Reject every unsupported construct; keep
  data parameters separate from query structure. Read-only database grants and transaction
  controls MUST independently constrain execution.
- **FR-006**: Obtain temporary credentials through the existing configured Vault route only
  after query admission. The trusted adapter MUST own connection handling and the existing
  durable issuance/cleanup lifecycle. Credentials and native handles MUST NOT enter generated
  code, model context, browser results, logs or traces.
- **FR-007**: Bound source, input, parameters, result rows/bytes, output, execution time, memory
  and host calls. Each run permits one generated program and at most three sequential database
  calls. Sandbox computation is limited to two seconds, active execution to thirty seconds
  and terminal credential cleanup to the existing thirty-second reserve; stricter existing
  limits prevail. Resource violations MUST stop new effects and be observable.
- **FR-008**: Cancellation, sign-out, policy containment and worker failure MUST stop new work,
  retain ownership of in-flight host operations until drained, and attempt exact cleanup.
  Uncertain issuance or cleanup MUST preserve a blocking recovery record; no diagnostic replay.
- **FR-009**: Isolate each run's code, data and state, including across worker reuse, identities
  and restarts. Execution identifiers and admission decisions MUST bind to the original run
  and cannot be supplied or altered by generated code.
- **FR-010**: Provide an execution explanation showing generated program/query on explicit
  inspection by the owning signed-in user, bounded results and boundary-specific outcomes.
  Render content as inert text. Default telemetry and reports contain bounded metadata only;
  raw code, SQL parameters, records and provider bodies MUST NOT enter exported evidence.
- **FR-011**: Ship repeatable offline demonstrations using the actual sandbox engine for useful
  computation, prohibited host access, rejected queries and resource limits. Label synthetic
  database/Vault behavior clearly and distinguish blocked attempts from unattempted operations.
  Include the remote-Linux-command scenario and distinguish model refusal from actual sandbox
  rejection; the controlled probe MUST make no connection to a real remote host.
- **FR-012**: Preserve original acceptance and closeout semantics. Native provider claims require
  independently reviewed live evidence; sandbox demonstrations MUST NOT promote those claims.
- **FR-013**: Document installation, supported platforms, sample questions, the Vault credential
  flow, boundaries, limitations and recovery in the setup guide and AGENTS.md. Missing optional
  dependencies MUST produce concrete repair instructions without disrupting existing profiles.
- **FR-014**: Require negative, cancellation, cleanup, replay, privacy and browser coverage,
  actual Monty worker tests and an isolated real PostgreSQL test of the permitted query subset.
  Review new dependencies/licenses and the changed security boundary before delivery.

### Key Entities

- **Analysis run**: verified owner, immutable run identity, generated program, execution budget,
  query attempts, permitted result and terminal outcome.
- **Query request**: proposed read-only query and separate bounded parameters, bound by the
  trusted host to a run; it conveys no credential or authorization of its own.
- **Admitted query**: immutable approved query structure, parameter binding, scope and limits.
- **Boundary observation**: attempted action, responsible boundary, outcome, counts and correlation;
  it distinguishes synthetic and live execution without exposing source data.
- **Credential custody**: existing durable token/lease attempts and exact cleanup receipts owned
  by the trusted database adapter; generated code cannot read or modify this state.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Three different supported questions (filtered records, grouped counts, percentages)
  produce correct results on the published synthetic dataset; two requests yield meaningfully
  different admitted queries and at least one requires computation after data retrieval.
- **SC-002**: Every case in the reviewed negative demonstration catalog prevents its forbidden
  effect, reports the responsible boundary and preserves accurate counts of earlier effects.
- **SC-003**: All cancellation, sign-out, crash and lost-response cases either confirm exact
  cleanup or retain an actionable unresolved record; none silently replay or report false success.
- **SC-004**: Every resource-limit case terminates within the declared execution/cleanup bounds,
  and a subsequent run remains usable without seeing prior run state.
- **SC-005**: A fresh macOS and Linux installation runs the offline demonstration using the
  documented commands without source edits or an additional sandbox service; missing support
  gives the exact installation step. Existing profile regression checks pass without the extra.
- **SC-006**: One reviewed live run demonstrates model generation, permitted database execution
  with temporary credentials, computation and confirmed cleanup. Software checks and missing
  external prerequisites are reported separately; all fifteen original native criteria retain
  their independent evidence requirements.

## Assumptions

- Local open-source Monty is the requested execution engine. Full Monty deployment, arbitrary
  CPython packages, shells, persistent sandbox sessions and user-uploaded programs are out of scope.
- Start with `public.poc_records(id, status)` and synthetic demonstration data; arbitrary schemas,
  joins, writes and administrative queries are excluded from this increment.
- The configured model may receive the user's task, curated schema and permitted result data;
  the operator selects an appropriate model for that data. Sandbox isolation does not change
  the model provider's data policy or detect all malicious intent.
- Generated SQL is an explicit extension to the fixed-query repository guidance. Implementation
  will update that guidance narrowly for this profile while retaining deterministic admission,
  parameter separation and least privilege. No constitution change is needed.
- Existing OIDC, Vault, database, recovery and response enrollment remain prerequisites for
  live work. No new administrator credentials or automatic provider provisioning are introduced.
- Automated demonstration programs are fixed security probes; the interactive positive flow
  uses the model. Test outcomes prove the tested boundaries, not universal sandbox security.
