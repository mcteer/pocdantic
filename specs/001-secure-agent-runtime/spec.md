# Feature Specification: Reusable secure agent runtime

**Feature Branch**: `main`
**Created**: 2026-10-09
**Status**: Implementable local baseline; vendor acceptance pending
**Owner**: maintainer
**Input**: Build a configurable customer PoC template with constrained agents and evidence gates.

## User Scenarios & Testing

### User Story 1 - Bounded delegation (Priority: P1)
An authenticated user asks the parent to retrieve a ticket. The parent delegates to a read-only child.
**Independent Test**: Offline deterministic model completes delegation with typed output.
**Acceptance Scenarios**:
1. Given verified identity, when requesting an allowed ticket, then parent and child runs correlate.
2. Given forged identity or a disallowed resource, when invoking a tool, then deny before any effect.
3. Given injection in ticket content, when it asks for a write, then child cannot perform that write.

### User Story 2 - Reconfigure a PoC (Priority: P1)
An operator supplies provider, identity credentials and telemetry key without modifying source.
**Independent Test**: Two agent definitions compose different capabilities using one runtime.
**Acceptance Scenarios**:
1. Given IBM Verify or generic OIDC configuration, when invoking ingress, then validate signed identity.
2. Given a Logfire write key, when running an agent, then export metadata without content or secrets.
3. Given a batch of requests, when one fails, then emit independent structured results and nonzero exit.

### User Story 3 - Trusted credentials and approval (Priority: P2)
A trusted executor exchanges delegated authority, acquires a read-scoped lease, uses it and revokes it.
A parent-only simulated infrastructure write requires action-bound approval before execution.
**Independent Test**: Mock transport proves exchange schema, cleanup, and all negative approval cases.
**Acceptance Scenarios**:
1. Given a read action, when credential use finishes or fails, then revoke its exact lease.
2. Given pending, denied, expired, replayed or mutated approval, then no privileged effect occurs.
3. Given a matching approval from a trusted backend, then recheck policy and execute once.

### User Story 4 - Evidence and containment (Priority: P2)
An operator tracks acceptance separately from software readiness and contains one run or a definition.
**Independent Test**: Evidence validator rejects mock-only live acceptance and unreviewed phase gates.
**Acceptance Scenarios**:
1. Given a blocked vendor feature, when generating a report, then report blocked with owner and reason.
2. Given two runs of one definition, when containing one, then the other can continue.
3. Given definition containment, when running again, then deny until authorized recovery.

### Edge Cases
Timeouts, malformed JWTs, wrong audience/type, unknown capabilities, changed approval parameters,
cleanup errors, retries after containment, URL/path injection, unsupported vendor features and missing
provider packages fail closed. Mock adapters are never selected automatically after live failures.

## Requirements

### Functional Requirements
- **FR-001**: Provide typed requests/results with server-owned request/run/definition correlation.
- **FR-002**: Verify external identity before model execution; reject self-asserted authority.
- **FR-003**: Compose alternate agents with named, reviewed capability allowlists.
- **FR-004**: Enforce principal, logical agent, action and resource policy at every trusted effect.
- **FR-005**: Restrict child toolsets; share timeout and usage budgets with parent.
- **FR-006**: Configure OAuth discovery, client authentication, scopes and audience for each provider.
- **FR-007**: Support delegated token exchange and exact Vault path RAR without exposing credentials.
- **FR-008**: Use per-request dynamic credentials; close connections and explicitly revoke leases.
- **FR-009**: Bind approval to action/requester/resource/parameters and consume it once.
- **FR-010**: Connect Logfire with a write API key; omit model/tool content and request parameters.
- **FR-011**: Provide repeatable JSONL batch execution and deterministic offline demo.
- **FR-012**: Enforce Git privacy locally and in CI; exclude private files from distributions.
- **FR-013**: Record acceptance disposition, evidence source, owner and reviewer for 15 criteria.
- **FR-014**: Separate run containment from definition containment and external revocation semantics.

### Key Entities
Verified principal, stable agent definition, invocation context, tool action, bound approval,
credential lease, sanitized audit event, acceptance evidence and phase gate.

## Success Criteria
- **SC-001**: A clean checkout installs with locked dependencies and runs an offline delegated demo.
- **SC-002**: All identity, policy, approval, containment and cleanup negative tests pass.
- **SC-003**: Changing a PoC identity provider or telemetry key requires configuration only.
- **SC-004**: No private input or credential is present in tracked files or distribution artifacts.
- **SC-005**: All 15 acceptance criteria have explicit disposition; live passes require source evidence.

## Assumptions
Initial write target is a simulated infrastructure action. Deployment issuer remains configurable.
Jira retrieval is synthetic until a target adapter is configured. Tenant-dependent workload mapping,
Verify push, Vault licensing/registry/RAR, PostgreSQL grants, VIP collectors and remediation are live
acceptance dependencies, not assumed platform features. No tenant resources are provisioned by default.


## Delegated identity follow-up

The local chat host in ignored chat/ uses a separate confidential OIDC client,
authorization code with S256 PKCE and cookie-bound state, a fixed loopback callback,
and signed API-audience access-token verification. Tokens and conversation context
remain in expiring server-side sessions; ID/refresh tokens are ignored. The frontend
is excluded from Git and distributions. Hosting applications may supply their own
verified access tokens and user-isolated message history.

Before token exchange, independently verify the user access token and actor access token.
Reject service credentials in user-only ingress and reject an actor equal to the user.
Verify returned subject, actor issuer/subject and exact requested authorization details.
A database-read grant does not authorize cleanup. Obtain a second delegated grant for
sys/leases/revoke with the exact lease_id as required/allowed parameter; never broaden
the read token or substitute an operator credential. Cancellation shields this cleanup.
Failure to acquire cleanup authority prevents a success result; TTL remains the backstop.
