# Feature Specification: Portable PoC Setup

**Feature Branch**: `011-portable-poc-setup`
**Created**: 2026-10-11
**Status**: Planned
**Input**: Make the harness simple and repeatable for other IBM employees to connect to their own Vault instance and OIDC provider for PoCs.

## Clarifications

### Session 2026-10-11

No additional user answers were needed. The existing directive establishes a reusable core
with explicit optional capabilities. Planning defaults remain IBM Verify plus Keycloak for
independent validation and actual colleague participation for usability acceptance.
Technical clarification: standard Vault JWT service tokens may advertise renewal; the harness
never renews them and requires a verified hard lifetime cap. Cleanup authorization is limited
to the dedicated PoC database role; the trusted adapter restricts calls further to its own lease.
This baseline does not claim provider-enforced per-lease delegated authority.

## User Scenarios & Testing

### User Story 1 - Set up a colleague's PoC (Priority: P1)

An IBM employee follows one short guide, supplies their own provider configuration privately,
checks prerequisites, signs into the local workspace, and completes a bounded read with
least-privilege credentials. They need no source edits or knowledge of the original tenant.

**Why this priority**: Reuse requires a working standard-provider path before advanced demos.
**Independent Test**: A fresh deployment with generic identity and standard Vault authentication
completes sign-in, an allowed read, a denied read, and cleanup using only the guide.

**Acceptance Scenarios**:
1. Given an independently configured compatible deployment, when a colleague follows setup,
   then sign-in and an authorized database read succeed without edits to maintained source.
2. Given missing settings, when setup runs, then it identifies only the missing required
   settings for the selected demonstration and gives exact corrective steps.
3. Given an existing deployment, when setup repeats, then private configuration and incident
   history are preserved and no remote provisioning or credential issuance occurs by default.

### User Story 2 - Know which demonstrations work (Priority: P1)

The employee sees which features their deployment supports, why others cannot run, and who
must fix each prerequisite before a customer demonstration.

**Why this priority**: A basic login must never imply advanced security features are available.
**Independent Test**: Providers with different capabilities produce distinct, accurate reports.

**Acceptance Scenarios**:
1. Given ordinary sign-in without delegated exchange or phone approval, when readiness runs,
   then baseline features remain available and those advanced demonstrations remain unavailable.
2. Given an expired credential, permission denial or unreachable dependency, when checking,
   then the report distinguishes those failures from unsupported and unverified capabilities.
3. Given advertised exchange support but no execution evidence, when checking readiness,
   then exchange is reported as unverified rather than proven.

### User Story 3 - Repeat and demonstrate portability (Priority: P2)

A colleague repeats the same workflow on a second, independently configured deployment,
using a different OIDC product and Vault instance, and records the exact demonstrated scope.

**Why this priority**: A second tenant of the same identity product cannot prove independence.
**Independent Test**: Two fresh setup runs on the second deployment pass the bounded workflow
and produce sanitized results, with advanced feature limitations explicitly recorded.

**Acceptance Scenarios**:
1. Given two different identity products and separate Vault instances, when the documented
   baseline runs on each, then sign-in, allow/deny enforcement and cleanup have live evidence.
2. Given only simulated compatibility tests, when reporting delivery, then software completion
   is separate from the pending real deployment and colleague usability checks.

### Edge Cases

- Opaque access tokens, incompatible claims, unsupported signing algorithms or missing scopes.
- Separate discovery, authorization, token and signing-key hosts; untrusted host redirects.
- Custom database/auth mounts, namespaces, internal certificate authorities and invalid paths.
- No token exchange, authorization details, phone approval, administrative API or audit export.
- Expired credentials, HTTP 403, unreachable services and sealed Vault instances.
- Failed or uncertain credential issuance/revocation, cancellation and setup during unresolved recovery.
- Repeated setup, changed deployment configuration, incompatible legacy evidence and secret leakage.

## Requirements

### Functional Requirements

- **FR-001**: Provide one colleague-facing baseline setup guide, private configuration example,
  prerequisites, commands, expected results and repair steps; no original-tenant identifiers.
- **FR-002**: Baseline sign-in MUST support compatible generic OIDC providers without IBM Verify
  administrative credentials, phone enrollment, delegated exchange or telemetry credentials. Baseline configuration MUST NOT require separate agent/service
  OAuth client credentials; the workspace uses its registered interactive client.
- **FR-003**: Baseline Vault access MUST support standard JWT authentication on a configured mount
  and role, followed by least-privilege database credentials and cleanup. It MUST identify this
  as user JWT authentication, never as proof of actor delegation or exchange enforcement.
  Each token MUST have a verified bounded maximum lifetime; cleanup permissions MUST be
  restricted to the dedicated database role and requests to the exact owned lease.
- **FR-004**: Deployment settings MUST include namespace, custom auth/database mounts, scopes,
  expected access-token purpose and explicitly trusted endpoints/certificate authorities without
  source edits. Tokens MUST remain signed, issuer/audience/time verified; opaque tokens are
  explicitly unsupported in this feature.
- **FR-005**: Setup and default readiness MUST NOT provision providers, issue credentials,
  send approval prompts, overwrite private files or reset durable state. Explicit live checks
  MUST name their effects before execution and remain separate from default checks.
- **FR-006**: Reports MUST classify each selected feature as configured, unverified, supported,
  unsupported or blocked, distinguish advertised from demonstrated support, and provide exact
  missing settings, repair steps and responsible actor without raw provider responses.
- **FR-007**: Preserve advanced delegated exchange and Verify phone/remediation behavior behind
  explicit capabilities; missing capabilities MUST fail closed without silently falling back
  to user JWT, operator tokens or weaker approvals.
- **FR-008**: Credentials, tenant details and raw evidence MUST stay private; examples, logs,
  traces, reports and distribution artifacts MUST remain sanitized.
- **FR-009**: Preserve exact cleanup, cancellation, replay protection and uncertain-outcome
  recovery for both authentication routes; deployment changes MUST NOT reattribute old evidence.
- **FR-010**: Preserve existing short settings and documented aliases/defaults; explain migration
  and reject conflicting authentication modes before issuing credentials.
- **FR-011**: Provide offline compatibility and negative-boundary tests, plus a separately
  invoked real-provider validation recipe for two distinct OIDC products and Vault instances.
- **FR-012**: Record actual colleague setup timings, repeat results, provider versions,
  demonstrated capabilities and limitations separately from software and legacy native acceptance.

### Key Entities

- **Deployment Profile**: Privately held provider settings, selected authentication route,
  trust boundaries and the demonstrations requested by an employee.
- **Capability Observation**: Feature, state, evidence level, observation time and corrective action.
- **Portability Run**: Deployment identity represented privately, sanitized scope, workflow outcomes,
  cleanup disposition, versions, reviewer and original evidence references.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Two fresh colleague baseline setup runs complete in at most 30 minutes each,
  excluding externally administered provisioning and human/provider response time, with no source
  edits or undocumented assistance. Record exclusions and actual durations.
- **SC-002**: Baseline sign-in, authorized read, denied read and cleanup pass on two different
  OIDC products with independent Vault instances; a second IBM Verify tenant alone does not count.
- **SC-003**: All tested missing/unsupported capability cases identify a corrective action or
  explicit limitation before the corresponding demonstration starts; no silent downgrade occurs.
- **SC-004**: Repeating default setup/readiness causes zero provider mutations or credential
  issuance and preserves existing private configuration and unresolved recovery state.
- **SC-005**: All compatibility, negative-boundary and publication-privacy checks pass; simulated
  results never promote live portability or the original fifteen native acceptance criteria.

## Assumptions

- Supported baseline means confidential authorization-code sign-in with signed JWT access tokens
  and standard Vault JWT/database facilities. It does not mean every feature on every OIDC product.
- Administrators create clients, trust, least-privilege roles, database grants and approved network
  access beforehand. Setup provides concrete instructions; automatic provider administration is out
  of scope, consistent with the existing guided-repair decision.
- The first deployment uses IBM Verify; the reference second product is Keycloak with a separate
  Vault deployment. Real deployment access and colleague participation remain external prerequisites.
- Phone approval, delegated actor semantics, audit-capable tiers, remediation and governance are
  optional named capabilities, not prerequisites for the baseline and not reimplemented for all vendors.
- Existing fixed database operations and local workspace remain the baseline; arbitrary tools,
  production hosting, opaque-token introspection and repository-wide commenting are out of scope.
- Setup uses current platform/install prerequisites and the committed lockfile; no new dependency
  or distribution licensing rights are assumed.
