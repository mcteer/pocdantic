# Pocdantic Constitution

## Core Principles

### I. Reusable slim runtime
Start with Pydantic AI Slim. Provider, database and service extras MUST be installed only
where needed. Capabilities compose reusable behavior. Tenant settings MUST remain outside
business logic. New dependencies require a stated purpose, a license review and lockfile updates.

### II. Trusted security boundaries
Identity MUST come from verified credentials, never model text. Every effect MUST pass
deterministic policy. Child permissions MUST be narrower than parent permissions. Workload
identity is stable per definition; run IDs are distinct. Co-located agents share workload
trust unless independently attested. Authorization changes require negative boundary tests.

### III. Secret isolation
Credentials MUST stay in trusted adapters and MUST NOT enter prompts, outputs, exceptions or
traces. Customer sources, local environments and private source-system evidence
MUST NOT enter Git or package artifacts. Maintainers MUST review the prospective publication
tree and distribution contents. Publishing a secret requires containment and credential rotation;
removing it from the latest revision is insufficient.

### IV. Evidence before acceptance
Local tests demonstrate application contracts only. Vendor enforcement MUST have live
source-system evidence, a reviewer, timestamp and explicit disposition. Unsupported features
remain blocked. Partial component success MUST NOT be reported as end-to-end acceptance.

### V. Bounded and observable execution
Runs MUST have time, usage and delegation limits. Audit records MUST correlate definitions and
runs without confidential payloads. Cleanup failures MUST prevent false success reporting.
Cancellation and replay behavior MUST be tested when changing side-effecting adapters.

### VI. Reviewed, reproducible delivery
Changes MUST have a documented problem, acceptance criteria, focused implementation and review.
Behavior changes MUST include meaningful tests; documentation-only changes require documentation
validation. Builds MUST use the committed lockfile and explicitly selected extras. CI MUST run
without customer credentials or live service mutations. Breaking changes require migration notes.

## Security Constraints

OAuth endpoints and authentication methods are configurable. JWKS, issuer, audience, expiry and
token purpose are verified at ingress. Vault authorization and database grants independently
restrict access. Privileged approval binds the exact action, resource, parameters, requester and
expiry. Lease revocation MUST NOT be represented as external JWT or session revocation.
Live provisioning and destructive operations MUST be explicitly authorized and isolated from CI.
New security-sensitive code requires owner review and a recorded threat/boundary analysis.

## Development Workflow

For behavior changes, use specification -> clarification -> plan/research/contracts ->
requirements checklist -> tasks -> consistency analysis -> implementation -> validation.
Requirements and boundary decisions MUST be reviewed before implementation; unresolved critical
analysis findings block it. Mark completed software tasks independently of live acceptance.

Versioned Spec Kit gates verify artifacts and reviewed checklists in local checks and CI.
Published CI also verifies publication privacy, runtime configuration, lint, formatting, deterministic tests, the offline
demo and distribution privacy. CI MUST validate every versioned feature without depending
on machine-local state.
A PR MUST contain a sanitized problem/acceptance summary and relevant validation evidence so
contributors and reviewers can assess the change without customer documents.

Definition of done: acceptance criteria traced to changes and checks; gates passing; public
documentation updated; compatibility and migration impacts recorded; private material excluded;
live limitations stated; maintainer review complete before merge.
The target branch MUST require the validate check and a PR review once GitHub is initialized.
Stale approvals MUST be dismissed after new changes; force pushes and branch deletion MUST be blocked.
Local hooks complement required server-side checks and are not sufficient on their own.

Dependency updates MUST be reviewed rather than merged automatically. Vulnerabilities MUST be
reported privately, triaged by the maintainer and assigned remediation and disclosure decisions.
Releases require a versioned change summary, verified artifacts and an explicit maintainer decision.

## Governance

Owner and project author: mcteer. The public CONTRIBUTING.md records contributor-facing rules.
Amendments require rationale, owner review and recorded compatibility impacts. Major versions
change or remove governance guarantees; minor versions add requirements; patch versions clarify
wording. Plan and analysis stages MUST read the active constitution and report violations.
Exceptions require a named owner, rationale, scope, compensating controls and expiry.
No exception may publish customer sources or credentials.

**Version**: 1.2.0 | **Ratified**: 2026-10-09 | **Last Amended**: 2026-10-09
