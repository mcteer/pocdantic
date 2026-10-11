# Implementation Plan: Shadow Agent Governance

**Branch**: `feature/008-shadow-agent-governance` | **Date**: 2026-10-10
**Spec**: [spec.md](spec.md)
**Input**: Function 11 and the clarified 008 specification.

## Summary

Implement an observation-only intake, explicit one-candidate Agent Registry onboarding,
native Vault JWT-SVID issuance, an independent local relying service, separate delegated
and direct permission probes, and honest per-test closeout. Unknown findings do not become
runtime authority. Provider administrators configure the isolated entity, policies, OAuth
profile, collector and SPIFFE role; this workflow checks them, previews the registration,
and applies only the reviewed registration creation. See [research.md](research.md).

## Technical Context

**Language/Version**: Python 3.12+, existing plain JavaScript/CSS workspace.
**Primary Dependencies**: Existing Pydantic, httpx, PyJWT/cryptography, FastAPI/uvicorn
server extra and pytest/Playwright WebKit. No dependency or environment-variable additions.
**Storage**: Versioned owner-only `.local/governance` snapshot plus existing private
validation artifacts. Fixed private config/secrets files; no configurable arbitrary state root.
**Testing**: Network-denied synthetic fixtures, strict token negatives, process/crash/lock
checks, meaningful chronology/policy attribution tests and owner-isolated WebKit views.
**Target Platform**: Existing POSIX macOS/Linux local workspace; Unix-domain relying service.
**Project Type**: Python CLI, loopback observation ingress, private relying service and
read-only browser status integrated into the existing local workspace.
**Performance Goals**: 1,000 candidates/10,000 observations report in five seconds excluding
I/O; 120-second effect/drain budget; ten-second bounded provider requests.
**Constraints**: Exact private contracts and bounds in [data-model.md](data-model.md);
no customer data in publication, no live mutations in tests, no general provider provisioner.
**Scale/Scope**: Four independently testable stories; seven Function 11 proof outcomes.
Single local effect owner and conservative conflict checks with existing response/recovery.

## Constitution Check

| Principle | Pre-research and post-design disposition |
| --- | --- |
| Reusable slim runtime | Pass: existing extras, small governance adapters, no new dependency |
| Trusted boundaries | Pass: verified actor/entity chain, explicit reviewed registry action, fixed targets, separate relying verification |
| Secret isolation | Pass: memory-only credentials, owner-only files/IPC, closed safe outputs and publication guards |
| Evidence before acceptance | Pass: independent F11 predicates; actual native evidence/review required; demo-tier audit stays blocked |
| Bounded execution | Pass: capacity reservation, one effect owner, bounded subprocess/network/drain, uncertainty retained |
| Reviewed delivery | Pass: spec/checklists/tasks traceability, negative/regression coverage, migration/privacy/build gates and owner review |

No constitutional exception is needed. Design review must test the race and failure
invariants below before implementation; live evidence remains independent of software gates.

## Project Structure

### Documentation (this feature)

`specs/008-shadow-agent-governance/` contains spec, requirements/security checklists, plan,
research, data model, contracts/runtime, quickstart, tasks, acceptance and validation ledger.
The formal analyze step is read-only and reports findings in the conversation.

### Source Code (repository root)

```text
src/agent/governance/
  __init__.py          # scope and trust boundary documentation
  models.py            # private and public contracts
  store.py             # anchored state, reservations, retention and locks
  config.py            # private draft, activation and readiness
  source.py            # bounded native projection and authenticated observation intake
  api.py               # loopback observation-only server
  commands.py          # operator CLI and safe errors
  bootstrap.py         # exact candidate direct OAuth/RAR and intent tracking
  activity.py          # controlled pre-registration fixture read
  registry.py          # exact create/readback and read-only reconciliation
  coordinator.py       # reviewed effect admission and containment checks
  workers.py           # bounded subprocesses and inherited ownership
  identity.py          # candidate bootstrap, mint intent and ephemeral delivery
  verifier.py          # strict Vault JWT-SVID verification and JWKS cache
  relying.py           # separate Unix-socket relying service
  permissions.py       # five fixed provider access probes
  evidence.py          # strict private import/review and chronology
  report.py            # safe projections and per-F11 closeout
src/agent/cli.py                       # additive govern command routing
src/agent/oauth.py                     # additive client-credentials RAR request method
src/agent/validation/models.py         # include new implementation files in revision
src/agent/telemetry.py                 # closed governance event fields
src/agent/workspace/{app,sessions}.py   # owner-scoped safe status
src/agent/workspace/static/            # readable governance status and sign-out clearing
scripts/publish_policy.py              # renamed governance-artifact rejection
config/governance.example.json         # exact synthetic empty-authority example
tests/test_governance_*.py            # unit/integration/security scenarios
tests/browser/test_workspace_governance.py
docs/{usage,configuration}.md
docs/adr/0010-shadow-agent-governance.md
```

**Structure Decision**: Add a distinct governance package. Reuse low-level verified-file,
OAuth and bounded-HTTP primitives through explicit APIs; do not copy remediation authority
or relax response authentication scope. Any extracted shared helper must retain regression
coverage for 006/007. No new model tool can invoke these privileged operations.

## Phase 0 — Resolved research

[research.md](research.md) records decisions, rationale, alternatives and primary sources.
Remaining deployment evidence is a readiness/acceptance prerequisite, not an unresolved
software design choice. Exact provider endpoints are in [contracts/runtime.md](contracts/runtime.md).
The selected bootstrap is verified candidate direct OAuth, using the current deployment's
issuer/Vault origin and a separate private candidate client. Existing Settings/actor config
and immutable response/recovery bindings are not rewritten to impersonate the candidate.

## Phase 1 — Architecture and contracts

### 1. Observation and chronology

`govern prepare` creates an inactive private draft; explicit source activation follows
readiness and review. Native relay delivery uses a separate audience and `governance:observe`
scope. A source body can describe an unknown object but cannot select a policy, provider,
owner or credential. Durability precedes acknowledgement. Candidate bindings are added
only through private reviewed configuration, never inferred from event names.

Before authorized activity, capture exact registry absence by entity and reserved name,
then perform one harmless fixed KV-v2 read with an otherwise valid candidate OAuth token.
A dedicated healthy registered control distinguishes provider outage. Record attempt and
receive intervals, native event and notification evidence, and source clock uncertainty.
Require source receipt before registration submission plus bounded native chronology.
A backdated later import alone cannot establish F11-T1. Local/synthetic observations can
exercise software without being native discovery. Native live enrollment requires reviewed
native source attribution for the controlled case; lack of collector evidence blocks that
live workflow with setup instructions rather than manufacturing a finding.

### 2. Review, registration and foreign changes

Private readiness verifies version/entitlement, exact entity and alias, OAuth profile,
policy bytes including defaults, SPIFFE config/role, registry absence and scoped operator
capabilities. All provider resource provisioning stays external. Native API default and
RAR flags are explicit. For 008 set no default ceiling policy, keep RAR required and include
only the reviewed effective ceiling list. Owner metadata is not authentication of review.

Review binds the full security payload, evidence and current metadata. Immediately before
create, re-read absence and all affected digests, acquire effect ownership, consume the
review and persist intent. Never send `id` in create. Confirm returned ID through exact
entity/ID/name readbacks. Matching present state after uncertain submission is not proof
of local ownership. Keep uncertainty until correlated native evidence plus explicit review
resolves it; no automatic retry/delete/update. A foreign change yields conflict.

### 3. Locks, containment and durability

Lock order for privileged work: existing recovery workspace ownership → response worker
ownership → response probe ownership → governance effect ownership → recovery effect
ownership; only then short response control followed by short governance control transactions.
All lifetime locks are nonblocking; release already-acquired locks on contention and return
an actionable busy code. Never hold a short control lock across I/O or wait for a lifetime
lock while holding one. Readiness uses metadata-only workers with the same outer exclusivity.
The existing browser workspace must be stopped before privileged governance operations
that require recovery workspace ownership; status remains available after it restarts.

Require valid existing recovery/response anchors for live effects. Conservatively refuse
any unresolved response hold, unsettled provider action, active owner or unknown recovery
acquisition before governance effects. Watch response control during work at 250 ms,
recheck just before dispatch and stop subsequent calls on new containment. Hold submission
remains able to commit while external I/O runs; in-flight writes may complete, so their
outcomes remain durable/uncertain and no success can clear containment. No 007 registration
is restored. No candidate client identity is installed into ordinary application settings.

Spawn fixed internal workers with inherited lifetime descriptors and private pipes; parent
exit cannot release ownership before its child drains. Bound output and deadline. Reserve
result space before every registration/OAuth/SVID effect. Journal failure before intent
means no dispatch; failure after dispatch latches blocked state and preserves possible
effect. Do not retain raw credential handles or secrets as a fallback. Retention respects
full reference closure and unresolved pins; test the near-capacity completion boundary.

### 4. Bootstrap, identity and relying service

After confirmed registration, use the private candidate client to obtain a signed direct
OAuth token with exact requested RAR. Verify exact issuer/subject/audience/purpose, absence
of `act`, requested authorization details and role/profile/entity readbacks. Missing direct
RAR support blocks the path; no optional-RAR or subject-exchange fallback is enabled.
The direct candidate ACL must permit only its reviewed mint path and synthetic proof reads.
Mint a Vault JWT-SVID; verify its signed entity matches the candidate, never an operator or
human OBO subject. Credential intents track both OAuth and SVID possible issuance.

`govern relying serve` runs as a separate process on `.local/governance/relying.sock`
(mode 0600 inside mode 0700 directory). It exposes only a health check and `/verify` over
that socket, uses no browser listener, disables request/access body logging and loads the
activated trust profile itself. It fetches the pinned public OIDC JWKS independently.
It consumes a single-use private challenge, verifies the strict Vault profile and returns
a closed result; no business action is attached. The effect worker sends the token over
private IPC, records only digest/safe outcome and disposes of token references on exit.
The verifier has no registration/minting credential and never trusts token-selected URLs.

One-time proof challenges prevent result replay; they do not make JWT-SVID one-time or
revocable. Unknown issuance retains a conservative expiry bound based on worker drain and
last possible provider dispatch completion, issuer maximum TTL and clock allowance. Client
timeouts/worker exit do not prove the server completed; a missing independent server
completion bound or provider evidence keeps unknown issuance blocked. No external issuer/native-token bootstrap fallback exists in 008.

### 5. Permission proofs and native closeout

Five fixed synthetic KV-v2 reads prove pre-registration denial, OBO allow/ceiling deny,
and direct ACL allow/deny. Readiness pins fixture metadata and policy digests; request RAR
permits the intended excessive path so a missing RAR cannot masquerade as ceiling denial.
Administrative setup supplies dedicated fixture values without real data. Read responses
are discarded in the trusted adapter; no data or tokens enter reports. Successful credential
exchange is still tracked even though the read itself creates no lease.

F11-T3 needs real native mint and the separate relying result. F11-T6 reports real
unauthenticated mint denial alongside labeled local token-tampering negatives. F11-T4/T7
need enough provider/configuration evidence to attribute the differing policy layers.
F11-T5 retains the known native audit blocker. Latest contradictory evidence defeats old
passes; stale implementation/profile/generation evidence cannot certify current behavior.
Imports and reviews never mutate `acceptance.json` automatically.

### 6. User experience and compatibility

CLI supplies exact missing prerequisites, fixed command syntax and current local UUID/
revision; flags never carry credentials. Private draft and input use owner-only files or
non-TTY stdin. Browser summaries show only host-reviewed owner candidates and safe aliases;
sign-out/expiry clears data from the DOM. Native versus local lifecycle status is explicit.

Existing 001–007 CLI, journal and approval semantics remain unchanged. New files are additive;
unknown governance schema fails closed. Preparing a new governance installation neither
migrates nor clears response/recovery state. New credential/private-artifact signatures
are added to publication checks, with an exact synthetic-example exception if needed.

## Validation and rollout

Implement foundational contracts first, then US1, US2, US3 and US4. Seeded fixtures let
each story be tested independently; full live flow is sequential. US1 is the observation-only
MVP. Required tests include unsafe files, source spoof/replay, chronology, candidate-conflict,
policy drift, response-hold races, parent death, mutation uncertainty, capacity, token
negatives, key rotation, one-time proof consumption, publication privacy and WebKit isolation.

Run the full existing CI command set plus focused 008 performance/security tests. Update
usage/configuration and ADR, then record exact software results and all seven native
dispositions. Native checks run only for explicitly authorized isolated targets; otherwise
record the precise prerequisite and operator step. Planning itself performs none of them.

## Complexity Tracking

No violations. Separate storage is necessary because unknown candidates cannot become
response roots merely to be observed. A separate relying process is necessary for the
independent-verification requirement; reusing issuer validation would not satisfy it.
