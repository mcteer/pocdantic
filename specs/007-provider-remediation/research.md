# Research: Provider detection and remediation

**Date**: 2026-10-10. Planning research only: repository/design review and public
primary documentation. No tenant configuration, live credential or provider mutation.

## 1. Continue Function 10 with separate, provable controls

**Decision**: Extend 006 with enrolled provider actions, native event translation,
independent access observations and notification. Implement every software adapter and
negative path; keep native acceptance conditional on actual deployment evidence.
**Rationale**: Local holds and exact dynamic-lease cleanup already exist. Cancellation,
registration removal, native-token revocation, external JWT denial, user suspension,
lease revocation, database closure and notification delivery are different effects.
One successful component cannot establish an end-to-end access block.
**Alternatives**: Infer provider enforcement from local cancellation, or stop software
implementation because live prerequisites are absent. Both conflict with the feature.
Function 11, public ingress hosting, global identity-provider administration and broad
tenant revocation remain outside this increment.

## 2. Native VIP translation without a fabricated provider contract

**Decision**: Add a bounded tenant-specific JSON projection at a new loopback native
intake endpoint, authenticated with the existing 006 relay JWT verifier and enrolled
source authority in the v2 profile, with a distinct native audience/source namespace;
006 source-policy bytes stay unchanged. A private enrolled mapping selects scalar event identity, timestamp,
rule and target fields; fixed predicates and exact target mappings select a response.
No expressions, executable templates, event-selected destinations or model decisions.
The relay owns vendor-specific transport authentication and delivers the native event;
its signed authority does not by itself prove that a VIP collector detected anything.
**Rationale**: IBM describes VIP identity telemetry and detection, but no applicable
tenant payload, collector configuration or outbound authentication export was supplied.
Enrollment records product/version, schema/fixture digest, mapping, source and collector
evidence references. Missing enrollment prevents native dispatch and yields exact setup
instructions. Tests use synthetic fixtures and never claim authentic VIP detection.
**Replay decision**: Normalize security-relevant fields before hashing. Deduplicate by
source/event identity; ignore transport-only redelivery metadata, reject changed mapped
content under an existing identity, and commit containment before acknowledgement.
**Alternatives**: AuthMind documents an issues API and identifies VIP as its IBM OEM
offering, but OEM/version compatibility must be established and polling is not the
selected workflow/webhook route. Verify SaaS notifications have their own documented
payload and replay behavior; they are not a substitute for VIP collector evidence.
Sources: [IBM VIP](https://www.ibm.com/products/verify-identity-protection),
[AuthMind OEM relationship](https://www.authmind.com/blogs/authmind-accelerates-go-to-market-strategy-with-ibm-oem-partnership),
[AuthMind issues API](https://apidoc.authmind.com/v1/docs/issues),
[Verify notification contract](https://www.ibm.com/docs/en/security-verify?topic=webhooks-notifications-api-contract),
[Verify replay and dead letters](https://www.ibm.com/docs/en/security-verify?topic=apis-notification-webhooks).

## 3. Enrollment and state evolution

**Decision**: ResponseJournalV2 embeds the provider policy, revision and action/proof
records. Preserve the response anchor and source-policy schema at version 1 and recovery
journal at version 2. Explicit offline migration preserves every 006 hold, generation,
incident and uncertainty; it creates no provider actions for historical incidents.
Revision-bound enrollment adds exact mappings/capabilities without silently replacing
authority through file edits. Older processes reject the new response journal.
**Rationale**: One response snapshot provides an atomic authority/action boundary.
Migration must not clear containment or allow an older worker to overlook provider work.
Private credential material remains outside safe projections. Existing settings and
private enrollment avoid additional dependencies and environment-variable proliferation.
**Alternatives**: Rewrite the immutable source policy, infer missing ownership during
migration, or start with an empty journal. Each loses an established trust boundary.
Code basis: `src/agent/response/{models,store,api,coordinator}.py` and
`src/agent/recovery/{models,store,lifecycle}.py`; 006 ownership and migration contracts.

## 4. Exact Vault definition block and native-token handling

**Decision**: Use the enrolled registration ID and namespace with
`DELETE /agent-registry/registration/id/{id}` for definition-wide OAuth blocking.
Read back the exact registration and test the same still-unexpired external JWT plus
fresh issuance. Readiness checks Enterprise 2.1+ availability, licensing, OAuth feature
activation, registration/entity binding and required narrow operator permissions.
**Rationale**: Vault documents registration as a requirement for OAuth access; delegated
requests require actor registration. The current application sends an external OBO JWT
in `X-Vault-Token`; it does not thereby acquire a native Vault service token.
**Decision**: Support `POST /auth/token/revoke-accessor` only for prospectively recorded,
exactly attributable service-token accessors. Coordinate cascading lease cleanup with
the existing recovery lifecycle. Unknown, shared and batch-token paths remain explicit;
no namespace-wide accessor discovery or root-only shared registration removal.
**Alternatives**: Disable an entire issuer, invent an accessor for an external JWT, or
assume registration deletion revokes every native token. These broaden scope or confuse
distinct provider mechanisms. Registration restoration remains an authorized operator action requiring proven minting
cessation and full old-token lifetime safety. Actor/client configuration changes are not
a supported 007 recovery route because existing response/recovery digests seal those settings;
local release cannot resume an old generation or certify stale-token safety.
Sources: [Agent Registry API](https://docs.hashicorp.com/vault/api-docs/secret/agent-registry),
[OAuth evaluation](https://developer.hashicorp.com/vault/ai/iam/concepts/oauth-profiles),
[OAuth activation](https://docs.hashicorp.com/vault/ai/oauth-server/activate-oauth),
[native-token API](https://developer.hashicorp.com/vault/api-docs/auth/token).

## 5. Tenant user response with explicit federation limits

**Decision**: Map a verified issuer/subject to one enrolled Verify user ID. Implement
`DELETE /v1.0/auth/sessions/{userId}` and SCIM `PATCH /v2.0/Users/{id}` setting
`active=false`, using separately authorized tenant administration credentials.
Local workspace sessions, tenant authentication sessions, issued access credentials and
upstream IBMid sessions receive separate outcomes and observations. Root-only policy
cannot suspend a shared user. No automatic reactivation or password reset is added.
**Rationale**: Session deletion and directory suspension are supported tenant controls;
their effect on federated authentication and already-issued credentials needs live
observation. The application does not administer global IBMid and must not claim it.
**Prerequisites**: Exact test-user mapping, supported tenant user type, least-privilege
session-revocation/user-update entitlement, recovery owner and independent before/after
session checks. Absent entitlement is a concrete repair condition, not a token guess.
Sources: [session deletion](https://docs.verify.ibm.com/verify/reference/deleteallsessions),
[SCIM PATCH](https://docs.verify.ibm.com/verify/reference/patchuser),
[user active attribute](https://docs.verify.ibm.com/verify/v2.0/reference/putuser_0).

## 6. Static rotation, database sessions and independent observations

**Decision**: Rotate only an enrolled isolated database static role through
`POST /{mount}/rotate-role/{role}`. Keep old/replacement values in the trusted probe
process only; prove old-value rejection and replacement usability without persisting
either. Record scheduled-rotation overlap as ambiguous attribution, not response proof.
**Decision**: Preserve dynamic cleanup through existing Vault revocation SQL. Direct
PostgreSQL termination is limited to the enrolled isolated static username and exact
observed session identity, including backend start and database; refuse PID reuse,
shared/pool attribution and unintended targets. Use fixed parameterized SQL.
**Rationale**: Password rotation does not terminate an existing connection. PostgreSQL
termination with zero timeout reports signal submission, so independent observations
must establish closure. Negative issuance probes need their own durable intent/definitive-denial disposition;
005 production denied acquisitions remain unresolved until their existing evidence rules
are satisfied. Successful probe leases are adopted idempotently with original ownership
into existing cleanup, not discarded or used by application tools. Existing-session and fresh-login probes run alongside a healthy
control and distinguish access denial from an outage or local cancellation.
**Alternatives**: Treat a revoke/rotation response as downstream loss of access, kill by
PID alone, or grant broad database administration to the model. All were rejected.
**Prerequisites**: Dedicated role, least-privilege trusted termination authority, direct
connection ownership, known supported plugin and an isolated healthy control resource.
Sources: [database rotation API](https://developer.hashicorp.com/vault/api-docs/secret/databases),
[PostgreSQL termination semantics](https://www.postgresql.org/docs/current/functions-admin.html),
[Vault lease revocation](https://developer.hashicorp.com/vault/api-docs/system/leases).

## 7. Durable action ordering and uncertainty

**Decision**: Commit 006 containment first. Serialize conflicting resources across
incidents; preserve the existing single live database effect owner and wait for its
drain before conflicting cleanup. Persist each provider intent before dispatch and
join existing exact cleanup results instead of issuing a second effect.
**Rationale**: A disconnect can hide a successful mutation. Submitted work recovered
after a crash stays uncertain; neither retries nor cancellation undo the remote request.
Reconciliation is bounded and read-only. A new attempt requires an explicit operator
decision bound to current policy/resource/action revisions and all applicable holds.
Provider calls never execute while a short response control transaction is held.
**Alternatives**: Automatic mutation retries, one global success bit, clearing state
to recover, or treating process exit as proof of effect drain. These are unsafe under
the established 006 subprocess ownership and durable containment contracts.

## 8. Teams Workflows and delivery evidence

**Decision**: Use a privately enrolled Workflows capability URL in its URL-only mode;
send no Authorization header and add no Entra dependency. Use one bounded noninteractive
Adaptive Card with incident ID, notification revision and safe outcome/timing metadata.
Ignore event-supplied destinations, forbid redirects and keep the complete URL secret.
**Rationale**: Microsoft documents this trigger mode and the card envelope. Workflows
replace legacy connectors; a workflow requires a working owner/connection and target.
Record a successful HTTP response as accepted, not delivered. A correlated imported
private receipt with explicit review proves message creation. A timeout after submission
remains uncertain; no automatic resend assumes unsupported provider idempotency.
Notification failure cannot prevent containment. Entra-restricted triggers and Graph
delivery polling are viable alternatives but add identity/permission setup outside this
chosen path. Readiness identifies the workflow owner, auth mode and delivery-check step.
Sources: [Teams trigger contract](https://learn.microsoft.com/en-us/connectors/teams/),
[workflow ownership/setup](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook),
[connector retirement](https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/).

## 9. Timing, privacy and honest closeout

**Decision**: Preserve distinct event/detection, decision, submission/revoke and observed
block timestamps. Use monotonic durations within one process and documented clock
provenance across sources; missing/skewed observations make intervals unavailable.
Compare only a valid trigger-to-observed-loss interval with the 30–60 minute baseline.
Keep raw evidence and native identifiers private; safe workspace summaries retain
session ownership. Test malicious payloads, unknown fields, crash windows, migration,
concurrent resource ownership, receipt replay, redaction and healthy-peer preservation.
**Rationale**: Deterministic tests establish software behavior. Native acceptance still
requires actual source evidence, reviewer, review time and per-control disposition.
The existing Development-tier Vault audit limitation remains blocked independently;
neither a new human token nor successful API probes produces unavailable native logs.
Sources: [HCP Vault tier capabilities](https://developer.hashicorp.com/vault/cloud/get-started/deployment-considerations/tiers-and-features),
[project constitution](../../.specify/memory/constitution.md).
