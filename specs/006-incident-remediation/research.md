# Research: Incident containment and exact cleanup

**Date**: 2026-10-10. Read-only source/code review; no provider or runtime changes.

## 1. Roadmap placement and bounded delivery

**Decision**: Start Function 10 with durable local root/definition containment,
trusted incident intake, exact dynamic-lease cleanup, timing, and operator release.
**Rationale**: `security.Containment` is process-local; `Runtime.forget` removes local
run blocks; recovery attempts have no trusted run attribution. These gaps precede
safe automatic cleanup and broader provider response.
**Alternatives**: Implement every external response at once, or return to unavailable
audit evidence. Neither resolves the foundational ownership/concurrency gap within
a focused increment. User/session response, static-secret rotation, notification,
external agent blocking, and Function 11 remain explicitly scheduled follow-ons.

## 2. Trusted intake without an invented VIP API

**Decision**: Add an application-defined normalized relay contract on a separate
loopback response service. Authenticate signed bearer JWTs through existing pinned
issuer/JWKS verification, a distinct configured audience, exact source-subject
allowlists, and `response:submit` scope. Local operator submission is a separately
labeled authority. Use a private source/target policy file, with no new secret variable.
**Rationale**: IBM Verify SaaS documents webhook authentication choices and retrying
notifications, but this does not establish a VIP-native event schema. No live VIP
payload or collector configuration was supplied. A relay contract can be implemented
and tested now without asserting vendor detection.
**Alternatives**: Guess a VIP endpoint; infer identity from a username or message; expose
the browser server publicly; poll reporting endpoints as if they were real time.
All were rejected. Hosted ingress/TLS and a native VIP translator need separate deployment work.
**Sources**: [Verify notification contract](https://www.ibm.com/docs/en/security-verify?topic=webhooks-notifications-api-contract),
[authentication choices](https://www.ibm.com/docs/en/security-verify?topic=interface-creating-notification-webhook),
[reporting latency limitations](https://docs.verify.ibm.com/verify/docs/pulling-event-data).

## 3. Ownership and migration

**Decision**: Keep recovery anchor and receipts at schema 1. Introduce JournalV2 and
AttemptV2 with discriminated `bound`/`legacy_unattributed` ownership. Explicit offline
migration acquires workspace → effect → journal locks and atomically replaces only
`state.json`; every old attempt is marked legacy without guessing its owner.
**Rationale**: The anchor's installation identity is unchanged. A single atomic rename
avoids a two-file transaction. Existing snapshot fsync/private-path safeguards apply.
Normal admission requires v2; existing `recover status/import/revoke` retain v1 recovery
support, but new acquisition on v1 returns `recovery_migration_required`.
**Alternatives**: Separate ownership sidecars or infer ownership from timestamps.
A sidecar creates an avoidable cross-file consistency gap; inference is not authority.
**Code basis**: `recovery/{models,store,lifecycle}.py`, `broker.py`, `runtime.py`,
`workspace/runs.py`, `capabilities.py`.

## 4. Cross-process containment and ordering

**Decision**: A separate private response snapshot owns incident records, run registry,
and definition generations. Short control transactions never wait on the recovery
effect lock. Commit containment first; watchers cancel affected work; normal owners
finish/drain cleanup; only then may the responder acquire the existing effect lock.
Every live entry point registers root ownership and checks current control state.
**Rationale**: Workspace currently holds the effect lock throughout the job. Waiting
for that lock before cancellation deadlocks the intended control. Broker awaits need
fresh guards before acquisition and SQL, not only at the outer capability boundary.
**Alternatives**: Share one long lock; use volatile containment only; allow two cleanup
workers for one handle. Rejected for deadlock, restart bypass, and effect ambiguity.
**Limit**: The pre-dispatch guard is the ordering boundary. A request already dispatched
can settle after a hold commits; it must be reconciled. No retroactive prevention claim.
**Design review**: Production effect subprocesses must inherit lifetime/effect lock
descriptors; parent death alone cannot prove drain. Cross-store retention pins unresolved
owners and response-referenced receipts. Explicit local_only intake and not_configured
recovery modes make local operation possible without inventing relay/database setup;
missing previously enrolled state never qualifies for those modes.

## 5. Exact cleanup and uncertainty

**Decision**: Reuse 005 synchronous revoke and proof machinery through a distinct
incident worker using configured operator authority only for attributable handles.
One provider submission per action until explicit operator reconciliation; a durable
`submitted` action on restart becomes uncertain and is never replayed automatically.
**Rationale**: Vault documents `sync=true` as returning after completed revocation.
Local cancellation, lease completion, external token validity, and DB-session loss are
separate claims. Missing source proof never becomes success through acknowledgment.
**Source**: [Vault lease API](https://developer.hashicorp.com/vault/api-docs/system/leases).

## 6. Stable definitions and generation-aware release

**Decision**: Target the configured stable workload-definition key, not the ephemeral
UUID returned by the default `Runtime.definition_ref`. Root targets include descendants;
independent child targeting is unsupported. Definition holds increment a generation.
Release is a local operator action requiring current incident/revision and no unresolved
applicable attempts or active owner; old-generation work cannot resume.
**Rationale**: `definition_ref` is telemetry correlation, not durable workload identity.
Root lineage gives a clear cancellation boundary without pretending co-located children
are independently attested workloads. Provider state is not changed by local release.

## 7. Storage, limits, privacy, and timing

**Decision**: Reuse secure owner-only snapshot primitives with an independent anchor,
atomic fsync/replace, fixed root, strict parsing, and bounded collections. Store normalized
private fields and digests, not raw provider payloads, tokens, passwords, or prompts.
Persist UTC event/receipt times; measure same-process intervals with monotonic time.
**Rationale**: Bounded memory/queue space, response-capacity reservation, stale-event
rejection, and retained unresolved holds prevent silent loss or replay. Cross-restart
or skewed durations are unavailable, not recomputed as precise elapsed measurements.

## 8. External controls reserved for following increments

| Roadmap need | Verified technical route | Why separate from 006 |
|---|---|---|
| Agent-wide external OAuth block | Exact registry removal, or validated entity-disable control | Needs dedicated identity mapping, installed-version verification, approved restoration, and same-JWT denial proof |
| Compromised user | Verify session DELETE and SCIM active=false | Needs exact issuer/subject-to-user mapping, federation rules, separate authorization and recovery |
| Static secret misuse | Exact Vault database static-role rotation | Needs dedicated target, independent downstream observation, and uncertain-rotation reconciliation |
| Notification | Teams Workflows with bounded Adaptive Card | Needs target/authentication/ownership and delivery semantics; legacy connectors are retired |
| Native VIP detection | Tenant collector and native adapter | No verified tenant payload/transport or collector proof available |
| Shadow governance | Workload bootstrap, SVID issuance/verifier, registration | Separate Function 11 trust decisions |

Provider sources: [Agent Registry API](https://developer.hashicorp.com/vault/api-docs/secret/agent-registry),
[OAuth evaluation](https://developer.hashicorp.com/vault/ai/iam/concepts/oauth-profiles),
[entity API](https://developer.hashicorp.com/vault/api-docs/secret/identity/entity),
[Verify session revoke](https://docs.verify.ibm.com/verify/reference/deleteallsessions),
[SCIM PATCH](https://docs.verify.ibm.com/verify/reference/patchuser),
[database rotation](https://developer.hashicorp.com/vault/api-docs/secret/databases),
[Teams connector](https://learn.microsoft.com/en-gb/connectors/teams/),
[connector retirement](https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/).

The installed Development tier does not supply native audit logs. This is a standing
capability limitation, documented in prior validation, not an unresolved access task.
[HashiCorp tier capabilities](https://developer.hashicorp.com/vault/cloud/get-started/deployment-considerations/tiers-and-features).
