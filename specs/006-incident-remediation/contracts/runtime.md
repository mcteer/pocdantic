# Runtime contract: Incident containment and exact cleanup

Planning contract; the commands and routes below are introduced by implementation.
Strict limits and field constraints are normative in [data-model.md](../data-model.md).
All mutation results derive from durable state; an HTTP response is not native audit.

## Source policy and enrollment

`agent respond init --prepare` creates `.local/response/policy.json` as a private draft
using current trusted settings for `workload_definition`, `environment_digest`, and
`issuer`. It adds schema version 1, `intake_mode: local_only`, an empty `sources` array,
null `audience`, and `automatic_cleanup: false`. The draft is not enrolled and cannot
permit live work. The operator may retain local_only with remote intake disabled, or
select relay and fill a distinct response audience and source entries with `alias`,
`issuer`, `subject`, and `allowed_scopes`. A source's issuer must match the configured
issuer; aliases and issuer/subject pairs are unique. Enrollment rejects incomplete relay values.
The maintained `config/response.example.json` uses synthetic mappings, no real tokens.

`agent respond init` validates the completed policy against current trusted settings,
checks recovery schema 2 when database access is configured, and creates the anchor and
empty response journal. Record recovery_mode and its installation UUID when configured;
not_configured is valid only with no database settings and no recovery enrollment files.
Missing established recovery state never becomes not_configured. Repeating initialization
against the same healthy installation is a no-op.
Preparation and enrollment never overwrite established state, clear holds, or contact
providers. Partial/missing established files fail closed. No custom state-root argument.
Policy enrollment captures its canonical digest. Changing mappings requires future
explicit migration; editing the file cannot silently replace enrolled authority.

## Signal and relay API

`agent respond serve --port 8002` binds only `127.0.0.1`, owns a single responder lock,
and starts one bounded worker. A second responder fails with `response_busy`. There
is no externally configurable host, CORS, browser-cookie authentication, or remote
release route. Authentication failure never echoes a token or claims. Request logging
excludes headers, bodies, query text and raw exceptions. Responses use `Cache-Control:
no-store`; forwarded headers do not confer trust. JSON content type is required.
In local_only mode all relay requests are rejected with source_invalid; the worker
continues to service locally submitted incidents.

| Route | Authority | Result |
|---|---|---|
| `POST /response/incidents` | Verified response JWT, exact source mapping and target scope | 202 after durable new containment; 200 for identical retained duplicate |
| `GET /response/incidents/{incident_id}` | Same verified source authority; only its own incident | 200 safe summary; unknown or another source's incident returns 404 |

The bearer credential must pass signature, pinned issuer/JWKS, distinct audience,
access-token purpose, scope, expiry, not-before and bounded issued-at/lifetime checks.
Allowlisted sources may target only the installation's mapped definition or its known
root runs and only their configured `allowed_scopes`. A normal task token, cookie,
model assertion or caller-supplied source alias does not authorize this API. Cached-key
verification and any bounded JWKS refresh fit the 2s intake budget; budget exhaustion
before persistence rejects with `response_busy`. No provider effect is part of intake.

The body has exactly these fields; `target` is a discriminated union:

```json
{
  "schema_version": 1,
  "event_id": "sample-event-001",
  "occurred_at": "2026-10-10T12:00:00Z",
  "reason": "suspected_compromise",
  "target": {"kind": "definition", "workload_definition": "demo-agent"}
}
```

The root alternative is `{"kind":"root_run","root_run_id":"<UUID>"}`.
Timestamp and definition in this example are illustrative, not reusable live inputs.
Signal bodies cannot name a source, user, child, URL, action sequence, credential or
native handle. The source alias comes from verified policy; event identity is the pair
`(source alias, event_id)`. Hash the strictly parsed canonical signal, not raw spacing.

After authentication and strict parsing, find an existing event first. An identical
retained duplicate returns its current result even after the event age limit; changed
content returns `event_conflict`. New events must meet freshness, target mapping, and
capacity checks. One atomic commit stores the incident, immutable scope, hold/generation,
and planned aggregate cancellation action, reserving completion capacity before 202.
Late disconnects do not undo a committed incident; resend the identical event to learn
the result. An unavailable worker does not undo containment; owning-process watchers
continue to enforce it. Starting the responder resumes only never-submitted planned work.

| HTTP status | Closed reason class | Effect |
|---|---|---|
| 400 / 413 / 415 | `signal_invalid` | Malformed, oversized or unsupported content; no mutation |
| 401 / 403 | `source_invalid` | Invalid token or unauthorized source/scope; no mutation |
| 404 | `target_unknown` | Unknown target or inaccessible incident; no mutation |
| 409 | `event_conflict`, `revision_conflict`, `release_unsafe` | Existing state preserved |
| 422 | `signal_stale` | New event outside freshness window; no mutation |
| 429 | `response_capacity` | No acceptance; unresolved state retained |
| 503 | `response_uninitialized`, `response_migration_required`, `response_storage_error`, `response_policy_changed`, `response_busy` | Fail closed; no new provider action |

Error bodies contain only schema version 1, reason code and a fixed next-action enum.
Storage persistence ambiguity cannot be represented as a guaranteed absence of a commit;
the same event must be inspected/redelivered, never replaced with a fresh identifier.

## Trusted runtime boundary

The host allocates a new root UUID after verified identity and before model execution.
It derives request, stable definition, issuer/subject and generation from trusted context,
records the RunBinding under control.lock, and holds its lifetime lock through descendant
and cleanup drain. Callers cannot restore old roots by supplying UUIDs. Batch allocates
one root per item; CLI, bearer API, workspace, direct broker and live validation use the
same guard. Offline fixtures inject an in-memory store and deny network.

Admission, model boundaries, delegation, approval consumption, token-transition returns,
credential dispatch and SQL dispatch check the binding against durable holds/generation.
Approval consumption also checks the current guard, so a race cannot resurrect an old
approval after release. A matching hold or unreadable state cancels local work; the
watcher polls every 250ms without taking effect ownership. The measured cancellation
goal is request dispatch within 2s of durable acceptance, not guaranteed vendor abort.
Already-dispatched operations may complete later and remain subject to reconciliation.

A definition signal contains all roots of the stable definition, including those of
other signed-in users; only authorized source policy or the local operator may do so.
A root signal includes all descendants and leaves siblings eligible under existing
global recovery and single live database-operation limits. Root containment never
expires into resumed work. Pruned roots remain unusable because callers cannot allocate
or resume them; registry misses are denials. Cleanup bypasses execution holds using the
original immutable ownership and existing deterministic cleanup authorization.

## Cleanup, receipts and reconciliation

There is one aggregate `cancel_local` action per incident, targeting that incident's
immutable scope. It is confirmed only when all matching owners are terminal/drained;
the cancel-request timing is reported independently. Per-root lifetime locks prove
drain. Production network/database child processes inherit root-lifetime/effect lock
descriptors and retain them through exit; parent SIGKILL must not release ownership
while a child still acts. Never explicitly unlock before child drain. Only then does a
free lock permit abandoned-state normalization, never an inference that a lease was
revoked. Fresh starts are denied by the persisted hold.

After drain, acquire recovery effect ownership with asynchronous bounded polling, then
reread both journals. No control transaction waits for an effect lock. Select only
AttemptV2 records whose immutable root/definition matches the incident; acquire no
credentials and execute no SQL. At most 100 unresolved records are selected. Existing
successful 005 receipts confirm outcomes without another provider call. Legacy records
remain unassigned; global unresolved legacy state is reported and blocks safe release.
Keep the incident partial while applicable unknown acquisition or shared legacy
uncertainty remains, even if its cancellation action is confirmed. An empty action list
is not proof of cleanup. A pre-dispatch authority failure records denied without a
provider submission and is not automatically retried.
Pin roots referenced by unresolved bound attempts, even before an incident exists.
From durable intake, pin recovery records/receipts matching every non-settled incident
scope, even before cleanup actions exist. Also pin those needed by unconfirmed actions
until their confirmation is durable. Retention takes effect then control ownership to inspect both
stores; missing/corrupt reference data blocks pruning and produces uncertainty.
In enrolled not_configured recovery mode, skip the recovery store/lock, use control and
root ownership, and report cleanup not_applicable; cancellation alone can then settle.

If `automatic_cleanup` is true and the existing operator credential is configured,
persist a `revoke_exact` action as submitted, call the existing synchronous exact revoke,
then record the outcome. The fixed configured Vault address/namespace and handle from
the private attempt are the only allowed destination/input. Prefix/force revoke,
policy changes, credential issuance, rotation and external token/user actions are absent.
Both the response action intent and existing recovery intent precede network dispatch.

The worker's 60s budget includes lock/drain/provider waits; each provider call has a
10s deadline. If the budget expires before a new action is submitted, leave it planned
and the incident partial. Planned work may proceed once during a later explicit worker
start; submitted/uncertain/denied/failed work never retries
automatically. Holds and effect ownership remain until any dispatched cleanup worker
drains. The next incident cannot start a duplicate operation against the same attempt:
the coordinator checks global response-action history as well as current recovery state.

On restart, submitted actions become uncertain. `agent respond reconcile` only reads
existing durable receipts and liveness; it never calls a provider or schedules new
provider work. A previously planned action may be serviced by `serve` only if there
has been no submission for that recovery attempt anywhere in response history. After
explicit 005 recovery supplies proof, reconciliation may confirm denied/uncertain/failed
cleanup actions and settle the incident. An unknown handle requires native recovery
proof; a timeout, elapsed TTL or empty lookup cannot clear it. No acknowledge/reset route.

## Local commands and reports

All commands use fixed private paths, existing settings, sanitized JSON output and
exit codes: 0 requested command completed; 1 incomplete/restricted state; 2 invalid
input/configuration/storage. `submit` exits 0 after durable acceptance, without claiming
cleanup success. `status` is read-only. Local operator authority is OS user ownership;
`--operator` is a nonsecret provenance label, not authentication.

| Command | Semantics |
|---|---|
| `agent recover migrate` | Offline locked v1→v2 state conversion; preserve anchor/receipts; v2 no-op; no network |
| `agent respond init [--prepare]` | Draft or enroll policy as described above; no network |
| `agent respond submit --event-id ID --occurred-at UTC --reason CODE (--run UUID \| --definition KEY)` | Local operator input; same strict signal/deduplication/hold transaction; no synchronous provider action |
| `agent respond status [--incident UUID]` | Current journal revision, known root/incident IDs, hold sets and private safe outcomes; no effects |
| `agent respond reconcile --incident UUID` | Re-read receipts/liveness under effect then control ownership; no provider calls |
| `agent respond release --definition KEY --incident UUID [--incident UUID ...] --revision N --operator LABEL` | Atomic local release of complete current hold set after all safety checks |
| `agent respond serve [--port N]` | Loopback API and single worker; execute opted-in cleanup only |

Release checks the full current hold set, expected journal revision, owner lifetime
locks, confirmed selected actions, no unresolved applicable/legacy attempts and no shared
recovery block. It increments generation and records the release atomically. A new event
or registration racing it causes serialization or revision rejection. Release does not
re-enable a provider, recreate a session, revive a job/approval, or clear a root terminal
record. Already-settled incidents are not automatically released.
The not_configured mode has no recovery lock or lease requirement; formerly configured
but missing recovery state still rejects release. Mode/configuration changes are not
silently adopted.

Private reports include incident/event IDs, source alias, immutable target, current
revision, cancellation status, cleanup actions and safe recovery incident IDs, timings,
hold state, and fixed next actions. They exclude verified user identity, raw signals,
provider addresses/handles, digests and credentials. External controls explicitly read
`not_performed`; native audit evidence reads `unavailable_on_recorded_tier`. These are
limitations, not execution failures to repair with another access request.

| Reason | Fixed next action and concrete local instruction |
|---|---|
| `response_uninitialized` | `initialize_response`: prepare policy, retain local_only or fill relay mappings, then `agent respond init` |
| `response_migration_required` | `migrate_recovery`: stop live processes, then `agent recover migrate` |
| `response_policy_changed` | `restore_configuration`: restore enrolled mappings/settings; do not reset state |
| `response_storage_error` | `repair_storage`: stop live work and repair the reported fixed private store; preserve state |
| `response_capacity` | `resolve_incidents`: inspect `agent respond status`, resolve listed recovery records and reconcile |
| `response_busy`, `owner_draining` | `wait_for_owner`: let the active owner finish; inspect status again |
| `legacy_unattributed`, `acquisition_uncertain` | `review_recovery`: `agent recover status`; use existing reviewed source import for the named recovery record |
| `cleanup_denied`, `cleanup_failed`, `cleanup_uncertain` | `recover_exact_lease`: correct authorized operator credentials if needed; `agent recover revoke --incident RECOVERY_UUID`, then `agent respond reconcile --incident RESPONSE_UUID` |
| `revision_conflict`, `release_unsafe` | `inspect_hold`: inspect current response/recovery status; finish cleanup/drain and use current complete hold set |
| `contained` | `inspect_incident`: inspect status; clean up and explicitly release the definition when safe |
| `source_invalid`, `signal_invalid`, `signal_stale`, `target_unknown`, `event_conflict` | `correct_request`: correct source/request/mapping; retain event identity for uncertain delivery |
| `timing_unavailable`, `external_control_not_performed` | `review_limitations`: inspect separate timing and deferred-control dispositions |

Missing/disabled automatic authority maps to `cleanup_denied` and the explicit recovery
command; it never falls back to delegated credentials or silently enables policy.

## Browser, timing and publication

Add `containment` to existing operations/job projections without changing schema version.
Signed-out operations expose only `{restricted: boolean, next_action: fixed enum}`.
Signed-in job detail may include C17 summaries only for roots owned by that exact current
workspace session; knowing a UUID or sharing a user subject is insufficient. Definition
holds show an aggregate restriction to other sessions without incident/source IDs.
No administrative mutation appears in the browser. Preserve sign-out cancellation,
session expiry, CSRF/origin checks, history, connection diagnostics and one-job limits.
Browser copy says “Work stopped” and separately “Credential cleanup confirmed/pending”.

Use same-process monotonic durations for receipt-to-cancel request, cleanup and worker
intervals; store UTC observation times separately. Cross-process cancellation timing
is unavailable unless measured by the accepting process that actually requests it;
controlled tests instrument both sides with a shared test clock. Report source event
age separately, never as native detection or provider-enforcement latency.

Public summaries exclude C17 private fields. Telemetry uses closed reason/action enums
and existing safe run correlation only; no incident/source IDs or payloads. Private
policy/journal/report files stay below `.local/`. Publication detectors reject their
content even if renamed into otherwise allowed JSON/JSONL files; test fixtures are
synthetic Python builders, not committed private artifacts. No acceptance manifest is
automatically changed by a software test, CLI response or provider HTTP success.
