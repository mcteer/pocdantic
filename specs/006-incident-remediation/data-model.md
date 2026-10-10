# Data model: Incident containment and exact cleanup

## Normative constraint catalog

Tasks quote these constraints verbatim. All private models forbid extra fields and
use strict integers/booleans rather than coercion. Public schemas remain version 1.

- **C01**: `RiskSignal schema_version is strict integer 1; event_id matches [A-Za-z0-9_-]{1,128}; occurred_at is UTC-aware; reason is suspected_compromise or policy_violation; target is exactly root_run(UUID) or definition([a-z][a-z0-9-]{1,63}); no other fields are accepted.`
- **C02**: `Intake accepts at most 16384 UTF-8 bytes, rejects duplicate JSON keys and nesting deeper than 8, permits source age at most 300 seconds and future skew at most 30 seconds, and returns an identical retained event before applying the age check.`
- **C03**: `SourcePolicy schema_version is strict integer 1; intake_mode is local_only or relay; local_only requires zero sources and null audience and disables remote intake; relay requires 1..16 sources with unique aliases matching [a-z][a-z0-9-]{1,31}, exact issuer, exact subject of 1..256 characters, nonempty allowed_scopes drawn from root_run and definition, and a distinct audience of 1..256 characters; every accepted JWT requires response:submit and at most 300 seconds of remaining lifetime.`
- **C04**: `Policy binds one exact current workload_definition, current recovery environment digest, and configured issuer; remote URLs, native handles, secrets, arbitrary expressions, and provider mutation choices are forbidden in signal bodies.`
- **C05**: `ResponseAnchor schema_version is strict integer 1 with installation_id UUID, recovery_mode configured or not_configured, and recovery_installation_id UUID only when configured; ResponseJournal schema_version is strict integer 1 with matching installation_id, 64-lowercase-hex environment_digest and policy_digest, positive strict revision, and UTC created_at/updated_at.`
- **C06**: `RunBinding has root_run_id UUID, request_id UUID, stable workload_definition, positive strict generation, exact verified issuer and subject, UTC started_at, and state active or terminal; independent child targets are rejected and descendants inherit the root binding.`
- **C07**: `Bound recovery ownership contains root_run_id, request_id, workload_definition, generation, and verified issuer/subject; ownership is immutable after attempt creation; legacy_unattributed ownership has no inferred identifiers.`
- **C08**: `Recovery anchor and receipts remain schema 1; recovery journal/attempt records become schema 2; v2 state is at most 4 MiB with unchanged 1000-attempt and 100-unresolved limits; migration preserves all attempt IDs, states, revisions, timestamps, native fields, and receipts.`
- **C09**: `Incident has server-generated incident_id UUID, source alias, event_id, canonical payload SHA-256 digest, immutable target, captured policy digest, positive strict revision and captured generation, UTC source/received/contained timestamps, and phase contained, responding, partial, or settled; source plus event_id is unique.`
- **C10**: `DefinitionHold binds the exact workload_definition and monotonically increasing generation to one or more incident UUIDs; root holds are terminal; definition release requires all current hold incident IDs and expected journal revision.`
- **C11**: `ResponseAction has action_id UUID, kind cancel_local or revoke_exact, target incident UUID for aggregate cancellation or recovery-incident UUID for exact cleanup, status planned, submitted, confirmed, denied, failed, or uncertain, UTC intent/completion times, and a closed reason code; no provider request may precede durable submitted state.`
- **C12**: `An incident has at most 101 actions and targets at most 100 unresolved attempts; confirmed actions are immutable; submitted actions found after worker restart become uncertain; duplicate intake and status reads never resubmit actions.`
- **C13**: `The fixed response root is .local/response; directories are 0700 and regular single-link files 0600 with current-user ownership; symlinks and nonregular files are rejected; snapshot replacement uses exclusive temporary creation, file fsync, atomic replace, and directory fsync.`
- **C14**: `Response state is at most 8 MiB, with at most 1000 runs, 1000 incidents, and 16 non-settled queued incidents; intake reserves 256 KiB per non-settled incident for action completion; active holds and unresolved actions are never pruned.`
- **C15**: `Settled incidents and terminal runs are retained for at least 7 days; active definition holds, unresolved root incidents, and unresolved bound recovery attempts pin referenced roots; recovery records/receipts matching any non-settled incident scope are pinned from durable intake, and those referenced by unconfirmed response actions remain pinned until reconciliation; settled root-only holds may be pruned atomically with their unpinned terminal runs after retention; unknown or previously issued caller-supplied run IDs never authorize work or revive old approvals.`
- **C16**: `The responder uses one worker, 250 ms watcher polling, a 2-second intake budget, a 60-second incident work budget, and a 10-second per-provider deadline; effect-lock waits poll without blocking the event loop; ownership remains held until workers drain.`
- **C17**: `Public summary contains only schema_version, incident_id, scope, phase, contained boolean, cleanup outcome, fixed reason/next_action, and observed_at; it excludes source event IDs, user identifiers, native handles, provider targets, raw messages, credentials, and policy digests.`
- **C18**: `Elapsed milliseconds are nonnegative strict integers measured by a same-process monotonic clock; source-to-receipt UTC age is labeled separately; cross-restart or clock-invalid elapsed fields are null with timing_unavailable.`
- **C19**: `ReleaseRecord has release_id UUID, definition key, complete incident UUID set, expected prior journal revision, new generation, UTC released_at, and local operator label of 1..64 nonblank characters; it never changes provider state or revives an old root. At most 1000 release records are retained for 7 days.`
- **C20**: `Closed reasons are source_invalid, signal_invalid, signal_stale, target_unknown, event_conflict, response_uninitialized, response_migration_required, response_storage_error, response_policy_changed, response_capacity, response_busy, contained, owner_draining, legacy_unattributed, acquisition_uncertain, cleanup_denied, cleanup_uncertain, cleanup_failed, release_unsafe, revision_conflict, timing_unavailable, and external_control_not_performed.`

## Private policy and authority

`.local/response/policy.json` is prepared by `agent respond init --prepare` from current
trusted settings; relay operators fill source mappings using the sanitized example.
It contains the C03 intake mode/source entries, the C04 definition/environment binding,
a distinct response audience in relay mode, and `automatic_cleanup` (strict boolean,
default false). Enabling it
expressly authorizes the narrow responder to use the existing `VAULT_TOKEN` for exact
bound-lease cleanup. This is the only automatic provider effect in 006. Disabled or
missing cleanup authority gives a partial result and an operator recovery command.
The file has C13 protections and a 32 KiB maximum. Its digest is captured at enrollment;
source/mapping changes require stopping the responder and a future reviewed migration,
not silent reload. Secret rotation via existing settings does not change policy identity.
Preparation creates only a new owner-only draft policy in local_only mode, never
overwrites a file, and does not enroll or permit live work. `agent respond init`
validates the completed policy and its settings-derived binding before enrolling.
The operator may retain local_only or select relay and supply the C03 mappings.

JWT signature, issuer, audience, purpose, expiry, not-before and issued-at are verified.
`iat` is required; token age and maximum exp-minus-iat lifetime are each at most 300s,
with at most 30s future `iat` skew. Allowlisted subjects must be unambiguous: no duplicate
issuer+subject entry. Human task tokens and ordinary actor tokens with other audiences
never authorize response intake. Local CLI submissions use reserved source
`local-operator`, never impersonate a configured relay, and undergo all target/content
checks. The reserved source is not a SourcePolicy entry and cannot authenticate remotely.

## Run registry and ownership

Root registration occurs after identity verification but before any model/effect or
approval reservation. The same transaction checks definition/root holds and captures
the current generation. It never accepts caller-supplied ownership. All roots in this
installation use `Settings.workload_definition`; profile and telemetry definition UUID
remain distinct diagnostic concepts. Descendant delegation carries the same immutable
root binding. No durable raw user credential is stored.

A RunBinding becomes terminal only after its owner/children and cleanup workers exit.
Process liveness is established by a per-root advisory lock held for its lifetime;
an active record without that lock becomes abandoned/terminal during reconciliation,
but unresolved credential attempts and incident holds remain blocked. OS locks are
not replaced by PID guesses. Production network/database subprocesses inherit the
applicable root-lifetime and recovery-effect descriptors until they exit; parent death
alone must not release ownership while a child can still act. Owners never explicitly
unlock before child drain. The watcher does not need a recovery effect lock to cancel.

Each prospective recovery AttemptV2 stores C07 in the same atomic snapshot as intent.
A recovery record may finish after its run is contained; cleanup is authorized by its
original ownership. Legacy unresolved attempts retain the existing global recovery block.
They are never relabeled as belonging to a targeted incident, and release is denied
while legacy uncertainty blocks this installation.

## State transitions

- Intake: authenticate → validate/map → deduplicate/capacity check → persist incident,
  hold, and cancel action → acknowledge → worker observes. No durable write, no acceptance.
- Incident: contained → responding → settled when all selected local/cleanup actions
  are confirmed and no applicable unknown or shared legacy uncertainty remains;
  otherwise partial. Settled does not release a hold or establish UC3.
- Action: planned → submitted → confirmed/denied/failed/uncertain. Explicit reconcile
  may confirm cleanup using an existing 005 receipt; it cannot replay uncertain effects.
  A crash in the durable-submit/before-network gap is conservatively uncertain.
  A pre-dispatch policy/authority rejection may move planned directly to denied/failed;
  it records that no provider request occurred and does not make it automatically retryable.
- Definition signal: increment generation, add its incident to the hold set, and
  invalidate prior-generation work. Another distinct signal increments again.
- Release: reject active/draining ownership, unresolved applicable/legacy recovery,
  unconfirmed selected actions, stale revisions, or incomplete hold sets. Atomically
  release all selected current holds and increment generation. Root holds stay terminal.
- Local run completion alone cannot confirm credential cleanup or clear a hold.

## Migration and lock ordering

`agent recover migrate` requires workspace → effect → journal ownership and no active
workspace. Strictly read v1 or v2 state and unchanged anchor. V2 is an idempotent no-op.
V1 conversion marks every attempt legacy_unattributed; only journal revision/time change.
Validate the whole 4 MiB output before replacing state.json. A crash leaves complete v1
or v2; abandoned temporary files are never promoted. Normal new acquisition requires v2;
legacy status/import/revoke remain supported so migration never prevents cleanup.

Response initialization is separate from recovery migration and never overwrites an
existing installation. Control transactions hold only control.lock, except a bounded
pre-dispatch guard/registration commit; they never wait for recovery ownership. Reconcile
and release take nonblocking recovery effect ownership first, then control.lock, and
revalidate both stores before committing. Never acquire effect.lock while holding
control.lock. Cleanup network waits occur outside control/journal locks.

Enrollment records recovery_mode and the recovery installation identity. In explicitly
not_configured mode, reconcile/release use control and root ownership only and report
cleanup not_applicable. Missing formerly configured recovery state is always an error,
never a transition to not_configured. Enabling database configuration later needs a
reviewed enrollment migration outside this increment. Retention reads both stores
under effect then control ownership; corrupt or unavailable attribution blocks pruning.
A missing referenced attempt/receipt is uncertainty, never proof of no cleanup needed.

## Timing and privacy

No clocks are assumed synchronized with a provider. Local acceptance-to-cancel request,
cleanup duration, and overall worker duration are separate from source-event age.
No field claims detector latency, JWT revocation, DB-session termination, or native audit.
Private CLI reports may display opaque root/incident/action UUIDs and durations; they
still exclude issuer/subject, provider addresses, native handles, raw signals and secrets.
