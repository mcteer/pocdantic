# Data model: Operational reliability

These are new strict, versioned recovery models. Existing public session/job models
remain compatible. All private models use non-revealing representations. Fields not
listed are rejected; provider payloads are decoded only in bounded trusted adapters.

## Constraint registry

Each numbered constraint is normative and quoted verbatim in the implementing task.

- **C01**: `schema_version is strict integer 1; generated identifiers are UUIDs; timestamps are UTC-aware; unknown fields and duplicate JSON keys are rejected.`
- **C02**: `environment_digest and evidence digests are 64 lowercase hexadecimal characters; revision is a strict positive integer; every update compares the expected revision.`
- **C03**: `credential_path is a validated database/creds/ path of at most 256 characters; native request IDs and lease handles are private nonempty strings of at most 1024 characters; a lease handle must match the configured credential path and existing lease-suffix grammar.`
- **C04**: `attempt state is intent, acquired, cleanup_pending, unresolved, or resolved; resolution is null, revoked, or not_issued; resolved requires a non-null resolution and receipt, and every other state requires null resolution.`
- **C05**: `a journal contains at most 1000 attempts and 100 unresolved attempts, encodes to at most 2 MiB, retains resolved attempts for at most 7 days, and never prunes an unresolved attempt.`
- **C06**: `diagnostic state is observed, failed, unavailable, or inconclusive; category is configuration, reachability, timeout, authorization, sign_in, or recovery; a report contains at most 8 checks and becomes stale after 60 seconds.`
- **C07**: `diagnostics use at most 10 seconds per check and 30 seconds per request, have one active request per workspace, keep only the latest in-memory report, and acquire no credentials.`
- **C08**: `an evidence import is at most 2 files, 2 MiB per file, 200 records total, and nesting depth 16; raw artifacts remain outside the journal and are never copied by recovery.`
- **C09**: `an imported proof outcome is lease_identified, revoked, or not_issued; it binds one incident revision, environment, operation UUID, native request/response pair, source digests, verifier version 1, review timestamp, and a nonempty reviewer label of at most 64 characters.`
- **C10**: `cleanup sends sync as strict boolean true and binds required_parameters to lease_id and sync, allowed_parameters.lease_id to the single exact handle, and allowed_parameters.sync to [true]; numeric, string, false, missing, or widened alternatives are rejected.`
- **C11**: `public projections exclude native handles, provider request IDs, environment digests, provider addresses, usernames, tokens, passwords, source paths, raw responses, prompts, and task results.`
- **C12**: `state directories are owner-only 0700 and files are owner-only 0600; symlinks, hardlinks, nonregular files, wrong owners, unsupported versions, and unsafe permissions are rejected.`

- **C13**: `connection is unchecked, observed, blocked, or inconclusive; recovery is not_configured, uninitialized, clear, blocked, or storage_error; active_work is boolean; blocked_count is a nonnegative integer; checked_at is null or UTC-aware; reason_code and next_action use the closed contract mappings.`

## Environment and journal

`RecoveryJournal` contains schema_version, installation_id (UUID), environment_digest,
revision, created_at, updated_at, and attempts. The digest canonically binds normalized
Vault address/namespace/credential path, database host/port/name/username suffix, identity
issuer/discovery and audiences/client ID, and the profile-content digest. Secrets do not
participate; no raw identity/provider configuration is retained in the journal except
credential_path. The same configuration produces the same digest across entrypoints.

`anchor.json` pins installation_id and schema_version. `state.json` pins the environment
and state revision. Both must agree on every open. A missing pair is uninitialized;
partial presence is damaged storage. Startup creates neither. `recover init` exclusively
creates an absent root, anchor, and empty state with durable file/directory writes.
Partial creation is a storage incident; never overwrite it automatically.

Storage updates use a verified owner-only temporary file under the same root, file fsync,
atomic replacement, and directory fsync while holding journal.lock. Check file/directory
identity during every operation; do not trust a path validated once at startup. A write
or durability failure retains the in-memory safety block and prevents future effects.
Prune resolved records older than seven days at admission/check; when capacity is reached,
prune oldest resolved records early. If unresolved records or encoded size still exhaust
capacity, reject admission. Reserve room for the active attempt's terminal receipt before
issuing; storage failure must never prevent best-effort cleanup of an in-memory handle.

## Recovery incident and receipt

`RecoveryAttempt` contains incident_id (public random UUID), operation_id (private random
UUID generated before issuance), environment_digest, revision, credential_path, state,
created_at/updated_at, optional native_request_id, optional lease_handle, reason_code,
resolution, and optional receipt. It does not persist a session, user identity, job
payload, database username/password, or credential authority. An in-memory workspace
mapping links an owned job to its incident; that mapping disappears on sign-out/restart.
A null handle means unknown, never no issuance. A valid handle can survive an otherwise
malformed credential response and must still be cleaned up.

`RecoveryReceipt` contains outcome, operation IDs needed for proof, source digests (empty
only for direct trusted transport completion), verifier_version, checked_at, and review.
Direct synchronous cleanup needs no imported human review; its authenticated transport
result is recorded by the trusted adapter. Imported proof requires reviewer_label and
reviewed_at and exact incident revision/digest binding. Review is a local provenance
attestation, not a new authenticated identity system. Store derived proof facts and
hashes only. Re-reading an identical accepted import is a no-op; changed evidence,
conflicting bindings, or a different incident cannot reuse its receipt.

A transient `RecoveryCandidate` may identify a handle before cleanup. It records
`lease_identified` proof and leaves state unresolved; only revoked/not_issued can resolve.
No import can rewrite an existing exact handle. One issuance request expects at most one
native lease; multiple different matching responses/handles are ambiguous and blocked.

### State transitions

| Before | Event | Durable result / effect |
|---|---|---|
| No attempt | Preconditions and locks pass | Commit intent and operation UUID before the credential request. |
| intent | Valid returned native handle | Commit acquired before any SQL; credentials remain memory-only. |
| intent | Response missing/invalid, cancellation, error, crash | unresolved; no automatic acquisition retry. |
| acquired | Begin exact cleanup | Commit cleanup_pending before sync revoke. |
| cleanup_pending | Successful sync completion durably saved | resolved/revoked. |
| Any unfinished state | Crash/restart or ambiguous cleanup | unresolved; retain all identifiers, block new effects. |
| unresolved | Strict native pair proves lease identity | Persist exact handle and proof; remain unresolved pending cleanup. |
| unresolved | Strict native pre-execution ACL denial + review | resolved/not_issued. |
| unresolved | Exact synchronous cleanup + durable receipt | resolved/revoked. |
| resolved | Same accepted receipt/check | No-op; original job remains unchanged. |

Even a crash before send can leave intent uncertain; absence of a native record is not
proof of no send. A received 401/403 alone is classified as authorization failure, but
only a strict pre-execution denial receipt resolves journaled intent. This deliberately
avoids assuming an arbitrary proxy/provider error proves no backend side effect.

## Locks and admission

`workspace.lock` provides lifetime workspace ownership. `effect.lock` is nonblocking
and covers all live broker acquisition-through-cleanup and operator reconciliation.
`journal.lock` protects brief state transactions. Order is workspace (if applicable),
effect, then journal; status reads may take only journal. Never hold journal during network
I/O. Never release effect while an in-process cleanup worker can still affect the provider.
After a crash, OS locks release but durable unfinished state continues to block admission.
Normalize unfinished states to unresolved only while holding effect.lock; a startup that
finds another live entrypoint holding it reports active work without changing its attempt.
Normal in-process owned intent/acquired/cleanup_pending states indicate active work, not
an abandoned recovery incident. Public recovery is clear during such an owned operation
unless another unresolved incident exists; active_work still prevents a new job. The
journal admission gate rejects foreign unfinished attempts regardless of public display.

Operator recovery can acquire effect while an idle workspace keeps workspace ownership.
Browser admission takes effect before its final journal check; the broker reacquires/reuses
the same lease through an explicit owner object, never a recursively acquired flock.
All live broker entrypoints enforce the gate. An active owned attempt is distinguished
from an unrelated unresolved attempt so it can finish cleanup but cannot start another
credential acquisition. No additional issuance is admitted until the prior one resolves.

## Public status and diagnostics

`OperationalView` contains schema_version, authentication (existing session projection),
connection (`unchecked`, `observed`, `blocked`, `inconclusive`), recovery (`not_configured`, `uninitialized`,
`clear`, `blocked`, `storage_error`), active_work (boolean), blocked_count (nonnegative
integer), checked_at (nullable UTC timestamp), and owned incident summaries. A summary
has incident_id, stage, reason_code, and next_action from closed mappings in the contract.
Unknown enums fail validation. Anonymous or other-session clients receive aggregate
status only; old incident details are available to the local operator CLI after restart.

`DiagnosticReport` has report_id, started_at, finished_at, and checks. Each check has
check_id from the fixed configuration/identity/Vault/database set, category, state,
reason_code, next_action, checked_at. Public text and links are generated from fixed
mappings; never render provider messages. Reports are observations, not admission tokens
or proof of end-to-end database readiness. Unavailable diagnostics alone do not grant or
revoke authority; every new task still validates actual configuration and its journal gate.
