# Data model: Signed-in agent workflow

Every record is in process memory. Only the explicit public projections below may be serialized
to browser responses. No persistent schema or database migration is introduced.

## Normative constraints

These clauses are quoted in tasks so limits and state semantics are not implementation choices.

- **C01**: "New JSON request/response models use schema_version exactly 1, reject unknown fields,
  use UUIDs for submission/job/request/run/retry identifiers, and UTC timestamps for exposed times.
  Server-generated IDs never derive from identity, task text or credentials."
- **C02**: "Opaque browser/session/CSRF/state/nonce values each contain at least 256 random bits;
  PKCE uses S256 and a 43–128-character verifier. Login attempts expire after 300 seconds, are
  single-use, and are capped at one per browser and sixteen globally; anonymous bootstraps
  share that cap and 300-second lifetime. Callback code/state/error
  parameters must be unique; reject duplicates, oversized values over 8192 characters and mixed
  code/error responses before exchange."
- **C03**: "At most four authenticated sessions exist; each expires after 1800 seconds without a
  successful user mutation or 28800 seconds absolutely. Polling does not extend idle expiry.
  Session states are active, reauth_required, closing and closed. Rotate the opaque cookie at
  login; sign-out/expiry immediately refuse work and retain run credentials only through cleanup."
- **C04**: "Access, refresh and ID tokens are SecretStr fields excluded from repr and all public
  projections; token strings are nonempty and at most 65536 characters, and new login/refresh
  responses are limited to 256 KiB before parsing. ID tokens require RS256
  or ES256 signatures, exact issuer, nonempty subject, exp/iat, one audience equal to LOGIN_CLIENT_ID,
  matching azp when present and the initial nonce. Access tokens retain the configured audience/type
  verifier and must match ID issuer/subject. Refresh is attempted at most once per admission under
  a session lock; remaining access lifetime must be at least TIMEOUT_SECONDS + 45 seconds."
- **C05**: "A job has kind task or approval_retry and state accepted, running, waiting_for_approval,
  cleaning_up, completed, denied, failed or interrupted. Only the last four states are terminal.
  Exactly one global job may own admission/execution/cleanup. Task length is 1–8000 characters;
  result summary is at most 32000 characters with an explicit truncated flag; each session retains
  at most twenty jobs and twenty distinct submission keys, including retry aliases; duplicate
  lookup precedes capacity checks and new alias keys at capacity are rejected; it rejects new jobs at capacity rather than evicting idempotency records."
- **C06**: "A submission key is a browser-generated UUID scoped to one session. The same key and
  canonical payload return the same job; changed payload returns conflict. Job access requires
  its owning session; unknown and foreign UUIDs both return not-found. Runtime IDs are generated
  by trusted code, reserved before effects and cannot be selected by a browser."
- **C07**: "Approval decisions are approved, denied or unconfirmed. Only DENIED, VERIFY_DENIED and
  USER_DENIED establish native denial; existing exact success aliases remain approved. Expiry,
  timeout, cancellation, failure and unrecognized/malformed results cannot authorize effects.
  Approval states are pending, approved, denied, consumed, expired, cancelled, unconfirmed and
  superseded; decision, invalidation and consumption are atomic, expiry-checked and terminal."
- **C08**: "A retry candidate contains canonical immutable action bytes, original issuer/subject,
  profile, parent job and original approval reference. Only one unconfirmed candidate with zero
  simulated writes, no uncertain other effects and completed cleanup is eligible. Retry atomically
  consumes that candidate, creates fresh job/request/run/approval IDs, rechecks identity/profile/
  policy and invokes no model. Approved, denied, interrupted, binding-invalid and cleanup-failed
  jobs are ineligible; an old decision never authorizes a new attempt."
- **C09**: "Cleanup status is not_acquired, pending, revoked, failed or unknown. Runtime budget is
  TIMEOUT_SECONDS in 1–180 seconds for the workspace; cleanup allows 30 seconds plus five seconds
  to drain cancellation. Unresolved cleanup holds the global gate and quarantines admission.
  Completed requires successful execution and all acquired leases revoked; cleanup failure or
  uncertainty cannot report completed or expose retry."
- **C10**: "LOGIN_CLIENT_ID and LOGIN_CLIENT_SECRET are required only by workspace; LOGIN_SCOPES
  defaults to openid and is a whitespace-delimited unique list of at most 32 scope tokens, each
  1–128 characters with no control characters. Short names precede POCDANTIC_LOGIN_* aliases.
  --port defaults to 8000 and accepts integers 1024–65535; host is always 127.0.0.1."
- **C11**: "All workspace requests require the exact configured Host including port; mutation
  requests require exact Origin and a browser/session-bound CSRF token. Authenticated mutations
  accept application/json only, including login. The GET login callback is
  the sole cross-site exception and requires its browser-bound single-use transaction."
- **C12**: "Public job projections expose only job/request/run/parent IDs, kind, state, UTC times,
  bounded result, approval status, safe action summary, cleanup status, retry eligibility and a
  closed error code/stage/next-action mapping. Tokens, cookies, state, nonce, raw provider responses,
  native transaction/lease IDs and identity claims never appear in job projections or telemetry."
- **C13**: "Browser polling runs at most once per second per page and performs no effects. Status
  updates must become visible within two seconds under controlled local tests. Browser storage
  contains no tokens, cookies copied by script, task text or result history; only in-memory page
  state and HttpOnly opaque cookies are used. All untrusted content is rendered as inert text."
- **C14**: "The memory sink retains at most 1000 safe lifecycle events per job and aggregates
  cleanup, approval and effect facts without retaining raw source bindings. Input HTTP bodies are
  limited to 64 KiB before JSON/form parsing. All sensitive responses use Cache-Control: no-store;
  callback/access logs and HTTP traces must omit query codes, cookies and authorization headers."

## Entity fields and relationships

| Entity | Private fields | Public projection / relationships |
|---|---|---|
| BrowserBootstrap | opaque cookie digest, CSRF secret, created/expiry, optional login attempt | anonymous session response has signed_in=false and CSRF token; capped by C02 |
| LoginAttempt | browser binding, state digest, nonce, verifier, issuer, redirect URI, created/expiry, consumed | no public record; 1:1 with initiating browser; C02 |
| CredentialSet | access token, optional refresh/ID token, validated issuer/subject/scopes/exp, original nonce | none; C04; ID token discarded after validation except required identity/nonce facts |
| WorkspaceSession | cookie digest, CSRF, CredentialSet, lifecycle state, created/last_mutation/absolute expiry, lock, owned job IDs | signed_in, requires_sign_in, CSRF token, configured profile names and safe configuration issues; C03 |
| SubmissionRecord | key, canonical payload digest, job ID | C06 idempotency; retained for session lifetime within twenty-job bound |
| WorkspaceJob | generated IDs, owner, kind, immutable task/profile or retry link, credential snapshot, task handle, runtime context, lifecycle facts and times | C05/C12; runtime ID nullable until trusted reservation (always reserved before execution) |
| ApprovalAttempt | ApprovalStore entry, frozen action, outcome/reason, owner run, raw native reference privately in adapter | approval_status not_requested/pending/approved/denied/unconfirmed and fixed safe action summary |
| RetryCandidate | C08 fields, eligible/consumed flag and successor job ID | retry_available boolean and parent job ID; browser sends no action or approval decision |
| WorkflowError | closed safe code, stage and next action | contract error catalog only; no arbitrary upstream text |

Fields not required by a listed kind are null or absent as defined by its explicit response model;
only run_id, parent_job_id, started_at, finished_at, result, action_summary and error may be null in JobView. Approval status,
cleanup status, retry_available and truncated are always present. Public times are UTC; internal
idle/expiry/drain deadlines use a monotonic clock alongside verified token epoch expiry.

## State transitions

### Authentication

Bootstrap → login attempt → consumed callback → active session. Provider cancellation consumes the
attempt and returns a fixed login_cancelled error. Login failure leaves no credentials. Invalid
state/binding does not invalidate another browser's legitimate attempt. Capacity errors create no
session and discard exchanged tokens. Starting sign-in while a session has active work is rejected;
reauthentication requires terminal drain and clears previous session job history.

Active → reauth_required on renewal rejection, invalid credentials or ambiguous refresh failure;
active/reauth_required → closing on sign-out/idle/absolute expiry → closed after job drain. Sign-in
creates a new session. Refreshed identity must match the prior issuer/subject; returned scopes
replace authority and may narrow it. If a refresh returns an ID token, validate identity/audience/
signature/expiry again and require a matching original nonce when nonce is present. Validate at_hash
when present using the signed ID token algorithm. No token-type relaxation is permitted.

### Jobs and cleanup

Admission reserves a slot before network renewal/verification; no queue. Accepted → running →
optional waiting_for_approval → optional cleaning_up → terminal. Terminal states never return to
running. Sign-out, session expiry and shutdown contain/cancel running work and terminalize approvals.
Disconnect and polling failure do not cancel or retry a job. Cleanup tracks every acquired lease;
revoked means all are confirmed revoked. If a provider request may have acquired a lease without
returning its handle, cleanup is unknown, never not_acquired.

### Approval and retry

Pending → approved → consumed, or pending → denied/expired/cancelled/unconfirmed/superseded.
Approved may be invalidated before consumption; no terminal transition can be undone. Expiry is
checked during both record_decision and consume. Run termination invalidates every unconsumed
approval. A trusted rejection remains denied; transport failure and missing confirmation remain
unconfirmed. Retry eligibility is computed from trusted facts only and only after the parent task
has terminated and cleanup is complete. A consumed candidate returns its existing successor for
repeat submissions; concurrent distinct keys cannot create multiple successors.

An original model task may have performed other tools. Retry repeats none of them. Multiple
approval candidates, a prior simulated write, sink failure or uncertain effect disables retry.
An unknown or binding-invalid outcome remains a failure requiring investigation, not an eligible
unconfirmed decision. Runtime compatibility wrappers may return bool, but False alone does not
establish an intentional denial.

Closed sessions remove their job/submission/sink records and terminal approval entries after drain.
Missing approval entries reject late decisions. Runtime reservations track active/retained jobs
only; no unbounded historic UUID or approval tombstone set is retained. Cookie names use the chosen
port as a suffix so separate local ports do not overwrite each other’s opaque session handles.
