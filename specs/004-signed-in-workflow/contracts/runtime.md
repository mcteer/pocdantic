# Interface contracts: Signed-in agent workflow

Normative data constraints are C01–C14 in [data-model.md](../data-model.md). No route accepts an
issuer, subject, credential, approval decision, destination URL or arbitrary action from the browser.

## CLI and configuration

`agent workspace [--port 8000]` uses the existing server extra and selected model/provider extras.
It prints the local workspace URL and exact callback `http://127.0.0.1:<port>/auth/callback`.
No --host, --workers, auto-reload or production fake-auth switch. Use one worker, proxy headers off,
access logging off and graceful shutdown long enough to allow 30-second cleanup plus five-second
cancellation drain. Binding failure reports port_in_use and exits 1 without provider calls.

Validate only local prerequisites at startup: optional package availability, configured issuer/
discovery/audience, login client credentials and valid scopes, model extra/key configuration,
profile catalog and runtime budget. Print missing setting names and the command needed to install
an extra, never values. Database/phone prerequisites are displayed as integration-specific issues;
they do not prevent unrelated configured tasks. Discovery/network errors appear on Sign in.

Three new env settings: LOGIN_CLIENT_ID, LOGIN_CLIENT_SECRET, LOGIN_SCOPES. The matching
POCDANTIC_LOGIN_* aliases remain supported; existing Settings precedence remains environment
before .env.local and short name before alias within a source. LOGIN_SCOPES defaults to openid.
No new configurable cookie, refresh, session, API-base or browser variable is required. Existing
OAuth issuer/discovery/audience/auth-method and model/database/Verify settings remain authoritative.
The login registration must issue the existing resource audience; the UI cannot override it.

## Browser request boundary

Exact loopback Host:port is checked on all routes, including static content. Ignore proxy forwarding
headers. A request with a foreign Origin is rejected except a top-level GET provider callback.
All mutation routes require exact Origin (missing/null rejected) and CSRF. All mutations use
X-CSRF-Token and application/json. Reject duplicate cookie names and malformed cookie
values. Auth cookies are host-only, HttpOnly, SameSite=Lax, Path=/, no Domain, no persistence beyond
session limits. Only their opaque values reach the browser. They are not Secure on the explicitly
HTTP loopback endpoint; deployment elsewhere is unsupported.

Use port-suffixed cookie names and prune closed-session/job/approval records after drain; a
missing approval rejects late responses. One shared Runtime preserves containment across jobs;
the global gate serializes sink assignment and cleanup before resetting it.

No CORS. Apply CSP `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';
form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, X-Content-Type-Options nosniff,
Referrer-Policy no-referrer and Cache-Control no-store. The authorization URL is returned by the trusted
server and used in a top-level script navigation; form-action remains self. Callback success/error immediately redirects
to `/` without preserving code/state in the page URL. No browser/local telemetry integration.

## Routes

| Route | Input / protection | Success | Failure |
|---|---|---|---|
| GET / | loopback boundary | 200 static workspace shell | 400 request_forbidden |
| GET /assets/app.js, /assets/style.css | exact resources only | 200 matching content type | 404 for other assets |
| GET /workspace/session | same-origin boundary; optional opaque cookie | 200 SessionView; bootstrap CSRF+cookie when anonymous, signed-in state otherwise | 429 capacity_exceeded for bootstrap cap |
| POST /auth/login | exact Origin, bootstrap/session CSRF; JSON schema_version=1 | 200 LoginStart with trusted authorization_url; records five-minute attempt | 400 invalid_request, 409 workspace_busy, 503 identity_unavailable |
| GET /auth/callback | unique code+state or error+state; initiating cookie required | 303 / with rotated opaque cookie after both token checks | 303 / with safe one-shot login error; invalid binding gets generic 400 login_invalid |
| POST /auth/logout | JSON schema_version=1, exact Origin+CSRF; valid session | 204 after immediate admission invalidation; draining continues under busy gate | 401 sign_in_required; no provider logout claim |
| GET /workspace/runs | session cookie | 200 session-owned JobView list, newest first | 401 sign_in_required |
| POST /workspace/runs | session cookie, CSRF, JSON TaskSubmission | 202 new JobView; 200 duplicate same-key/body | 400 invalid_request; 401 sign_in_required; 409 busy/capacity/conflict; 503 workspace_unavailable |
| GET /workspace/runs/{job_id} | session cookie, UUID | 200 JobView | 401 sign_in_required; 404 run_not_found for foreign/missing |
| POST /workspace/runs/{job_id}/retry | session cookie, CSRF, JSON RetrySubmission | 202 fresh JobView; 200 existing successor for a duplicate retry | 404 run_not_found; 409 retry_unavailable/conflict/busy; 401 sign_in_required |

LoginStart contains schema_version=1 and the validated authorization_url with protocol state, nonce
and PKCE challenge. Only this response may expose those required authorization parameters; it
contains no tokens or PKCE verifier. Script navigates with location.assign, not an automatic fetch
redirect to the identity provider.

SessionView: schema_version, signed_in, requires_sign_in, csrf_token, profiles, configuration_issues,
optional fixed login_error. It exposes no identity claims or credentials. Profiles include only
reviewed server definitions, not user-supplied capability configuration. CSRF is intentionally
available to same-origin script and is never logged. Login errors are fixed codes stored in the
bootstrap context, never provider descriptions or callback query parameters.

TaskSubmission: schema_version=1, submission_id UUID, task string, profile identifier from configured
definitions (`^[a-z][a-z0-9-]{1,63}$`, default parent). RetrySubmission: schema_version=1 and
submission_id UUID only. Additional fields are rejected. A duplicate key with a changed route/body
conflicts. Capacity checks occur after duplicate lookup, so retained jobs can always be retrieved.
A different key targeting an already consumed retry candidate returns its existing successor;
no second prompt is sent. Its key still occupies one of twenty submission slots; a new key
at capacity is rejected without creating an alias. Eligibility and candidate consumption are atomic with global admission.
Admission failure before scheduling leaves the candidate available for a later deliberate attempt.

JobView fields: schema_version, job_id, request_id, run_id (nullable until reservation), parent_job_id
(nullable), kind, state, created_at, started_at (nullable before execution), finished_at (nullable),
result (nullable summary), truncated boolean, approval_status, action_summary (nullable fixed
simulated restart description), cleanup_status, retry_available, error (nullable WorkflowError).
Only the owning live session can retrieve it. Job history lasts through that session, capped at
twenty; capacity explains Sign out and sign in again after active work finishes. No bulk delete
or automatic eviction can make an old submission UUID executable again inside the same session.

## Authentication contract

Use a configured confidential login client with the existing client_secret_basic/post setting.
Validate HTTPS authorization, token and JWKS endpoints using existing configured trust rules;
redirect_uri is derived from the fixed bound loopback origin. Never trust Host to construct it.
Use response_type=code, response_mode=query, state, nonce, code_challenge and S256; request exactly
configured scopes including openid. Consume the matching attempt under lock before exchange.
No automatic code exchange retry; network uncertainty starts a fresh login transaction.

The initial response requires access and ID tokens. Validate ID claims separately from access-token
typ/audience. The token response's expires_in can shorten, never extend, verified JWT expiry.
A refreshed ID token may be absent; if supplied validate it and any returned nonce. Scope authority
comes from verified access claims, never browser claims or requested scopes. Refresh cannot change
issuer or subject. No refresh-token expiry is invented from expires_in. Reauthentication clears the
prior session; it never automatically submits a waiting task or retries an approval.

## Trusted runtime and approval contract

Add an internal RunContext allocation path and an internal exact-action execution method; neither
is an HTTP generic execution API. Caller reserves a fresh request/run ID before any lifecycle event.
Runtime's existing default call shape and AgentResponse remain compatible. The workspace attaches a
per-job memory sink and credential snapshot; existing bearer routes never accept workspace cookies.

A shared trusted helper performs current profile capability, policy and containment checks; creates
a fresh bound approval; records typed waiting/outcome; and calls execute_simulated_write once after
valid approval consumption. The original tool and retry entry point share this helper. No model is
called for retry. Observer failure, invalid binding, expired identity or changed privilege denies
execution. The fixed restart action is `infra.write`, `sandbox/demo`, parameters change=restart;
only canonical bytes copied from a trusted previous attempt may become a retry candidate.

Typed native outcomes distinguish confirmed denial from unconfirmed expiration/failure. Retain the
existing aliases and fail closed on unknown states. A bool compatibility backend may continue to
work for existing callers; False maps to unconfirmed unless trusted typed evidence establishes
explicit denial. Keep original source evidence classification and validation result semantics intact.
No source correlation rule is relaxed to satisfy the workspace.

Store terminalization and consumption race under a lock: pending decisions require unexpired state;
consumed/denied/expired/cancelled/unconfirmed/superseded never become approved. Sign-out and run
termination invalidate all unconsumed approvals before cancelling the task. Late native success
is ignored for authorization. Successful writes cannot become retryable after later model failure.

The workspace derives terminal status from trusted execution facts. Unconfirmed approval is failed
with approval_unconfirmed; confirmed policy/approval denial is denied; cleanup failure is failed;
operator cancellation is interrupted unless cleanup failure takes precedence. Completed requires
runtime success plus verified cleanup. Never trust a model sentence to override these facts.

## Closed error catalog

Each WorkflowError consists of code, stage and next_action; text is a fixed UI mapping. Internal
SecurityError codes map into this catalog; arbitrary exception/provider strings do not pass through.

| Code | Stage | Next action / visible instruction |
|---|---|---|
| sign_in_required | identity | sign_in — Select Sign in again |
| login_cancelled | identity | sign_in — Sign in was cancelled; select Sign in to try again |
| login_invalid | identity | sign_in — Sign-in could not be verified; start a new sign-in |
| identity_unavailable | identity | retry_sign_in — Identity service unavailable; try Sign in later |
| token_lifetime_short | identity | configuration — Increase provider token lifetime or reduce task budget, then sign in |
| configuration_missing | configuration | configuration — Configure the named missing setting or extra |
| invalid_request | request | edit_task — Check the task and selected profile |
| request_forbidden | request | reload — Open the printed local workspace URL and reload |
| submission_conflict | request | new_submission — Use a new submission for changed task text |
| workspace_busy | request | wait — Wait for the current task and cleanup to finish |
| capacity_exceeded | request | new_session — Finish active work, then sign out and sign in |
| run_not_found | request | reload — Reload the run list for this session |
| workspace_unavailable | cleanup | inspect_cleanup — Cleanup is unresolved; check cleanup before restarting the workspace |
| profile_unavailable | configuration | configuration — Select a configured profile with the needed capability |
| model_unavailable | model | inspect_configuration — Check the selected provider configuration |
| task_failed | runtime | inspect_result — Review the failed stage before starting another task |
| policy_denied | policy | check_permissions — This identity/profile lacks permission for the requested action |
| database_unavailable | database | inspect_configuration — Check database and delegated credential configuration |
| approval_denied | approval | none — The requested action was denied |
| approval_unconfirmed | approval | retry_approval or inspect_result — No confirmed decision; Retry appears only when safe |
| approval_invalid | approval | inspect_configuration — Approval binding could not be verified |
| approval_unavailable | approval | inspect_configuration — Configure and enable the phone integration |
| retry_unavailable | approval | inspect_result — This attempt cannot be retried |
| cleanup_failed | cleanup | inspect_cleanup — Credential cleanup failed; resolve it before another attempt |
| interrupted | runtime | new_submission — Task stopped; inspect cleanup status before starting another |

Only configuration_missing may include a list of allowlisted setting/extra names. No configuration
values or upstream error descriptions are included. A failed stage is shown only when trusted facts
identify it; otherwise use task_failed. The UI must not claim to have observed a phone app crash.

## UI contract

One page with Sign in/Sign out, labeled task textarea, profile selector, Run button, current status,
result and a bounded prior-run list. Include a sample read task, `Read database record 1`, with a
clear note that it uses the configured database. Simulated restart is labeled as simulated.

Buttons have loading/disabled states. Reuse a submission UUID on uncertain network delivery;
regenerate it only for a new deliberate task. Polling and page reload fetch state only. Disable Run
while busy and show cleanup as work still in progress. An eligible Retry approval button states
that it requests a fresh phone decision for the displayed action, and sends only the parent ID plus
submission UUID. There is no browser Approve/Deny button.

Use semantic form labels/buttons, visible focus and aria-live polite status with assertive errors;
move focus to an error/result heading on terminal action without stealing focus every poll. Render
model/task/provider-facing text with textContent, no HTML/Markdown execution. No external fonts,
CDN resources, browser token APIs, localStorage or service worker. Keyboard tests cover every control.

## Compatibility and verification

Existing CLI/API token workflows, default settings precedence and v1 validation records remain
readable. New state does not enter validation evidence automatically. The installed base wheel must
import and run offline commands without server/browser SDKs; workspace explains the missing extra.
Static assets must exist in the server-enabled installed wheel outside the checkout. Expand the
publication policy for exactly the three bundled assets, retaining all private exclusions.
