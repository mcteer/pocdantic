# Validation ledger: Signed-in agent workflow

**Status**: T001–T033 software work completed on feature/004-signed-in-workflow.
T034 configured live walkthrough completed on 2026-10-10, including the no-refresh
sign-in-again fallback and sign-out during an acquired-credential read. T035 delivery is in progress under the owner's explicit push/PR/merge-after-green-CI instruction.

## Implemented behavior

The local browser workspace uses a separate confidential login client with code/S256 PKCE,
browser-bound state, ID-token nonce and independently verified access tokens. Server memory
holds credentials, sessions, bounded job history and idempotency keys. Refresh occurs once
under the session lock at admission and reserves lifetime for execution and cleanup.

A shared runtime reserves trusted IDs before effects, preserves containment and holds one
global slot through admission, execution and cleanup. Sign-out refuses admission before
draining work. Public status uses trusted approval, read, cleanup and simulated-effect facts.
A database profile cannot report completion solely from a model success claim.

Approval outcomes distinguish approved, denied and unconfirmed. Terminal invalidation and
expiry checks reject late decisions. Explicit retry freezes canonical action bytes, rechecks
identity/profile/policy and executes one fresh approval without model or prior-tool replay.
Twenty distinct submission keys include retry aliases; there is no in-session eviction.

## Test development and results

Boundary/publication tests were run failing before the asset allowlist, models and middleware.
Auth/session and application tests initially failed for missing modules. Runtime reservation,
typed native failure outcomes, decision expiry/invalidation, cleanup child drain and normalized
failure, exact integer schema version, duplicate security headers, bootstrap capacity,
false model success and direct poll cancellation were also observed failing before their fixes.
Additional integration, race, privacy and browser tests verify the resulting behavior.

Commands and results:

| Check | Result |
| --- | --- |
| uv run --group browser --extra server --extra postgres --extra logfire pytest -q | 324 passed in 62.14 seconds, including all seventeen WebKit scenarios |
| uv run pytest tests/test_verify.py tests/test_security.py tests/test_validation_scenarios.py -q | 40 passed after terminalizing cancelled/malformed/storage-failed polls |
| uv run ruff check . | Passed |
| uv run ruff format --check . | Passed; 136 files |
| uv run python scripts/check_gates.py --all-features | All four feature gates passed; fifteen live criteria per feature remain blocked |
| uv run python scripts/check_gates.py --runtime-only | Passed |
| python3 scripts/check_privacy.py --history | Passed after staging the implementation and planning artifacts |
| git diff --cached --check | Passed after correcting CSS trailing whitespace |
| uv run agent demo | Passed, synthetic delegation |
| uv run agent validate run | Passed, nine deterministic scenarios; no live acceptance promotion |
| uv build | Wheel and source distribution built |
| uv run python scripts/check_distribution.py | Passed; exact three workspace assets verified in both artifacts |

Seventeen WebKit scenarios use synthetic signed identity and controlled native/broker responses.
They cover keyboard sign-in/sign-out, nonce rejection, renewal, retained results, lost response
and UUID reuse, separate signed-session ownership, foreign Host/Origin, inert markup, waiting/
approved/denied/unconfirmed approval, explicit retry without model replay, ten complete database
reads, permission denial, multiple sequential leases, sign-out during read and cleanup, and
stable keyboard focus while polling. Controlled transitions satisfy the two-second display bound.
All unmocked browser routes and backend fixture requests are rejected. No real phone prompt was sent.

WebKit visual inspection used a synthetic completed read. Layout and inert result display were
checked; the screenshot stays ignored and private under .local/. No browser storage state or
live credentials were saved.

## Dependencies, build and installed-package checks

Browser-only dependencies are locked: Playwright 1.63.0 (Apache-2.0), pyee 13.0.1 (MIT),
greenlet 3.5.6 (MIT AND PSF-2.0). Package metadata/licenses were reviewed. None is a runtime
dependency; existing server/model/database extras remain separate.
Matching WebKit was installed with uv run --group browser playwright install webkit.
CI requires the locked browser group and installs WebKit with --with-deps; tooling absence fails.

Fresh wheel installs were exercised outside the checkout in separate base and server environments.
Base Python 3.14.7: offline demo passed; FastAPI, Uvicorn, Playwright, Logfire, PostgreSQL,
OpenAI and Anthropic SDKs were absent. Workspace exited 1 with the exact server install command.
All bundled assets were accessible through importlib.resources.
Server Python 3.12.14: packaged index/assets/session routes passed under a network-denying transport,
and an unknown asset returned 404, with model/provider/browser SDKs absent. Final wheel reinstalled
in both environments. Distribution checks reject unexpected or missing workspace assets.

## Boundary and threat review

Exact loopback Host and port are enforced on every route. Foreign, missing and null mutation
Origins, duplicate authority/CSRF/content headers, duplicate/malformed cookies, oversized bodies
and wrong CSRF are rejected. Callback inputs are unique, bounded and bound to a single-use
browser transaction. Redirects derive from the configured loopback origin; proxy authority,
CORS, generic action execution and browser approval setters are absent.

Opaque values contain 256 random bits; login attempts/bootstrap contexts expire after five minutes.
Four sessions, sixteen bootstraps and twenty jobs/keys per session bound retained authority.
Polling does not extend idle expiry and makes no effects. Token refresh ambiguity removes renewal
authority; identity changes and insufficient token lifetime prevent execution.

Credentials, raw native bindings and identity claims have no public job or lifecycle fields.
CSP, no-store, no-referrer and nosniff protect responses. HTTP access/query logging is disabled.
Output uses textContent. Browser storage contains no credentials, task text or result history.

Cleanup drains cancellation for five seconds after the thirty-second budget. A stubborn child
retains its private context and quarantines admission until it stops. Failed observation cannot
skip revocation. Cleanup errors are normalized and terminal child exceptions are retrieved.
Unknown acquisition or cleanup never establishes success or retry eligibility.

## Configured live walkthrough — T034 complete

On 2026-10-10, the operator completed IBMid sign-in in ephemeral WebKit after scanning
its QR code inside the IBM Verify app. Opening that QR link in phone Safari had produced
an IBM login-server error. The workspace received an authorization code callback (HTTP 303),
validated the credentials, and reported a signed-in session.

The private controller submitted “Read database record 1” using database-reader. Ten live
jobs completed without an error. Each recorded one lease acquired, database-read completion observations,
one lease revoked, and cleanup status revoked. No tokens, identity claims, record contents,
or QR payloads are included in this ledger.

The next submission, intended to approach token expiry, failed before any observed read:
zero acquisitions with known lease handles, zero reads, cleanup unknown, error cleanup_failed.
The workspace quarantined further admission. A zero acquisition counter does not establish
that Vault created no lease. Source inspection shows non-401/403 acquisition failures or a
missing lease handle cause this uncertainty; this controller did not capture the underlying
provider error, so no particular cause is asserted. A read-only native lease-list attempt was
rejected with HTTP 403; native outstanding-lease reconciliation remains unavailable.

The saved login-application configuration specifies a 600-second access-token lifetime and
no refresh tokens. Renewal cannot be claimed. Quarantine prevented the intended near-expiry
sign-in-again observation. The operator then selected Sign out. The live controller observed signed_in false and
zero retained session jobs after the server removed the session. An unauthenticated request
to the protected runs route returned HTTP 401. Live sign-out after terminal jobs passed;
sign-out during an active controlled read remains covered by software tests only. Future
controller launches support sign-out and reload. At this stage T034 remained open for the unresolved
acquisition/expiry check; the following entries record recovery and completion. This limitation does not reopen software
validation or change acceptance dispositions.

Follow-up diagnosis reproduced the failure with a fresh verified IBMid session and 579
seconds of token lifetime remaining. Private instrumentation recorded vault_request_failed
on credential acquisition after 15.09 seconds, while Vault seal-status responded HTTP 200.
A direct operator database connection through the configured Supabase pooler then returned
FATAL: Failed to connect to database: {:error, :econnrefused}. The pooler TCP connection was
reachable. This establishes a pooler-to-database connectivity failure independently of the
workspace and token expiry; project pause, network bans, and other underlying causes have
not been distinguished. No lease uncertainty was cleared, no automatic retry was performed,
and no tenant configuration was changed. Supabase dashboard inspection is the next step.

Prior IBM denial-app failures and the Vault native-audit evidence gap remain incomplete.
No acceptance.json entry was promoted or inferred from synthetic tests.

## Final software gate

All T001–T033 software tasks are checked. The final regression ran after the approval poll
cancellation/storage-failure hardening. Subsequent updates changed only validation/task status
and CSS formatting; distribution and staged privacy/whitespace gates were rerun.
The final wheel/sdist build includes that hardening.

## Delivery and hooks

No push, PR, merge or repository-protection change was performed. T035 requires a later delivery
request and fresh CI/protection/review checks or a newly scoped owner exception. PR #4's exception
expired on its merge. Changes are staged for review; private helpers and screenshots are excluded.

.specify/extensions.yml is absent. Pre/post implementation hooks were checked and skipped accordingly.

Follow-up after the operator reported Healthy: the supplied dashboard screenshot shows
21/60 connections, CPU 3%, and 15 PostgreSQL errors. The project reference matches the
private configured pooler URI. Read-only connection probes through both session (5432)
and transaction (6543) poolers still returned econnrefused. Direct database DNS has an
AAAA record but no A record; this Mac cannot route to that IPv6 address. No connection
configuration was changed. The operator was asked to check Database Settings for banned
IPs, a documented possible cause; no ban has yet been established.

The operator subsequently showed one network-banned IP and selected Unban IP. An
immediate read-only operator connection through the same pooler succeeded (SELECT 1);
the database role catalog showed zero unexpired Vault-generated roles. This demonstrates
that removing the ban restored connectivity, but is not native lease reconciliation.
No known credential was retried after revocation. The provisioning script has an explicit
revoked-credential negative test, but its recorded run was on the prior day; that alone
does not establish the cause of this ban. The quarantined server was stopped and a fresh
workspace started; the original unknown-acquisition result remains recorded.

After unbanning and restarting the workspace, a fresh IBMid session completed a live
database task. Instrumentation recorded a successful credential request (0.25 seconds)
and successful native Vault revocation (0.07 seconds). The live provider response has no
refresh token. The controller is waiting for natural expiry before its admission check.
The internal read counter receives both broker and tool completion events; it is not a
count of distinct SQL queries. Previous counter values must not be read as two SQL reads.

Three additional post-unban live reads completed with exactly one job per submission,
including browser reload during each running task, and matched acquisitions/revocations.
A read-only pg_stat_activity query confirmed that the address shown in the operator's
network-ban screenshot matches the current pooler-to-database client address. This explains
why a healthy database was unreachable through both pooler modes. The original authentication
failures triggering the ban remain unobserved; no claim is made about their source.

Natural expiry/admission check passed after recovery. With no refresh token available,
the controller submitted another read when the original token could no longer cover
the configured execution budget plus margin. The session transitioned to reauth_required,
the UI reported signed out/sign-in required, and job count remained four. Native call
count remained eight (four successful acquisitions and four successful revocations).
No extra model task or Vault request was started. This is live evidence of the supported
sign-in-again fallback, not evidence of refresh-token renewal. The final controlled
sign-out-during-read check was then performed after the operator's fresh sign-in.

## Live closeout — 2026-10-10

T034 is complete. After the supported expiry fallback, the operator signed in again.
The controller held a reversible lock on the marked synthetic poc_records fixture,
submitted a read, and selected Sign out while the new credential was acquired and the
read was blocked. Vault confirmed credential acquisition (0.17 seconds) and native
revocation (0.06 seconds). The server removed the session; the protected runs route
returned HTTP 401. The lock was released, the fixture remained readable with healthy
status, and the operator role catalog check found no unexpired Vault-generated roles.

The workspace was restarted with a fresh WebKit context. It reported signed_in false,
zero sessions, zero jobs, and zero native calls: credentials and tasks were not restored.
Fourteen normal live reads completed across the initial and recovered sessions. Browser
reload during three recovered running jobs produced one job per submission. The final
controlled interrupted read was separate and its acquired credential was revoked.

The configured provider supplied no refresh tokens; only its real no-refresh fallback
was exercised. The two pre-recovery acquisitions with unknown results remain explicitly
recorded, and exact native reconciliation for those original attempts was unavailable
(lease-list HTTP 403). The ban trigger is unknown. Removing the pooler-source network
ban restored connectivity and all post-recovery native calls succeeded. These limitations
do not imply a passing 003 audit criterion or change any acceptance.json disposition.
No new phone approval prompts, tenant changes, or database record/schema changes were made.

T001–T034 are checked. The owner subsequently requested T035 delivery. The private live controllers
and raw outcomes remain ignored; only sanitized documentation is staged.

## Authorized delivery — in progress

Owner: repository owner. Current instruction: “push + pr + merge when CI is green.”
Scope: this feature/004-signed-in-workflow PR only, expiring on its merge. Rationale:
the owner explicitly directed delivery after the completed software and live walkthrough.
Fresh GitHub inspection returned Branch not protected (HTTP 404) for main and no rulesets.
The authenticated GitHub account is the repository owner; there is no independent approval
yet. The owner instruction controls this delivery decision; it does not claim server-side
protection or independent review. No prior PR exception is reused and no settings are changed.
Compensating controls: prospective publication/security-boundary review, staged privacy and
whitespace checks, existing 324-test regression, and green CI on the exact PR head before
merge. Live unknown-acquisition results, the unknown ban trigger, unsupported refresh, and
003 audit/denial limitations remain disclosed. The PR/CI/merge identifiers will be recorded
as the delivery completes.

## CI finding and initialization fix

PR #5: https://github.com/mcteer/pocdantic/pull/5. Implementation commit
656384f33de3af4c9f2e0dd5eaa73e3fc5ef678e had a passing pull-request CI run
38060721688, but push run 38060696930 failed its first keyboard sign-in test (323 passed).
The test activated sign-in while browser session initialization was still pending.
A delayed-bootstrap WebKit regression was first observed failing because Sign in was
enabled during Loading. The initial HTML now disables Sign in and loadSession enables
it only after the cookie/CSRF response is loaded; keyboard testing waits for readiness.
No assertion retries or timeout increases were introduced.

Final local regression after that change: 325 passed in 63.71 seconds, including eighteen
WebKit scenarios. Ruff check/format, wheel/sdist build, and distribution privacy passed.
The earlier 324-test result remains historical. The revised head must pass both push and
PR CI before merging; the initial passing PR run does not waive the failed push run.
