# Research: Signed-in agent workflow

**Date**: 2026-10-09. Decisions apply to the local workspace only. Product limits below are
chosen design constraints, not claims imposed by OAuth standards. No live service changes were made.

## R1 — Reuse the optional server, with a separate browser application

**Decision**: A separate FastAPI app launched by `agent workspace` serves bundled static assets
and memory-backed session routes. Keep `agent serve` and bearer `/runs` intact. Use lifespan-owned
HTTP clients, expiry cleanup and job shutdown. No runtime dependency is added.
**Rationale**: `api.py` already establishes the optional service boundary, but cookie auth must not
silently replace its bearer contract. Lifespan supplies explicit resource ownership.
**Alternatives**: A new Node frontend or persistent job/session service adds installation and
credential storage obligations without helping a one-operator local workflow.
**Source**: [FastAPI lifespan](https://fastapi.tiangolo.com/advanced/events/).

## R2 — Separate the login registration from actor credentials

**Decision**: Add LOGIN_CLIENT_ID, LOGIN_CLIENT_SECRET and LOGIN_SCOPES; reuse configured issuer,
discovery, audience and client authentication method. Support corresponding POCDANTIC aliases.
The login client is confidential and must already support the exact callback and code grant.
Default scopes are `openid`; documented examples add `offline_access` and required resource scopes.
**Rationale**: `DatabaseBroker` uses OAUTH_CLIENT_ID/SECRET for actor identity and token exchange;
replacing them during interactive login would change the delegation boundary. Verify API credentials
remain separate. Missing provider grants/scopes produce a configuration explanation, not provisioning.
**Alternatives**: Reusing the actor client or copying a user token into `.env.local` was rejected.
**Source**: [IBM token endpoint](https://docs.verify.ibm.com/verify/reference/post_oauth2-token).

## R3 — Code login and two distinct token validations

**Decision**: Use authorization code with S256 PKCE, browser-bound single-use state and nonce.
Trust configured discovery/issuer and validate authorization/token/JWKS endpoints before use.
Validate the ID token for login-client audience, signature, issuer, expiry, nonce and authorized
party; separately verify the access token with the existing resource audience and token type.
Require their issuer/subject to agree. Do not infer trusted configuration from returned claims.
**Rationale**: The existing JWTVerifier is explicitly an access-token verifier. Merely generating
a nonce without validating an ID token would not complete the planned OIDC login checks.
**Alternatives**: Implicit flow, browser-held access tokens, ID-token-as-access-token and accepting
an arbitrary callback destination were rejected.
**Sources**: [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.7.1),
[OIDC ID validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation),
[JWT access-token validation](https://www.rfc-editor.org/rfc/rfc9068.html#section-4),
[IBM PKCE](https://docs.verify.ibm.com/verify/docs/oauth-20-grant-type-authorization-code).

## R4 — Single renewal before admission, with cleanup lifetime reserved

**Decision**: Extend token parsing with secret ID/refresh tokens and refresh grant support.
Under a session lock, renew once if verified expiry is less than the runtime budget plus 45 seconds
(30 cleanup plus 15 margin). Revalidate issuer/subject and granted scopes; reject insufficient
lifetime after renewal. Replace rotating refresh tokens atomically. A refresh response without a
new refresh token retains the prior one. Ambiguous refresh failure invalidates renewal and requires
sign-in; the application does not retry a possibly consumed refresh token.
**Rationale**: Existing database cleanup obtains a fresh delegated revoke token using the run's
original subject token. Credentials cannot change mid-run. OAuth `expires_in` describes access-token
lifetime, not a universal refresh-token expiration. Local session expiry bounds refresh use.
**Alternatives**: Timer-based background refresh, guessing refresh expiry and automatic replay after
reauthentication were rejected. Refresh may omit an ID token; any supplied one is validated with
identity continuity and matching nonce if present.
**Sources**: [OAuth refresh](https://www.rfc-editor.org/rfc/rfc6749.html#section-6),
[OIDC refresh response](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse).

## R5 — Opaque local cookies with explicit request defenses

**Decision**: Memory-only sessions use opaque host-only HttpOnly SameSite=Lax cookies. Bind only
127.0.0.1, validate the exact Host including port, reject forwarded-host authority, and require
exact Origin plus CSRF on every mutation. The provider GET callback is the narrow exception,
protected by the initiating cookie/state/PKCE/nonce. No CORS or remote-host option.
**Rationale**: Cookie sessions require CSRF defenses even on localhost. Signed cookie payloads
remain readable and are unsuitable for tokens. The deliberate HTTP loopback-only design does not
rely on Secure-cookie exceptions working identically in WebKit. It does not protect against a
malicious local process/browser extension or claim suitability for remote hosting.
**Alternatives**: Starlette SessionMiddleware containing tokens, browser localStorage, permissive
localhost aliases and arbitrary port/proxy headers were rejected.
**Sources**: [OWASP CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html),
[OWASP sessions](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html),
[Starlette middleware](https://starlette.dev/middleware/),
[RFC 8252 loopback guidance](https://www.rfc-editor.org/rfc/rfc8252.html#section-8.3).
RFC 8252 is guidance for native clients; it does not make this configured confidential client public.

## R6 — Retry one frozen action, never a whole model task

**Decision**: Add typed approved/denied/unconfirmed outcomes and atomic terminal approval states.
Extract the existing simulated-action approval/execution sequence into a trusted helper shared by
the model tool and a new internal runtime retry entry point. Store canonical action bytes, new
request/run/approval IDs and trusted effect counts. A retry is allowed only after terminal drain,
with exactly one retry candidate, matching issuer/subject and current profile/policy permission.
**Rationale**: `wait_for_decision()` currently conflates explicit denial and failure/expiry; a pure
poll deadline leaves a pending Approval. `Action.parameters` is mutable despite its frozen model.
Whole-task replay could repeat prior reads or writes and produce a different action. A consumed
write stays non-retryable even if later model output or telemetry fails.
**Alternatives**: Treating timeout as denial, a browser approval setter, user-edited retry payload,
or resuming old message history were rejected. Unsupported or mismatched source binding is never
retryable. Existing bool backend callers retain compatibility through an explicit adapter: False
alone is unconfirmed; it cannot manufacture an intentional denial.
**Evidence**: Inspected `approval.py`, `capabilities.py`, `runtime.py`, `services.py`, `verify.py`
and current tests. Existing precise denial aliases remain DENIED, VERIFY_DENIED and USER_DENIED.

## R7 — Job ownership includes cancellation and cleanup

**Decision**: One process-wide active slot covers admission, execution and cleanup. Session expiry
or sign-out revokes browser authority immediately, contains the run, invalidates approvals and
cancels the job. Credentials survive privately until cleanup terminates. Bound cleanup to 30
seconds plus a five-second cancelled-task drain; unresolved cleanup quarantines further admission.
**Rationale**: `VaultClient.credentials()` already shields revocation from repeated cancellation,
but its deadline path needs explicit child draining and stable cleanup failure classification.
Terminal UI success must depend on trusted cleanup/effect facts, not a model summary.
**Alternatives**: Releasing the slot on HTTP disconnect, dropping credentials immediately, and
marking cancellation complete before cleanup were rejected. No persistence or restart replay.

## R8 — Plain assets and real WebKit tests

**Decision**: Bundle index.html, app.js and style.css; render untrusted text with textContent.
Use Python Playwright directly in a separate development group, WebKit on macOS/Linux and no
external frontend packages. Lock the chosen version at implementation and install its matching
browser binary in CI. Tests cover keyboard controls, reload, CSRF, inert markup, expiry and retry.
**Rationale**: Fits the current Python package and the operator's browser preference. Playwright
uses its own WebKit build, not automated system Safari. Browser fixtures use controlled providers,
not a shipped fake-login flag. Assets need a narrowly expanded publication policy.
**Alternatives**: Native Mac UI automation, an SPA dependency stack and shipping browser binaries
were rejected. Test output is synthetic and private by default; no live browser storage is saved.
**Sources**: [Playwright browsers](https://playwright.dev/python/docs/browsers),
[Playwright license](https://github.com/microsoft/playwright-python/blob/main/LICENSE).

## R9 — Completion and evidence remain separate

**Decision**: Software tasks require deterministic passing checks. Live login/database observation
gets a separate task and safe record with owner/stage; unavailable vendor proof stays open. No
customer acceptance is promoted and no 003 task is silently closed. Future PR delivery gets its
own task; the 003 merge exception does not carry forward.
**Rationale**: This implements the operator's direction to continue building despite phone failures
while preserving evidence-before-acceptance. A screenshot or model result is not source proof.
