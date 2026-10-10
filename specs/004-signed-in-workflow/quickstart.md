# Quickstart validation: Signed-in agent workflow

Run software checks before the separate live walkthrough. Controlled tests use synthetic signed providers and do not establish live product enforcement.

## Deterministic software checks

```sh
uv sync --locked --extra server --extra logfire --extra postgres --group dev --group browser
uv run playwright install webkit
uv run --group browser pytest -q --ignore=tests/browser
uv run --group browser pytest -q tests/browser
uv run ruff check .
uv run ruff format --check .
uv run python scripts/check_gates.py --all-features
uv run python scripts/check_gates.py --runtime-only
python3 scripts/check_privacy.py --history
uv run agent validate run
uv run agent demo
uv build
uv run python scripts/check_distribution.py
```

CI installs WebKit's system dependencies with `uv run playwright install --with-deps webkit`.
The browser suite must fail if its required tooling is absent; it cannot silently skip in CI.
Tests inject synthetic identity/provider/model/broker/approval adapters through Python fixtures,
never a production configuration bypass. Deny all unmocked external network calls.

Expected results: all prior tests pass; ten deterministic signed-in database reads clean up exact
leases; all invalid identity, cross-site/cross-session, duplicate submission and stale approval
cases perform zero forbidden effects. Browser tests cover keyboard-only sign-in/task/result,
renewal, sign-out, reload, inert markup, each approval state and one eligible explicit retry.

Build/install the base wheel in an isolated environment outside the checkout: no server/browser/
Logfire/PostgreSQL SDK is required for offline commands. `agent workspace` without the server extra
must return an actionable install instruction. Repeat with server extra and ensure the three
bundled assets load from package resources. Inspect wheel/sdist for private tokens/browser files.

## Local browser workflow

1. Install the existing selected model provider and integrations, for example:

   ```sh
   uv sync --locked --extra server --extra google --extra postgres --group dev
   ```

2. Keep current private model, actor OAuth, database and telemetry configuration in `.env.local`.
   Configure LOGIN_CLIENT_ID and LOGIN_CLIENT_SECRET for the existing interactive login registration.
   Set LOGIN_SCOPES to the granted scopes required for the example, such as
   `openid offline_access database:read tickets:read`. Add `infra:write` only for a selected simulated
   approval exercise. If offline_access is unsupported, omit it; the workspace will ask for sign-in
   again when renewal is unavailable. The access token must target existing OAUTH_AUDIENCE.

3. Register exactly `http://127.0.0.1:8000/auth/callback` with that login application if it is not
   already registered. This is a prerequisite; the workspace does not change provider settings.
   Configure authorization-code/S256 PKCE and refresh grants when supported. Keep actor and login
   credentials separate. Token lifetime must cover TIMEOUT_SECONDS + 45 seconds.

4. Start the workspace:

   ```sh
   uv run agent workspace
   ```

   Open the printed `http://127.0.0.1:8000/` link. If the port is occupied, close the identified old
   local listener or choose `--port 8002` and register that exact callback. Never stop an unrelated
   process merely to free the default port. Use Playwright/WebKit for agent-driven browser checks.

5. Select **Sign in** and finish provider authentication. For IBMid QR authentication, open
   IBM Verify on your phone and use its **Scan QR code** function; opening the QR link in phone
   Safari can fail before the workspace receives a callback. Choose **database-reader**, enter **Read database record 1**, and
   select **Run**. Expect a bounded result, request/run correlation and cleanup shown as revoked
   when a credential was acquired. Refresh the page while running; no second task should start.

6. Let a short-lived token approach expiry, submit a new read, and confirm one renewal when the
   provider supports it. Otherwise expect **Sign in again**, with no task started automatically.
   If lifetime remains too short after renewal, follow the displayed lifetime/budget instruction.

7. Select **Sign out** while a controlled read waits. The page signs out immediately; the server
   retains cleanup authority and refuses another job until cleanup finishes. Restart signs out
   all sessions and restores no tasks. Local sign-out is not provider-wide revocation.

## Approval behavior (controlled tests first)

Test approved → exactly one simulated write, denied → zero writes, and unconfirmed → zero writes
with eligible Retry only after cleanup. Use Retry once and verify fresh request/run/approval IDs,
no second model call and no repeated prior tools. Deliver a late success to the old attempt and
verify zero additional effects. Successful, explicitly denied, interrupted and uncertain-effect
attempts must have no Retry. The page never claims to observe a phone app's internal error.

A live phone exercise is optional and requires an explicit operator action per prompt. Do not
repeatedly send prompts to diagnose an app failure. A pending state is not a recorded denial.

## Live record and handoff

Record only sanitized outcomes in validation.md: which stage passed or blocked, owner, check time,
and which private observation was inspected. Store any raw native/browser evidence under ignored
`.local/`, with existing private file permissions. Do not publish provider identifiers or credentials.
A successful model summary alone does not prove database execution or exact revocation; inspect
trusted lifecycle facts and applicable native evidence. Existing 003 evidence gaps remain open.

Software completion is reported even when the live walkthrough is blocked. Keep that task open
and give one concrete action for the missing prerequisite. PR preparation/merge is a later explicit
request, with fresh review/protection checks; 004 has no inherited exception from PR #4.
