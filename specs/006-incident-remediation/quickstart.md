# Validation guide: Incident containment and exact cleanup

This is a post-implementation guide. Planning does not execute these new commands or
change providers. See the [runtime contract](contracts/runtime.md) for arguments and
the [validation ledger](validation.md) for evidence boundaries.

## Offline software checks

Use the locked environment and existing optional server/browser dependencies:

```sh
uv sync --locked --extra server --extra logfire --extra postgres --group dev --group browser
uv run --group browser playwright install webkit
uv run pytest -q tests/test_response_models.py tests/test_response_store.py tests/test_response_migration.py tests/test_response_auth.py tests/test_response_intake.py tests/test_response_guard.py tests/test_response_coordinator.py tests/test_response_cli.py tests/test_response_crash.py tests/test_response_privacy.py
uv run --group browser pytest -q tests/browser/test_workspace_containment.py
uv run agent validate run
uv run agent demo
```

Expected scenarios:

1. Submit a signed synthetic relay event during a controlled root execution. Confirm
   durable containment before acceptance, cancellation request within 2s, blocked child
   work and a healthy sibling still eligible under normal global limits. Submit a
   definition event and prove every supported entry point stays blocked after restart.
2. Send unauthorized/wrong-audience/wrong-source/stale/conflicting/oversized signals.
   Confirm zero containment or provider calls; an identical retained duplicate returns
   its incident without another action, including after its freshness window.
3. Observe ownership recorded before credential issuance. Complete ordinary owner
   cleanup and prove no second revoke. Inject an unresolved attributed lease and prove
   only its handle is revoked. Unknown and legacy handles remain blocked.
4. Crash before/after each durable transition and provider boundary. Restart and prove
   holds survive, submitted effects become uncertain and nothing replays automatically.
   Exercise lock contention, corrupt/missing files, migration crashes and full capacity.
5. Reconcile an existing recovery receipt, release the current complete definition hold
   set, and start a fresh root. Old roots/approvals and stale release requests fail.
6. In WebKit, verify owned job summaries, cross-session isolation, aggregate anonymous
   status, sign-out/expiry behavior and retained failed job history. No admin control or
   credential appears. Automated fixtures do not prompt a phone or call providers.

All fixtures use temporary private roots through test-only dependency injection, no
production root override. Existing CI repeatability, offline network denial, privacy,
runtime, formatting and distribution checks remain required for implementation.

## Migration and local enrollment

After implementation, stop workspace and response processes. Preserve existing private
recovery files. For an already enrolled database installation run:

```sh
uv run agent recover status
uv run agent recover migrate
uv run agent respond init --prepare
```

A fresh database installation runs existing `agent recover init` first; implementation
creates schema 2 directly. Non-database installations need only response enrollment.
Migration must report successful conversion or an idempotent v2 result without provider
calls. Legacy unresolved attempts remain visible and are not assigned to a run.

Open `.local/response/policy.json` locally. Keep the generated definition, environment
digest and issuer. Keep `intake_mode: local_only`, empty sources and null audience for
local commands without a relay. For relay use, set intake_mode to relay and use
`config/response.example.json` to fill the dedicated response audience and each approved
relay's exact issuer, subject and scopes. These values come
from the operator's registered automation identity, not a guessed user name or model.
Leave `automatic_cleanup` false for local containment-only use; enabling it explicitly
permits exact attributable cleanup with the existing configured operator credential.
Do not paste credentials into policy or command arguments.

```sh
uv run agent respond init
uv run agent respond status
uv run agent respond serve --port 8002
```

The server remains loopback. Native relay provisioning, vendor translation and public
hosting are follow-on work; the local operator path works without those integrations.
Restart the normal workspace after enrollment. All live paths enforce the same holds.

## Optional authorized live observation

Implementation can finish without a live run. If the operator separately authorizes
one, use the existing test role/workspace and a fresh authenticated session. Obtain the
current root UUID from private `agent respond status`, then in another terminal submit:

```sh
uv run agent respond submit --event-id manual-check-001 --occurred-at CURRENT_UTC --reason suspected_compromise --run ROOT_UUID
```

Replace `CURRENT_UTC` with the current UTC timestamp and `ROOT_UUID` with that exact
active root from private status. Keep the same event ID and content if delivery is
uncertain. With the responder running, inspect the returned response incident:

```sh
uv run agent respond status --incident RESPONSE_UUID
uv run agent recover status
```

Local cancellation and exact synchronous cleanup may be observed independently. A root
hold is terminal; it is never released to resume that job. For a separately authorized
definition test, replace `--run` with the configured `--definition` value. Once cleanup
is confirmed and all owners drain, use the complete incident list and current revision:

```sh
uv run agent respond release --definition DEFINITION_KEY --incident RESPONSE_UUID --revision CURRENT_REVISION --operator local-maintainer
```

Repeat `--incident` for every current hold member. If cleanup is incomplete, follow
the exact recovery command reported by status, then reconcile before release. Do not
clear private state, assume expiry proves revocation, or request audit access again.
Record unavailable audit and all untested external controls independently. Never claim
this single serialized live read proves concurrent native sibling-lease isolation,
native VIP detection, JWT/session termination, or complete Function 10 acceptance.
