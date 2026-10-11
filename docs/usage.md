# Runtime and integration guide

## Configuration

Copy `.env.example` to `.env.local` and fill in local values. Environment variables
override the file. Keep the file private. Run `uv run agent probe` for a status-only,
read-only connectivity report. It neither creates resources nor issues database leases.

| Setting | Purpose |
| --- | --- |
| `MODEL` | Pydantic AI model ID, such as `google-gla:gemini-3.8-flash` |
| `GOOGLE_API_KEY` / provider environment | Model credentials |
| `LOGFIRE_TOKEN` | Logfire project **write** API key; supplying this enables export |
| `OAUTH_PROVIDER` | `verify` or `generic` |
| `VERIFY_TENANT_URL` | Verify tenant; hostname or HTTPS URL |
| `OAUTH_DISCOVERY_URL` | Generic OIDC discovery URL, or explicit Verify override |
| `OAUTH_ISSUER` | Optional exact pinned issuer; otherwise trusted discovery supplies it |
| `OAUTH_TOKEN_ENDPOINT` | Optional token endpoint override |
| `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` | Agent OAuth client |
| `OAUTH_AUTH_METHOD` | `client_secret_post` or `client_secret_basic` |
| `OAUTH_AUDIENCE` | Dedicated API access-token audience; required for authenticated ingress |
| `OAUTH_ACCESS_TOKEN_TYP` | Required JWT header type, default `at+jwt` |
| `BEARER_TOKEN` | User access token for CLI runs; keep it in private environment |
| `VERIFY_API_CLIENT_ID`, `VERIFY_API_CLIENT_SECRET` | Separate Verify API client for push/inventory |
| `VERIFY_PUSH_ENABLED` | Explicitly enable live push in the simulated write capability |
| `VERIFY_USER_ID`, `VERIFY_AUTHENTICATOR_ID` | Trusted mapping of verified subject to enrolled phone |
| `TIMEOUT_SECONDS` | Entire parent/child deadline, default 45; use 150 for interactive push |
| `WORKLOAD_DEFINITION` | Stable runtime definition ID; never an invocation ID |
| `VAULT_ADDR`, `VAULT_NAMESPACE` | Vault deployment |
| `VAULT_TOKEN` | Operator token for read-only readiness probe; never model execution credentials |
| `VAULT_AUDIENCE`, `ACTOR_AUDIENCE` | Delegated Vault and actor JWT audiences |
| `VAULT_READ_PATH` | Exact dynamic read-role path, default `database/creds/poc-readonly` |
| `DATABASE_HOST`, `DATABASE_NAME`, `DATABASE_PORT` | PostgreSQL target with trusted TLS |
| `DATABASE_SSLROOTCERT` | Trusted PostgreSQL CA file |
| `DATABASE_USERNAME_SUFFIX` | Optional pooler routing suffix |
| `PROFILES_FILE` | Agent profile JSON; defaults bundled with the wheel |

Existing local variable names are supported: `VERIFY_AGENT_CLIENT_ID/SECRET` are
fallbacks for the agent OAuth client; `VERIFY_CLIENT_ID/SECRET` are fallbacks for
the administrative API client. Short settings take precedence over legacy aliases.
Interactive OIDC application credentials are separate from agent/service credentials.

Generic OIDC providers work with signed access-token verification and configurable
client authentication. Token exchange/RAR and push are provider features: an unsupported
provider fails closed. Discovery endpoints must use HTTPS; endpoints on another host
must be deliberately allowlisted in the OAuth adapter configuration.

Logfire instrumentation excludes model messages, tool arguments/results, binary content,
and model request parameters. HTTP headers/bodies are not instrumented. Change the write
key to route telemetry to a different Logfire project. Do not put secrets in task text.

## Authenticated runs and automation

Authenticated execution requires a signed access JWT with issuer, subject, audience,
expiry, issued-at and an accepted token type. The caller's scopes must include
`tickets:read`, `infra:write`, or `database:read` for the corresponding tool. JWT keys
come from trusted provider discovery. Human identity never comes from prompt fields.
The CLI and bearer service accept an externally acquired user access token. The browser workspace performs its own login and keeps session credentials in server memory.

```sh
uv run agent run --task 'Summarize POC-1' --profile parent
uv run agent batch --input requests.jsonl
uv run agent serve
```

JSONL input contains one request per line:

```json
{"task":"Summarize POC-1","profile":"parent"}
{"task":"Retrieve POC-2","profile":"ticket-reader"}
```

Batch returns one JSON result per line and a nonzero exit if any request fails.
The optional HTTP server binds to `127.0.0.1:8000`; `POST /runs` accepts the same
request with an `Authorization: Bearer` header. `/health` exposes no configuration.
Use the deployment platform for TLS, scheduling, workload attestation and secrets.

## Delegated database access

The database broker verifies the human API token, obtains a separate agent token,
and exchanges both for an exact `vault:path_access` read grant. Vault must bind the
issuer and external subject IDs to explicit human and agent aliases. The human's
baseline policy, agent registry ceiling and requested authorization details must
all permit the operation. The runtime never falls back to an operator Vault token.

After the fixed SELECT query, the broker requests a separate cleanup grant with
`required_parameters: ["lease_id"]` and `allowed_parameters` containing only the
acquired lease ID. Vault namespace suffixes in returned lease IDs are supported.
Cleanup failure prevents a successful result; cancellation still waits for cleanup.

Configure the provider's authorization detail type using
[config/vault-path-access.schema.json](../config/vault-path-access.schema.json).
A schema containing only `type`, `path` and `capabilities` rejects the parameter-bound
cleanup request. Verify schema setup requires `manageAuthDetailTypes` on the
administrative API client; agent execution does not require that entitlement.
The schema validates the grant's structure. Provider authorization and Vault policies
must independently enforce which human and agent can request those grants.

## Compose alternate agents

Edit `config/agents.json` or supply `PROFILES_FILE`. Each definition selects
reviewed native Pydantic AI capabilities and a trusted policy role. A read-only
profile can use a new stable ID with `ticket-read` and `policy_role: ticket-reader`.
A parent role can compose `delegate-tickets`, `simulated-infrastructure`, and
optionally `database-read`. The reserved child definition remains read-only.
Unknown capabilities and overprivileged child configurations are rejected at startup.

Add new adapters behind existing tool contracts or new reviewed capability factories.
Models cannot choose policy roles, endpoints, database roles, SQL, credentials, or
approval decisions. Current ticket data is synthetic; live Jira is not implemented.
Parent and child are logical agents inside one process and share workload trust.
Separate objects and registry entries do not create independent attestation.

## Verify phone approval

Enroll the phone in the PoC tenant using its user portal (`/usc/`), then
**Profile & settings → Security → Add new method → IBM Verify app**. Use the
existing **Verify Profile** registration profile if configured.

The PoC API client needs `readAuthenticatorsAnyUser`, `readEnrollMFAMethodAnyUser`,
and `authnAnyUser` to locate a phone/signing factor and initiate verification.
Reading registration-profile configuration also needs `readAuthenticatorsConfig`;
that permission is optional and is not needed for an already enrolled phone.

```sh
uv run agent push-demo
```

This isolated test selects exactly one active phone and its validated user-presence
signing factor (or the configured device/user), sends one push, polls the exact
transaction, verifies its action digest, and consumes the approval once. Only a
simulated write occurs. It does not create a production user session or Vault lease.
Evidence stays in ignored `.local/` files. Multiple enrolled phones require explicit
selection through configuration.

For model-requested live push, configure the subject/device mapping, enable
`VERIFY_PUSH_ENABLED=true`, and set the run timeout to 150 seconds.
The verified access-token subject must match the configured Verify user. A pending,
denied, expired, changed or replayed approval cannot execute the simulated action.
Without a backend, the tool returns `approval_required` and performs no write.

## Vault and database boundary

`database-read` uses `DatabaseBroker`: agent client credentials → subject/actor
exchange with exact `vault:path_access` RAR → delegated JWT claim validation →
Vault dynamic lease → fixed parameterized SELECT → connection close → separate
exact-lease cleanup grant → explicit lease revoke. No operator token is substituted if delegation fails. Malformed
credential responses with a lease handle still trigger cleanup. Cleanup failure
prevents a success result. Agent execution uses leased credentials; administrative
provisioning credentials remain local.

The target must supply the database secrets engine, a SELECT-only dynamic role,
`poc_records(id, status)`, TLS trust and appropriate OAuth profiles/registry/ACLs.
Vault RAR governs Vault API access; PostgreSQL grants govern SQL. Confirm actual
product version/licensing and OAuth feature availability before claiming enforcement.
`VaultClient.workload_login` supports a separately configured JWT auth mount and role;
an approved deployment issuer must supply signed workload JWTs. Operator token lookup
is not evidence of independent workload attestation or stable 100-run mapping.

Process-local containment is available through trusted `Runtime.contain_run` and
`Runtime.contain_definition` methods. Targeted cancellation preserves unrelated runs.
These are control-plane methods, not model tools or public HTTP endpoints. External
Vault tokens, leases, Verify JWTs/sessions and active DB sessions each need separate
remediation. VIP discovery, VIP-triggered remediation, SVID issuance/verification,
Teams notifications and customer closeout are not implemented in this baseline.

## Database provisioning and local fixtures

Local PostgreSQL can run in OrbStack with `uv run python scripts/local_lab.py up`
after installing the `postgres` extra. It binds to `127.0.0.1:55432`, creates
synthetic records, and verifies TLS using a generated local CA. Bootstrap
credentials and certificates stay under ignored `.local/`. Use
`uv run python scripts/local_lab.py down` to stop it and retain its data volume.
This helper runs PostgreSQL only; Vault remains the existing HCP instance.
HCP Vault needs an approved network route to PostgreSQL before its database
secrets engine can issue credentials. Set `DATABASE_SSLROOTCERT` to
the trusted CA file when configuring the runtime database connection.

For a Supabase shared session pooler, set
`DATABASE_USERNAME_SUFFIX` to `.PROJECT_REF`: Vault's generated
PostgreSQL role name stays unchanged, while the connection username includes
the pooler's routing suffix. Set `DATABASE_SSLROOTCERT` to the
CA certificate downloaded from the database settings. Administrative database
URIs belong only in local provisioning configuration; the agent uses leased
credentials.

To provision and validate PostgreSQL using an existing Vault, install the
`postgres` extra, provide a local `SUPABASE_DB_URI` and trusted CA path, and run
`uv run --extra postgres python scripts/provision_database.py`.
The helper creates its marked synthetic table with row-level security, a
Vault database connection and a SELECT-only two-minute credential role.
It verifies read access, write denial, restricted Vault paths and revocation
through a five-minute scoped test token, then revokes that token. Private
evidence and suggested runtime settings are saved under `.local/`.
It never rotates the supplied administrative password.

The `database-reader` profile exposes only the database capability. Its
authenticated principal needs `database:read`; the runtime broker still
requires a signed delegated user/actor token and exact RAR. Successful
operator-token provisioning does not satisfy this delegated identity gate.
Direct OAuth JWT acceptance requires the appropriate Vault Enterprise
version and license; configure issuer trust and agent registration before
using this profile end to end.


## Repeatable validation and private evidence

The base installation includes a fixed validation catalog and nine deterministic offline
scenarios. They exercise delegated reads, forbidden tool/policy attempts, invalid approvals,
replay, action mutation, failed cleanup and cancellation through the trusted runtime/adapters.
They use no customer credentials, ambient exporter or network. No additional dependency is needed.

~~~sh
uv run agent validate list
uv run agent validate run
uv run agent validate run --scenario policy-denial --scenario approval-replay
~~~

Each run creates a unique owner-only directory beneath the current project's ignored
`.local/validation/`. JSON stdout and JSON/Markdown reports contain registered labels, enums,
opaque IDs, counts and digests. Native identifiers, source copies and reviewer text remain private.
Output overrides must stay beneath `.local/` and be Git-ignored in a worktree. Imports reject
symlinks, invalid UTF-8, duplicate JSON keys, archives and excessive nesting. Limits are 32
selected scenarios, 100 artifacts, 10 MiB/artifact, 64 KiB/event, 10,000 events and 100 MiB/run.
Scenario/suite/cleanup budgets default to 30/300/30 seconds offline and 150/300/30 live;
maximums are 180/1800/30. Failed or uncertain effects are never automatically retried.

For genuine database validation, install the existing PostgreSQL extra and supply fresh
verified human credentials and scoped OAuth/Vault/database configuration privately. The fixed
live factories deterministically request the selected tool; they use real adapters and do not
substitute simulated services or administrative credentials. Phone validation requires a
separate explicit scenario and a witnessed decision:

~~~sh
uv run agent validate run --suite live-database --mode live
uv run agent validate run --suite live-phone --scenario phone-approved --mode live --interactive
uv run agent validate run --suite live-phone --scenario phone-denied --mode live --interactive
~~~

`LOGFIRE_TOKEN` enables the optional filtered OTLP pipeline. Install the existing `logfire`
extra; key-only region discovery uses the public Logfire API. `LOGFIRE_BASE_URL` is
an optional trusted HTTPS override with no userinfo, query or fragment. Set
`LOGFIRE_PROJECT` to the exact private project alias used by your exports to bind
receipt checks. A base URL alone does not enable export. Providers are injected without global
Logfire configuration; existing hosts should retain the returned `configure_telemetry` object
and pass it to `Runtime(telemetry=...)`. Native parent/child spans and trusted lifecycle metadata
are filtered before SDK storage. Flush is bounded to five seconds. Acknowledgment proves export
health; imported matching project/trace/run/span rows prove receipt separately.

Use explicit bounded Vault JSONL, Verify Events envelopes and Logfire rows, with private source
manifests. Imported metadata is operator provenance and needs reviewer inspection. Exact native
identifiers establish matches; timestamps alone cannot. Unsupported Verify Events transaction
linkage and incompatible Vault lease HMAC contexts remain blocked. A verified phone transaction
is labeled transaction response evidence, separately from Events audit evidence.

~~~sh
uv run agent validate import --run RUN_UUID --source vault --input .local/input/vault.jsonl --manifest .local/input/vault-manifest.json
uv run agent validate report --run RUN_UUID
uv run agent validate review --run RUN_UUID --criterion UC1-05 --decision pass --review-file .local/input/review.json
~~~

Use the criterion's current `evidence_revision` from the report as `expected_revision` in the
private review file, with reviewer, rationale, UTC observation time and opaque artifact references.
Rebuilds recheck bytes and invalidate stale decisions. Previous reports/reviews stay immutable;
unfinished runs recover terminal interrupted projections without replaying effects. All fifteen
customer criteria remain visible. Only supported, unchanged, live evidence and explicit review
can produce pass/alternative; broader unsupported UC3/VIP/workload claims remain blocked.
No command updates tracked acceptance snapshots or publishes artifacts.

Exit codes are 130 for interruption, 1 for observed failure/integrity contradiction, 2 for invalid
or blocked required work, and 0 for successful selected work. `run` evaluates operational and
configured export checks; `report` additionally evaluates suite source/receipt requirements.
Wider customer acceptance is separate. See the [feature quickstart](../specs/002-security-validation/quickstart.md)
and [native import contracts](../specs/002-security-validation/contracts/runtime.md).

## Local readiness and closeout

Readiness checks selected live-case configuration without network calls, token verification,
phone prompts or persisted evidence:

~~~sh
uv run agent validate ready --suite live-database
uv run agent validate ready --suite live-phone --scenario phone-approved
~~~

Execution and evidence readiness are separate. `configured` means local configuration is
present and structurally valid; external identity, permissions, reachability and manual export
access remain `unverified`. Readiness never proves that credentials are fresh. A real run
rechecks local prerequisites and verifies ingress. Phone selection must name exactly one case.
Readiness has a two-second budget and returns 2 for missing/invalid required configuration.

Import format version 1 remains readable. Version 2 supports Vault's nested
`response.secret.lease_id` and Logfire arrays, `rows`, or `schema.fields` with `data` row objects.
Conflicting aliases are rejected. Native project names must match the private manifest's
`source_instance`; an internal `project_id` requires an explicit `native_project_id` in a
Logfire v2 manifest. Positional data arrays and guessed project mappings are unsupported.
No additional environment variables or read tokens are required; export access stays manual.

Create a private immutable closeout from one to four explicit live runs, then inspect it:

~~~sh
uv run agent validate closeout --run DATABASE_RUN_UUID --run APPROVED_RUN_UUID --run DENIED_RUN_UUID
uv run agent validate closeout --closeout SNAPSHOT_UUID
~~~

Closeout contains four fixed case slots, operational and evidence outcomes, and all fifteen
criteria with each member run's existing review disposition. Missing or duplicate slots block
closure. It adds no reviews or aggregate customer acceptance. Only native `DENIED`, `VERIFY_DENIED` or `USER_DENIED` proves intentional phone denial; timeout, expiry, cancellation and failure do not.
Source IDs, deployment selectors and raw exports remain private. JSON stdout and Markdown
contain opaque references and safe conclusions. Snapshots have a 30-second wall budget and use
the existing 130/1/2/0 exit precedence; blocked wider customer claims do not change successful
operational/evidence closure into failure.

Live runs now seal a credential-free deployment context before effects. Different targets,
profiles or trust configuration block combined evidence; credential rotation does not change
context. Legacy runs remain reportable, but missing context or trusted approval bindings cannot
be recreated from current settings. Changed source, code or reviews make an old snapshot stale;
create a new snapshot explicitly. Inspection never retries effects or deletes evidence.

See the [003 walkthrough](../specs/003-live-evidence-closure/quickstart.md) for the separate
real database, witnessed phone, source-review and delivery gates.


## Browser workspace

1. Install the integrations you use:
   **uv sync --locked --extra server --extra google --extra postgres --group dev**.
2. In .env.local, retain your issuer/discovery, OAUTH_AUDIENCE, actor and model settings.
   Set LOGIN_CLIENT_ID and LOGIN_CLIENT_SECRET to a separate confidential OIDC
   application. Set LOGIN_SCOPES to openid plus granted task scopes; add
   offline_access if the provider supports refresh tokens.
3. Run **uv run agent workspace** (or **--port 8002** if the port is occupied).
   Register the **exact** printed callback, for example
   http://127.0.0.1:8000/auth/callback, in that login application.
4. Open the printed local URL and select **Sign in**. For the database example,
   choose **database-reader**, enter **Read database record 1**, and select **Run**.
5. Inspect the status, result and credential cleanup. Keep the job/request/run IDs
   when correlating private adapter evidence; they contain no identity claims.

The workspace binds only to 127.0.0.1, uses one worker and disables access logging.
Host, Origin and CSRF checks protect mutations. It is intended for local use.
Tokens stay in process memory behind an HttpOnly cookie. Browser storage holds no
credentials or history; untrusted output is displayed as text.

Up to four signed-in sessions are allowed. Sessions expire after 30 minutes without
a successful user mutation, or eight hours absolutely. Polling does not extend expiry.
Each retains at most twenty jobs and twenty submission keys, including retry aliases.
Restart or sign-out clears history after active work drains. Sign-out immediately
blocks new work and contains the active run while cleanup completes.

Access tokens must have at least TIMEOUT_SECONDS + 45 seconds remaining at admission.
The workspace attempts renewal once if a refresh token exists; it never changes a token
mid-run. Configure TIMEOUT_SECONDS from 1 to 180. Cleanup has 30 seconds and five more
seconds to drain cancellation. Unresolved cleanup quarantines the workspace and blocks
further work; inspect the private lease before restarting.

Phone approval is a simulated infrastructure effect. Only an explicit native denial is
shown as denied. Failure, timeout or missing decisions are **unconfirmed**. An eligible
**Retry approval** sends one fresh prompt for the same frozen action, without another
model call or replay of earlier tools. Successful, denied, interrupted and uncertain
cleanup attempts have no retry. There are no browser Approve or Deny controls.

If submission delivery fails, **Check submission** reuses the same UUID and body.
Reload retrieves retained results. It does not submit another task.

| Symptom | What to do |
| --- | --- |
| Missing startup settings | Set the printed setting names in .env.local; install the printed extra command. |
| Port unavailable | Choose --port 8002, register the newly printed callback, then open that URL. |
| Sign-in cannot be verified | Check issuer, login application callback, resource audience and granted scopes; start a fresh Sign in. |
| Token lifetime too short | Increase provider access-token lifetime or reduce TIMEOUT_SECONDS, then sign in again. |
| Permission denied | Grant the required resource scope to this identity and choose the correct profile. |
| Database unavailable | Check actor exchange, Vault read role, PostgreSQL TLS and database:read scope. |
| Approval unconfirmed | Inspect the displayed cleanup and use Retry approval only when offered. |
| Cleanup failed or unknown | Inspect and revoke the exact lease in private adapter evidence before restarting. |
| Session capacity reached | Finish active work, sign out of an existing session, then sign in again. |

Browser development checks use synthetic signed identity and Vault responses:

~~~sh
uv sync --locked --extra server --group dev --group browser
uv run --group browser playwright install webkit
uv run --group browser pytest tests/browser -q
~~~

They establish software behavior; live vendor observations remain separate.

## Connection observations and guided repair

Use **Check connection** in the workspace, including while signed out. It checks local
configuration, public identity discovery, Vault seal status, and a database TCP connection.
It sends no user/operator credentials and performs no SQL, credential acquisition, or
provider mutation. A successful TCP connection proves transport reachability only; Vault
being unsealed proves neither issuance permission nor Vault-to-database connectivity.
Checks have a ten-second per-check and thirty-second total deadline. Only one request
can run or drain at a time. Observations become stale after sixty seconds; reload does
not rerun provider checks. **Check recovery** rereads local durable state separately.

For a Supabase connection failure, a project administrator should open
[Database Settings](https://supabase.com/dashboard/project/_/database/settings), select
and verify the project, and inspect **Network bans**. If the relevant client address is
listed, use **Unban IP** for that address. Expect the entry to disappear, then rerun
Check connection. This destination is linked by the
[official troubleshooting guide](https://supabase.com/docs/guides/troubleshooting/error-connection-refused-when-trying-to-connect-to-supabase-database-hwG0Dr).
A timeout alone does not establish a ban or its cause.

For other providers, ask the integration administrator to verify the configured target,
port, TLS trust, and provider status. Missing access is a reason to contact that operator,
not to guess a dashboard menu. A permission failure from an actual credential call is
reported separately from reachability. Sign in when new work needs user authentication;
repeated sign-in cannot resolve uncertain credential issuance or cleanup.

Connection checks preserve a valid session and never replay a task. Repairing connectivity
alone does not clear durable recovery incidents. Do not delete recovery state, retry an
acquisition automatically, or test intentionally invalid database passwords.

## Durable recovery

With complete live database settings, enroll future attempts once before using the database:

```sh
uv run agent recover init
uv run agent recover status
```

These commands do not sign in or contact providers. Enrollment starts prospective
tracking in owner-only `.local/recovery/`. It does not resolve the historical unknown
attempts from 004 or the native evidence gaps from 003. Missing enrollment blocks live
database use. Partial, damaged, moved, or mismatched state blocks use; restore the
original private files/configuration with the integration administrator. There is no
reset command. Do not delete state or initialize again to bypass an incident.

An active workspace owns its lifetime lock; an idle operator can reconcile an incident
without restarting it. Acquisition and cleanup share an effect lock with CLI/API reads.
Intent is committed before issuance, the exact handle before SQL, and a terminal receipt
before cleanup is reported complete. Lost responses remain blocked, including 401/403
without native non-issuance proof. Offline demo/validation remain independent.

For a reported known-handle incident, an authorized operator supplies existing
`VAULT_TOKEN` privately through the process environment or local configuration, then runs:

```sh
uv run agent recover revoke --incident INCIDENT_UUID
```

This sends exactly one synchronous revoke to the configured Vault instance and namespace.
It cannot issue credentials, read SQL, revoke a prefix, force revocation, or retry
implicitly. Missing authority: obtain a token permitted to update `sys/leases/revoke`
for the exact incident handle from the Vault administrator; do not paste it into the
browser. Denied/timeout/queued responses leave the incident blocked. A completed command
is a verified no-op when repeated. Production cleanup runs in a terminable private worker;
the effect lock remains held through worker termination and receipt persistence.

For unknown issuance, ask the Vault integration administrator for the native acquisition
request/response pair with the incident operation's **X-Correlation-Id**, request ID,
credential path, namespace, explicit policy decision, and un-HMACed lease ID. Do not
repeat acquisition to obtain evidence. If these fields/export access are unavailable,
recovery stays blocked: the administrator must provide supported native linkage.
A generic error, empty lease field, healthy database, or operator acknowledgment is
insufficient. Only an explicit pre-execution ACL denial proves non-issuance.

Keep exports in a 0700 folder beneath ignored `.local/`, with 0600 regular files.
The supported private JSON envelope has exactly `schema_version: 1`,
`environment_digest` (the journal's current private fingerprint), `source_instance`
(the configured Vault address), and `records` (original native audit objects). JSONL
uses the same three-field header first, followed by native records. This provenance is
operator-attested, not a provider signature. Review the actual source instance and
export integrity before using a non-sensitive reviewer label. Never publish this wrapper.
The verifier follows [Vault's native pair IDs](https://developer.hashicorp.com/vault/docs/audit/schema).

```sh
uv run agent recover import --incident INCIDENT_UUID --source .local/input/acquisition.json --reviewer operator
# Include a second --source only for the matching completed sync-cleanup pair.
```

Limits: two files, 2 MiB each, 200 native records total, depth 16. Duplicate keys,
ambiguous pairs, foreign provenance, HMAC-protected linking fields, conflicts, and stale
receipt revisions are rejected. Raw exports stay outside the journal. A lease-identification
receipt binds the handle but remains blocked until exact cleanup. Completed synchronous
cleanup or supported non-issuance evidence resolves it; imports never promote acceptance.
Use **Check recovery** afterward. It observes durable closure without renewing credentials,
changing old results, or replaying work. A valid session can submit a new task explicitly;
an expired/signed-out session must sign in normally.

Before live cleanup, the integration administrator must update the installed RAR schema
and every applicable cleanup ACL, including the agent-registry ceiling policy, to permit
**boolean** `sync=true`. Updating only the database role policy can still leave delegated
cleanup denied by an unchanged ceiling policy. The cleanup authorization details
must have `required_parameters: ["lease_id", "sync"]` and
`allowed_parameters: {"lease_id": ["exact handle"], "sync": [true]}` at
`sys/leases/revoke` with `capabilities: ["update"]`. Numeric `1`, string `"true"`, false,
omitted sync, extra rights, or widened handle lists are rejected. Review
`config/vault-path-access.schema.json` and `scripts/provision_database.py`; implementation
and CI do not apply these provider changes. Existing policies that reject sync fail closed.

## Incident containment

Live execution requires explicit local enrollment. Stop the workspace first. For a new
live database installation run `uv run agent recover init`; for an existing schema-1
installation run `uv run agent recover migrate`. Migration preserves old attempts and
labels their ownership unknown; unresolved attempts still need operator repair.

Run `uv run agent respond init --prepare`, review `.local/response/policy.json`, then run
`uv run agent respond init`. The default local-only policy needs no relay or new environment
variables. Restart the workspace and inspect `uv run agent respond status` for root IDs.

In a separate terminal, start `uv run agent respond serve --port 8002`. To stop a particular
root, run:

```sh
uv run agent respond submit --event-id operator-001 --occurred-at CURRENT_UTC --reason suspected_compromise --run ROOT_UUID
uv run agent respond status --incident INCIDENT_UUID
uv run agent respond reconcile --incident INCIDENT_UUID
```

Replace placeholders with the current UTC timestamp and IDs returned by private status.
Use `--definition DEFINITION_KEY` instead of `--run` to hold the configured stable definition.
Retain the exact event ID and payload when delivery is uncertain: identical delivery is
idempotent; changed content under that ID is rejected. Status and reconciliation never
call providers. The responder attempts only previously unsubmitted attributable cleanup.

Local work stops independently of cleanup. Denied, unknown or uncertain cleanup remains
blocked. Follow the exact `agent recover` instructions in private response status, then
reconcile the response incident. Do not delete journals or retry ambiguous provider work.
To release a settled definition hold, inspect the current revision and supply **every**
current incident:

```sh
uv run agent respond release --definition DEFINITION_KEY --incident INCIDENT_UUID --revision CURRENT_REVISION --operator local-operator
```

Use the configured definition key from private status. Repeat `--incident` for overlapping holds. Release permits fresh roots; it never resumes
old roots or approvals. Exact lease cleanup does not prove that native downstream sessions
or existing external JWTs have stopped. Native risk collection, user suspension, rotation
and notification remain follow-on work.

## Provider remediation

Provider controls are optional exact-resource actions after local containment. Setup is
local and read-only until enrolled events request configured mutations. Use dedicated test
resources and the [configuration reference](configuration.md#provider-remediation-enrollment).

Stop the workspace and response service, preserve private state, and run:

```sh
uv run agent respond migrate
uv run agent respond providers prepare
uv run agent respond providers readiness
uv run agent respond providers status
uv run agent respond providers enroll --revision N
```

Replace `N` with the current journal revision from status. Edit the generated private draft
and secret map before readiness; each finding names the responsible operator and repair.
Migration changes only the response snapshot from schema 1 to 2, preserving legacy holds,
source policy, anchor and recovery records. It is idempotent and sends no provider requests.
Older binaries reject schema 2. Never delete private state to bypass a hold.

Start `agent respond serve` after enrollment. The relay posts bounded JSON to
`POST /response/native/ALIAS`, authenticated with its separate enrolled response audience,
exact subject, access-token purpose and `response:submit` scope. A successful response is
only `{schema_version, incident_id, disposition}` after durable hold/plan commit. Replays
return the existing incident; changed selected security content conflicts. Source events
must be no more than 300 seconds old or 30 seconds in the future.

Read a safe report without contacting providers:

```sh
uv run agent respond providers status --incident INCIDENT_UUID
uv run agent respond providers reconcile --incident INCIDENT_UUID --revision N
```

Status makes no network calls. Reconcile reads exact metadata without reading credentials,
sending notices or replaying mutations. Acknowledgment, readback and credential-loss proof
remain separate. Each effect has durable submitted intent, a ten-second network deadline
and a 120-second worker budget including drain. Restart changes unfinished submission to
uncertain. A lost reply never causes automatic replay.

Explicit recovery preserves predecessor history:

```sh
uv run agent respond providers retry --action ACTION_UUID --revision N --operator REVIEWER
uv run agent respond providers import --incident INCIDENT_UUID --file PRIVATE_OBSERVATION.json --revision N --operator REVIEWER
```

Retry first reads current metadata where safe. If the change is already present it reconciles
that attempt. Otherwise it creates a linked planned action after checking current holds and
review, then runs the normal bounded worker once. Session retry requires fresh independent review
because newer sessions could be affected. Uncertain static rotation cannot be retried from
current metadata. Teams resend creates a new notice UUID/revision; 2xx means accepted,
while delivery needs an imported correlated workflow/message receipt.

Import files must be owner-only, regular, singly linked and at most 1 MiB. Use the strict
`Observation` fields in the configuration model: exact installation/environment/implementation/
enrollment digests, incident/action/binding UUIDs, generation, path, closed result/provenance,
source digest and UTC observation time. Native intake evidence additionally pins the event
digest and exact intake timestamp; delivery evidence pins notice UUID/revision. Independent
review never turns synthetic execution into native evidence. Imported source material stays
private; reports contain closed outcomes and opaque correlations.
A configured native JWT login role remains a separate unverified fresh path: OAuth exchange
denial and existing-accessor revocation cannot certify it. Definition closeout reports this
limitation explicitly instead of claiming complete provider containment.

For an authorized pre-event proof, place only the relevant credentials and peer root/binding
UUIDs into an owner-only JSON file matching `ProofInput`, then pipe it through stdin:

```sh
uv run agent respond providers probe --root ROOT_UUID --revision N --scenario same_jwt --operator REVIEWER < PRIVATE_INPUT.json
```

Do not put credentials in flags, command substitutions, chat or committed fixtures. Supported
scenarios are `same_jwt`, `fresh_issuance`, `native_token`, `user_sessions`, `dynamic_database`,
`static_database`, and `notification_delivery`. Identity probes use captured tokens and a
separately enrolled healthy peer. Database probes keep independent before-event connections
open and distinguish native password rejection from native session termination. Wait for
`probe_ready`, then generate the authorized enrolled event in a separate session. The probe
releases effect ownership while waiting and reacquires it for privileged requests. Tokens,
passwords, connections and native session IDs stay inside the trusted bounded process.

`--incident INCIDENT_UUID` instead of `--root` reports missing baseline as inconclusive;
it cannot invent before-event success. Notification delivery is receipt import only and
never resends from a proof. Unexpected credential issuance creates durable acquisition
intent and joins exact recovery before use; uncertain issuance stays pinned. Known issued
JWTs remain pinned until their verified finite lifetime plus 30 seconds has elapsed. Token
expiry establishes lifetime safety only, never an enforcement result.

Exit codes: `0` completed/readable, `2` invalid provider input, `3` blocked setup/authority,
and `4` partial or missing proof. Readiness inspects an inactive draft; enrollment is the
explicit authority activation. Reports provide individual Function 10 outcomes and bounded
clock intervals. Missing clock bounds, provider outages or network bans yield unavailable
or inconclusive timing/denial claims. The workspace displays session-owned closed control
and database outcomes; sign-out, expiry or subject suspension clears those displays.

Restore provider resources manually through their responsible operator after reviewing the
report. Local release requires all current holds/revisions, drained owners, confirmed exact
cleanup, complete required provider proof, and reviewed old-credential safety. The same
actor can be restored only after minting stopped and the complete maximum old-token lifetime
plus 30 seconds elapsed. Old roots stay terminal; a successful release permits fresh roots.
Actor/client configuration migration is outside this workflow.

## Shadow agent governance

`agent govern` provides an operator workflow for Function 11. It observes an unknown
workload, reviews one exact registration, proves short-lived SPIFFE identity through a
separate relying process, and compares harmless permission reads. Findings never grant
permission to enroll or execute tasks. The browser only displays cases belonging to the
verified signed-in principal; privileged operations remain operator CLI commands.

Install `server` for the two listeners. Existing OAuth/Vault settings select the deployment;
there are no new environment variables. Stop the browser workspace before privileged
commands, because it owns the recovery workspace lock. Keep response intake running.
A hold remains authoritative and must be resolved through the existing response workflow.
Do not remove locks or private journals to bypass `workspace_busy` or `contained`.

Start locally, without calling a provider:

```sh
uv run agent govern prepare
uv run agent govern status
```

Edit `.local/governance/config.draft.json` and `secrets.json`, then run `configure` with
status's current revision and your safe operator label. Prepare a case with
`case prepare --source ALIAS` and fill its generated `candidate-UUID.draft.json`.
The [configuration reference](configuration.md#governance-private-inputs) explains the
reviewed source, actor, policy, trust and entitlement inputs. `prepare` refuses an existing
installation; it never resets previous authority or uncertain issuance.

The controlled sequence is:

```text
agent govern configure --revision N --operator LABEL
agent govern case prepare --source ALIAS
agent govern readiness --candidate UUID
agent govern serve --port 8002
agent govern observe --candidate UUID --revision N
agent govern import --input PRIVATE_FILE --candidate UUID --revision N --operator LABEL
agent govern review --candidate UUID --revision N --operator LABEL
agent govern enroll --review REVIEW_UUID --revision N
agent govern relying serve
agent govern prove --candidate UUID --revision N --scenario identity
agent govern prove --candidate UUID --revision N --scenario permissions
agent govern prove --candidate UUID --revision N --scenario negatives
agent govern closeout --candidate UUID
```

Prefix each line with `uv run`. Run each listener in its own process. Always obtain `N`
from fresh status or the previous command's returned revision. Inspect the owner-only
`review-REVIEW_UUID.json` before applying that review. Readiness returns closed
per-prerequisite checks (enterprise, entity, alias, OAuth profile, license, SPIFFE, policies,
KV mounts, registry and operator capability); it creates no provider resources or tokens.

`observe` captures the actual registration absence, one dedicated KV read and a distinct
healthy actor's control. Its result describes activity, not successful discovery. The real
collector must deliver authenticated unknown-workload and notification receipts before
registration. Intake is observation-only at
`http://127.0.0.1:8002/governance/native/ALIAS`; use the separately enrolled relay audience
and `governance:observe` scope. Public hosting and generic vendor schemas are unsupported.
An identical event is acknowledged once; changed content under its original ID conflicts.

Permission proofs read only the five reviewed KV-v2 fixture paths. Supply the human token
through non-TTY stdin as a bounded JSON object with `schema_version: 1` and `human_token`.
Use an owner-only file redirected into the command; never put a credential in a flag,
terminal transcript or shell command. The human signature/identity is checked independently
of the actor, and the excessive OBO request needs a successful human baseline and healthy
control before a denial can be attributed to the ceiling.

The independent relying process exposes only `.local/governance/relying.sock` (mode 0600).
It reads current pinned public trust itself, consumes a short-lived one-use challenge,
verifies signed entity/issuer/SPIFFE subject/audience/lifetime, and rechecks containment.
A mint acknowledgment alone cannot pass. Local tamper tests are labeled synthetic;
actual unauthenticated mint denial needs a successful authenticated issuer/relying control.
Neither the local nonce nor sign-out globally revokes a JWT.

Status exposes generated aliases, local IDs/revisions, safe receipt kinds and retained
attempt IDs. Review an adapter's already captured receipt by creating an owner-only import
file containing `schema_version: 1` and `captured_evidence_id: UUID`, then running `import`.
For an external receipt, use the full bounded envelope described in the configuration
reference. The import records who reviewed it; it does not authenticate arbitrary text.
Native discovery/notification/triage additionally require the exact authenticated intake
observation, source-object mapping, times and source digest. Never edit `state.json`.

On a lost response, use `reconcile --candidate UUID --revision N`; this only reads exact
registry metadata. Matching presence does not prove that this process created it, and
absence does not prove an old request cannot finish. Import independently attributed
provider completion/non-issuance evidence, then explicitly run
`resolve --attempt UUID --revision N --operator LABEL`. Resolution never retries a POST.
Abandoned submitted work is retained as uncertain on the next quiescent metadata operation;
refresh status after that revision changes. Unknown issuance stays pinned until resolved,
or until an independently reviewed server-completion/lifetime bound actually passes.

`close --candidate UUID --revision N --operator LABEL` archives locally only after effects
have drained and every credential is expired or resolved. It does not delete registration
or restore/revoke provider permissions. Complete linked evidence is retained for at least
30 days; unresolved work is never pruned. Old closed source generations retain their
original snapshots when a new generation activates.

Closeout reports F11-T1 through T7 independently. Missing native prerequisites remain
blocked; outage or a failed baseline cannot pass as policy enforcement. Demo-tier audit
unavailability affects the audit result, not unrelated proof paths. Nothing automatically
updates `specs/008-shadow-agent-governance/acceptance.json`. See the
[controlled validation guide](../specs/008-shadow-agent-governance/quickstart.md) and
[validation record](../specs/008-shadow-agent-governance/validation.md) for prerequisites.

CLI exits are 0 for completed/readable commands, 2 for invalid input, 3 for missing setup,
stale review, holds or busy ownership, and 4 for failed/inconclusive/uncertain effects.
Every closed error includes a concrete setup, review or recheck action.
