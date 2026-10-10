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
The harness accepts an externally acquired user access token; interactive OIDC login
and session storage belong to the hosting application and are not implemented here.

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
[config/vault-path-access.schema.json](config/vault-path-access.schema.json).
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
Wider customer acceptance is separate. See the [feature quickstart](specs/002-security-validation/quickstart.md)
and [native import contracts](specs/002-security-validation/contracts/runtime.md).
