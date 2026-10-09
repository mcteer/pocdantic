# Pocdantic

A reusable, identity-aware Pydantic AI agent harness by **mcteer**. It starts with
`pydantic-ai-slim` and adds model providers, Logfire, HTTP serving, and PostgreSQL
only through optional extras.

The parent delegates ticket reads to a restricted child. Trusted application code
verifies identity, authorizes every effect, binds privileged approval to an exact
action, and keeps credentials outside model context. The initial infrastructure
write is a **simulated sandbox restart**.

## Project status

This is a pre-1.0 PoC harness. Deployment-specific delegated user/actor identity and
workload trust require configuration and reviewed live verification. An adapter or unit
test pass does not establish end-to-end product acceptance.

## Quick start

See [CONTRIBUTING.md](CONTRIBUTING.md) for PR expectations and all development gates.

Python 3.12+ and [uv](https://docs.astral.sh/uv/) are required.

```sh
uv sync --locked --group dev
scripts/install-hooks.sh
uv run pocdantic demo
uv run pytest -q
uv run ruff check .
uv run python scripts/check_gates.py --runtime-only
```

The demo uses a deterministic model, synthetic identity, and synthetic ticket data;
it makes no network calls. Results contain separate request, parent-run and child-run
identifiers. A software test pass does not establish external vendor enforcement.

Install only the integrations needed for your PoC:

```sh
uv sync --locked --extra google --extra logfire --extra server --extra postgres --group dev
```

Other provider extras are `openai` and `anthropic`. Base installation does not install
any model provider SDK, Logfire SDK, FastAPI, or PostgreSQL driver.

## Configuration

Copy `.env.example` to `.env.local` and fill in local values. Environment variables
override the file. Keep the file private. Run `uv run pocdantic probe` for a status-only,
read-only connectivity report. It neither creates resources nor issues database leases.

| Setting | Purpose |
| --- | --- |
| `POCDANTIC_MODEL` | Pydantic AI model ID, such as `google-gla:gemini-3.8-flash` |
| `GOOGLE_API_KEY` / provider environment | Model credentials |
| `LOGFIRE_TOKEN` | Logfire project **write** API key; supplying this enables export |
| `POCDANTIC_OAUTH_PROVIDER` | `verify` or `generic` |
| `VERIFY_TENANT_URL` | Verify tenant; hostname or HTTPS URL |
| `POCDANTIC_OAUTH_DISCOVERY_URL` | Generic OIDC discovery URL, or explicit Verify override |
| `POCDANTIC_OAUTH_ISSUER` | Optional exact pinned issuer; otherwise trusted discovery supplies it |
| `POCDANTIC_OAUTH_TOKEN_ENDPOINT` | Optional token endpoint override |
| `POCDANTIC_OAUTH_CLIENT_ID`, `POCDANTIC_OAUTH_CLIENT_SECRET` | Agent OAuth client |
| `POCDANTIC_OAUTH_AUTH_METHOD` | `client_secret_post` or `client_secret_basic` |
| `POCDANTIC_OAUTH_AUDIENCE` | Dedicated API access-token audience; required for authenticated ingress |
| `POCDANTIC_OAUTH_ACCESS_TOKEN_TYP` | Required JWT header type, default `at+jwt` |
| `POCDANTIC_BEARER_TOKEN` | User access token for CLI runs; keep it in private environment |
| `POCDANTIC_VERIFY_API_CLIENT_ID`, `POCDANTIC_VERIFY_API_CLIENT_SECRET` | Separate Verify API client for push/inventory |
| `POCDANTIC_VERIFY_PUSH_ENABLED` | Explicitly enable live push in the simulated write capability |
| `POCDANTIC_VERIFY_USER_ID`, `POCDANTIC_VERIFY_AUTHENTICATOR_ID` | Trusted mapping of verified subject to enrolled phone |
| `POCDANTIC_TIMEOUT_SECONDS` | Entire parent/child deadline, default 45; use 150 for interactive push |
| `POCDANTIC_WORKLOAD_DEFINITION` | Stable runtime definition ID; never an invocation ID |
| `VAULT_ADDR`, `VAULT_NAMESPACE` | Vault deployment |
| `VAULT_TOKEN` | Operator token for read-only readiness probe; never model execution credentials |
| `POCDANTIC_VAULT_AUDIENCE`, `POCDANTIC_ACTOR_AUDIENCE` | Delegated Vault and actor JWT audiences |
| `POCDANTIC_VAULT_READ_PATH` | Exact dynamic read-role path, default `database/creds/poc-readonly` |
| `POCDANTIC_DATABASE_HOST`, `POCDANTIC_DATABASE_NAME`, `POCDANTIC_DATABASE_PORT` | PostgreSQL target with trusted TLS |
| `POCDANTIC_DATABASE_SSLROOTCERT` | Trusted PostgreSQL CA file |
| `POCDANTIC_DATABASE_USERNAME_SUFFIX` | Optional pooler routing suffix |
| `POCDANTIC_PROFILES_FILE` | Agent profile JSON; defaults bundled with the wheel |

Existing local variable names are supported: `VERIFY_AGENT_CLIENT_ID/SECRET` are
fallbacks for the agent OAuth client; `VERIFY_CLIENT_ID/SECRET` are fallbacks for
the administrative API client. Explicit `POCDANTIC_*` settings take precedence.
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
uv run pocdantic run --task 'Summarize POC-1' --profile parent
uv run pocdantic batch --input requests.jsonl
uv run pocdantic serve
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

## Compose alternate agents

Edit `config/agents.json` or supply `POCDANTIC_PROFILES_FILE`. Each definition selects
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
uv run pocdantic push-demo
```

This isolated test selects exactly one active phone and its validated user-presence
signing factor (or the configured device/user), sends one push, polls the exact
transaction, verifies its action digest, and consumes the approval once. Only a
simulated write occurs. It does not create a production user session or Vault lease.
Evidence stays in ignored `.local/` files. Multiple enrolled phones require explicit
selection through configuration.

For model-requested live push, configure the subject/device mapping, enable
`POCDANTIC_VERIFY_PUSH_ENABLED=true`, and set the run timeout to 150 seconds.
The verified access-token subject must match the configured Verify user. A pending,
denied, expired, changed or replayed approval cannot execute the simulated action.
Without a backend, the tool returns `approval_required` and performs no write.

## Vault and database boundary

`database-read` uses `DatabaseBroker`: agent client credentials → subject/actor
exchange with exact `vault:path_access` RAR → delegated JWT claim validation →
Vault dynamic lease → fixed parameterized SELECT → connection close → explicit
lease revoke. No operator token is substituted if delegation fails. Malformed
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
secrets engine can issue credentials. Set `POCDANTIC_DATABASE_SSLROOTCERT` to
the trusted CA file when configuring the runtime database connection.

For a Supabase shared session pooler, set
`POCDANTIC_DATABASE_USERNAME_SUFFIX` to `.PROJECT_REF`: Vault's generated
PostgreSQL role name stays unchanged, while the connection username includes
the pooler's routing suffix. Set `POCDANTIC_DATABASE_SSLROOTCERT` to the
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

## Validation, publication and contribution

Harness source, supporting files, sanitized specifications and architecture decisions
belong in Git. The versioned Spec Kit constitution, templates, scripts and secure-poc
workflow support requirements → clarification → plan/contracts → checklist → tasks →
analysis → implementation → validation. See [ADRs](docs/adr/README.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).

Constitution 1.2.0 defines the development rules. CI runs both
the all-feature specification gate and runtime configuration gate. Locally, run:

~~~sh
uv run python scripts/check_gates.py --all-features
uv run python scripts/check_gates.py --runtime-only
~~~

Customer design sources, .env.local, .local/, raw evidence, generated integration files
and machine-local Spec Kit state stay excluded. Versioned acceptance status and validation
summaries contain no customer identities or source-system secrets. Hooks and CI enforce
the publication allowlist; distribution contents are checked independently.

Local hooks can be bypassed, so configure GitHub branch protection to require the
`validate` check and maintainer review before merging. CI and the readiness
probe do not provision resources. The database setup helper changes configured PoC
targets when explicitly invoked.

References: [Pydantic AI capabilities](https://pydantic.dev/docs/ai/capabilities/overview/),
[Verify push API](https://docs.verify.ibm.com/verify/reference/initiateverification),
[Vault RAR](https://developer.hashicorp.com/vault/ai/iam/concepts/rar),
[GitHub Spec Kit](https://github.com/github/spec-kit).


## Licensing and security reports

No project LICENSE file has been added; an open-source license for this harness must
not be assumed. Bundled Spec Kit support assets retain their upstream MIT notice in
.specify/THIRD_PARTY_LICENSE.txt.
Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting an issue or PR, including
its private vulnerability reporting guidance.
