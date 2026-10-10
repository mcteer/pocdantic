# Configuration reference

Offline demo and validation require no environment variables. For live integrations,
use only the relevant group below; unset settings use their defaults. Secrets belong
in the environment or ignored `.env.local`, never task text.

Environment variables override `.env.local`. Short names take precedence over
`POCDANTIC_*` aliases within a source. Legacy provider aliases
`VERIFY_AGENT_CLIENT_ID/SECRET` and `VERIFY_CLIENT_ID/SECRET` remain supported.
Agent OAuth credentials and administrative Verify API credentials serve different roles.

## Runtime

| Variable | Default |
| --- | --- |
| `MODEL` | `google-gla:gemini-3.8-flash` |
| `TIMEOUT_SECONDS` | `45` |
| `REQUEST_LIMIT` | `8` |
| `TOOL_CALLS_LIMIT` | `12` |
| `OUTPUT_TOKENS_LIMIT` | `6000` |
| `PROFILES_FILE` | `config/agents.json` |
| `WORKLOAD_DEFINITION` | `pocdantic-runtime` |

## Identity

| Variable | Default |
| --- | --- |
| `OAUTH_PROVIDER` | `verify` |
| `VERIFY_TENANT_URL` | Unset |
| `OAUTH_DISCOVERY_URL` | Unset |
| `OAUTH_ISSUER` | Unset |
| `OAUTH_TOKEN_ENDPOINT` | Unset |
| `OAUTH_AUDIENCE` | Unset |
| `OAUTH_ACCESS_TOKEN_TYP` | `at+jwt` |
| `OAUTH_CLIENT_ID` | Unset |
| `OAUTH_CLIENT_SECRET` | Unset |
| `OAUTH_AUTH_METHOD` | `client_secret_post` |
| `BEARER_TOKEN` | Unset |

## Browser sign-in

| Variable | Default |
| --- | --- |
| LOGIN_CLIENT_ID | Unset; required by workspace |
| LOGIN_CLIENT_SECRET | Unset; required by workspace |
| LOGIN_SCOPES | openid |

Use a separate confidential OIDC application; retain the actor's OAUTH_CLIENT_*
credentials. POCDANTIC_LOGIN_* aliases remain supported. Add only scopes the
provider grants, including offline_access for renewal where supported.
The application must issue the configured OAUTH_AUDIENCE and accept code/S256 PKCE.
No cookie, session, browser URL or refresh environment setting is needed.

## Phone approval

| Variable | Default |
| --- | --- |
| `VERIFY_API_CLIENT_ID` | Unset |
| `VERIFY_API_CLIENT_SECRET` | Unset |
| `VERIFY_PUSH_ENABLED` | `False` |
| `VERIFY_AUTHENTICATOR_ID` | Unset |
| `VERIFY_USER_ID` | Unset |

## Database and workload trust

| Variable | Default |
| --- | --- |
| `VAULT_ADDR` | Unset |
| `VAULT_NAMESPACE` | Empty |
| `VAULT_TOKEN` | Unset |
| `VAULT_READ_PATH` | `database/creds/poc-readonly` |
| `VAULT_AUDIENCE` | Unset |
| `ACTOR_AUDIENCE` | Unset |
| `DATABASE_HOST` | Unset |
| `DATABASE_NAME` | Unset |
| `DATABASE_PORT` | `5432` |
| `DATABASE_SSLROOTCERT` | Unset |
| `DATABASE_USERNAME_SUFFIX` | Empty |
| `WORKLOAD_JWT` | Unset |
| `WORKLOAD_AUTH_MOUNT` | `jwt` |
| `WORKLOAD_AUTH_ROLE` | Unset |

## Providers and telemetry

| Variable | Default |
| --- | --- |
| `GOOGLE_API_KEY` | Unset |
| `LOGFIRE_TOKEN` | Unset |
| `LOGFIRE_BASE_URL` | Unset |
| `LOGFIRE_PROJECT` | Unset |

## Integration notes

- OAuth: Verify derives discovery from its tenant; set `OAUTH_DISCOVERY_URL` for
  the newer delegated-exchange provider or a generic OIDC deployment. Issuer and
  token endpoint overrides are optional. Authenticated ingress requires its expected audience.
- Database: `VAULT_TOKEN` is for operator readiness checks, not runtime delegation.
  Database credentials come from scoped leases. Configure TLS trust and use the
  username suffix only when a pooler requires it.
- Phone: enabling push requires the verified subject to match the configured user
  and enrolled authenticator. The infrastructure action remains simulated.
- Workload: signed JWT login needs a trusted issuer and configured Vault mount/role;
  it is separate from human/actor delegation.
- Telemetry: `LOGFIRE_TOKEN` enables export. Region routing is automatic;
  `LOGFIRE_BASE_URL` is an optional trusted HTTPS override. The private
  `LOGFIRE_PROJECT` alias binds imported receipt checks.
- Providers: use their standard credential variables, such as `GOOGLE_API_KEY`,
  `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`, with the corresponding extra.

See the [runtime guide](usage.md) for commands and deployment requirements.

`agent validate ready` uses these existing settings locally; it adds no configuration variables.
Execution prerequisites vary by selected case. Evidence readiness also needs the optional
Logfire exporter and private project alias, while manual source export access remains unverified.
Do not supply a service read token to the runtime for this workflow.

Live deployment contexts record only explicit non-secret selectors and profile/CA digests.
Context and closeout files belong beneath ignored `.local/`, alongside raw exports and reviews.
Moving these generated files into a tracked path is rejected by publication checks.

## Diagnostic targets

Workspace diagnostics use existing settings only: public `OAUTH_DISCOVERY_URL` (or the
Verify discovery endpoint), unauthenticated `VAULT_ADDR` seal status, and TCP
`DATABASE_HOST:DATABASE_PORT`. No new environment variables are needed. Browser requests
cannot supply targets, native handles, evidence paths, or administrative tokens.
HTTP checks use verified TLS, bounded streamed responses, and no redirects or ambient
proxy credentials. Production network checks run in isolated, bounded worker processes.

A project administrator can inspect Supabase bans at
[Database Settings](https://supabase.com/dashboard/project/_/database/settings) after
selecting the correct project. Provider repair is manual. After repair, connection and
recovery are checked separately; a reachable endpoint does not establish cleanup proof.

## Recovery configuration

Recovery adds no environment variables. It uses existing database, Vault, OAuth, and
profile selectors to fingerprint one fixed project-local environment. Credentials are
excluded from that fingerprint; rotating secrets does not migrate the environment.
Changing/removing selectors or profile contents cannot bypass an existing incident.
Restore original selectors before reconciliation; there is no automatic environment reset.

Explicit `agent recover init` creates `.local/recovery/` with 0700 directories and 0600
files. Keep the anchor, snapshot, and three lock files together. Symlinks, hardlinks,
wrong owners, unsafe permissions, partial state, and unsupported schemas block use.
The journal is limited to 1000 attempts/100 unresolved attempts/2 MiB; resolved records
are retained for at most seven days and can be pruned to reserve receipt capacity.
Unresolved records are never evicted. One workspace owns an initialized journal; CLI/API
and an idle operator share its separate effect lock. Sessions and job history stay in
memory and are lost on restart.

`VAULT_TOKEN` also authorizes an explicitly invoked exact operator cleanup. Ordinary
runtime delegation never falls back to it. Review the synchronous RAR/ACL migration and
private evidence format in [Durable recovery](usage.md#durable-recovery).

## Response policy

`agent respond init --prepare` creates a private `.local/response/policy.json` draft.
Keep its generated definition, environment digest and issuer. Local-only enrollment uses
`intake_mode: local_only`, `sources: []`, `audience: null` and `automatic_cleanup: false`.
No response-specific environment variables are required. Policy/state changes after
initialization fail closed; never reset these files to bypass an incident.

Relay mode requires a dedicated audience distinct from human, actor and Vault audiences,
and 1–16 exact approved automation issuer/subject mappings. Each mapping has a unique
alias and allowed scopes (`root_run`, `definition`, or both). The pinned issuer must match
normal identity configuration. The maintained `config/response.example.json` is a synthetic
local-only example; register the automation identity with your provider separately.
Relay JWTs require `response:submit`, verified signature/issuer/audience and bounded
five-minute issue/expiry windows. Cookies, browser sessions and ordinary task tokens confer
no response authority. The separate API listens only on loopback; it has no remote release
endpoint or browser administration controls.

Enabling `automatic_cleanup` before enrollment opts in to exact attributable lease
revocation using the existing `VAULT_TOKEN` operator credential. Leave it false for
containment-only operation. Never put tokens in the policy. Unknown ownership/issuance or
unconfirmed responses require existing explicit recovery; the responder cannot invent
proof or automatically replay submitted actions. Preserve both private journal directories
and their anchors together. Stop all owners before migration or storage repair.

## Provider remediation enrollment

007 adds no environment variables or dependencies. Existing Vault/Verify control settings
supply administrative authority. Run `agent respond providers prepare` to create
`.local/response/providers.draft.json` and `provider-secrets.json` with owner-only permissions.
The draft is inactive until an explicit, revision-bound enrollment. Never commit these files.
[providers.example.json](../config/providers.example.json) is a synthetic structural example,
with no provider authority or native acceptance claim.

The private `Enrollment` model in `src/agent/response/providers/models.py` is the strict field
reference. It pins the installation, runtime environment, source policy and definition;
resource aliases select exact UUID bindings, HTTPS origins, namespaces, native IDs and
positive generations. Rules choose fixed actions and root/definition scope. Root rules allow
only exclusive owned native-token revocation and advisory notification; shared registration,
user and static-role changes require definition scope. Duplicate canonical resources fail
validation even if aliases, UUIDs or Teams URL signatures differ.

Store only secret alias → string values in `provider-secrets.json`. Bindings can reference
`secret_alias` (control DSN or Teams URL), `proof_secret_alias` (direct isolated-role proof DSN),
and `healthy_secret_alias` (direct distinct-role health DSN). Enrollment pins their SHA-256
values. Teams also pins the workflow host/path independently of its rotating signature.
Production database DSNs require `sslmode=verify-full`; pool endpoints, transaction-pool
ports, multi-host destinations and connection `options` are rejected. The healthy account
must resolve to a different actual server role in the same database.

For dynamic database proofs, set `dynamic_healthy_secret_alias` and supply the independently
reviewed canonical `revocation_statements` digest as `dynamic_revocation_review_digest`.
Readiness reads the configured Vault role and compares this digest; it does not install SQL
or provision accounts. Generated lease cleanup continues through existing exact recovery.
Legacy leases receive no retrospective database identity attribution.

Native `SourceProfile` entries pin the relay issuer, exact subject, distinct audience,
source alias, schema reference, equality predicates and bounded scalar JSON pointers.
Each native source requires owner-only files in `.local/response/`:

- `native-ALIAS.schema.json`: object with the matching `schema_ref`.
- `native-ALIAS.fixture.json`: minimal exported native event, matching `fixture_digest`.
- `native-ALIAS.receipt.json`: independently captured collector receipt, matching
  `collector_digest`, with reviewer attribution in the source profile.

Pointers select `event_id`, `occurred_at`, `rule`, `object`, and for root events `request_id`.
`objects` maps native object IDs to the definition. Root profiles additionally require
`object_bindings` mapping every object to an enrolled binding UUID; the host request and
verified actor/user must match that binding. A generic SaaS event or manually submitted
normalized signal cannot establish VIP-native detection. Native bodies are bounded to
64 KiB, depth eight and 128 scalars, with at most eight pointers/predicates. Credential
fields are rejected even when they are not selected.

Verify bindings require a private `verify-ALIAS.authority.json` matching `AuthorityReview`:
exact tenant/API client/user/issuer/subject, reviewed entitlements, tenant-only federation
scope, source digest, reviewer and UTC review time. Readiness deliberately avoids API-client
secret-returning detail endpoints. Session proofs additionally require an independently
reviewed `session_id_field` and `session_schema_digest`; the implementation does not assume
an undocumented vendor response field. Use `session_id_field: "@"` only for an independently
reviewed root array of scalar string IDs; otherwise supply the exact reviewed object field.
Session IDs stay in ephemeral trusted memory.

Only explicitly enabled controls with fresh successful readiness can activate. Changing
an existing resource requires its next generation and the next enrollment revision, with
no live roots, owners, holds or unresolved effects/acquisitions. Configuration changes do
not reset old identity blocks. Ordinary OBO passes the delegated JWT directly to Vault;
native service-token ownership is available only through the separately enrolled exclusive
native login mount/role. Batch/shared token trees remain unsupported.
