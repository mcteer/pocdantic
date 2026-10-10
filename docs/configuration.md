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
