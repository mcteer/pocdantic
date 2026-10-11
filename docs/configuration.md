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

## Governance private inputs

Governance reuses `OAUTH_ISSUER`/`OAUTH_DISCOVERY_URL`, `VAULT_ADDR`, `VAULT_NAMESPACE`,
`VAULT_AUDIENCE` and existing response/recovery enrollment. Keep the candidate source,
credentials and evidence exclusively under owner-only local files. No model tool or browser
route accepts these inputs. The inactive committed `config/governance.example.json` grants
nothing; `agent govern prepare` creates the actual mode-0600 drafts beneath a mode-0700 root.

| Private input | Required review |
| --- | --- |
| `config.draft.json` | Up to 16 `Source` profiles: safe alias/generation; exact product/version/instance, schema/fixture/collector SHA-256 digests, scalar JSON Pointers and fixed classification predicates; exact relay issuer/subject/separate audience; native clock bound at most five seconds |
| `secrets.json` | Operator metadata/create credential; candidate and healthy client objects, each with the reviewed alias, verified JWT subject, private client ID and secret. Their signed subjects must differ |
| `candidate-UUID.draft.json` | `binding` and expiring independently reviewed `entitlement` receipt. No provider settings are created from this file |
| Non-TTY permission input | Exactly `schema_version` and `human_token`; at most 64 KiB. This human must match the reviewed owner issuer/subject and have the excessive-path baseline |
| External evidence import | Exactly `schema_version`, `evidence` and `artifact`; at most 1 MiB, owned regular file mode 0600, no symlink/hardlink. Artifact SHA-256 must match the strict evidence record |
| Captured receipt review | Exactly `schema_version` and `captured_evidence_id`; review the unchanged current adapter receipt without reconstructing secret-bearing provider bodies |

Use the maintained strict models in `src/agent/governance/models.py` and `config.py` as the
field reference. Boundary models reject extra fields and unsupported schema versions.
Canonical hashes use `binding_digest` in `agent.governance.config`, which hashes sorted
canonical JSON; hashing an arbitrary pretty-printed export produces a different digest.
Hash the inner `data` object returned by the reviewed SPIFFE role/config and named policy
GETs, rather than the outer response envelope. For an owner-only exported role receipt:

```sh
uv run python -c 'import json,sys; from agent.governance.config import binding_digest; print(binding_digest(json.load(sys.stdin)["data"]))' < .local/governance/role-export.json
```

This prints a digest and makes no provider call. The
entitlement's `digest` hashes the entire strict receipt excluding its own `digest` field;
it includes schema version, exact origin/namespace/version, registry/SPIFFE support,
artifact digest, reviewer/time and expiration. Readiness reports the first failed
prerequisite and does not infer a feature license from a version string.

The binding joins exact source object, owner issuer/subject, actor issuer/subject, client
aliases, Vault entity/issuer-external-ID alias, OAuth profile, reserved operation name,
namespace, ceiling policies and published SPIFFE trust. Pin one supported RS/ES algorithm,
canonical SPIFFE subject, signed entity, audience, discovery/JWKS URLs and a maximum
SVID TTL of 300 seconds. Trust's namespace must equal the binding namespace; public-key
requests use that exact namespace. OAuth profile audiences must equal the one configured
Vault audience and RAR remains mandatory. The supported profile resolves `sub` and
`act.sub` and uses access-token JWTs with at most 30 seconds of clock leeway. Candidate
root policies, inherited groups and dynamic group claims are rejected; all effective
policies must be explicit reviewed named policies. Ceiling policies exclude `root`,
`no_default_ceiling_policy` is true, and `optional_authorization_details` is false.
Record the independently reviewed `registry_clock_bound` (at most five seconds) before
the controlled case; unknown bounds cannot prove pre-registration chronology. The isolated
operator must have exact create/update capability rather than a root token.

The five path keys are `preregistration`, `obo_allowed`, `obo_beyond_ceiling`,
`direct_allowed` and `direct_denied`. Every value must be a dedicated
`MOUNT/data/FIXTURE` KV-v2 path; readiness verifies each mount's version. For registration
causality, preregistration and later direct-allowed reads must use the same resource.
Pin all relevant human baseline, ordinary actor ACL and ceiling policy bodies. A ceiling
claim requires the human baseline and requested RAR to allow the excessive path while
only the reviewed ceiling excludes it. Provider status 403 by itself is insufficient.

A source body cannot choose an owner, entity, policy, provider destination or effect.
Native provenance requires an enrolled actual source shape and authenticated collector
capture. `operator`/`synthetic` profiles cannot satisfy native acceptance. Source/profile
changes need a next generation and cannot replace inputs pinned by an open case or live/
unknown issuance. Changed case evidence invalidates unconsumed enrollment reviews.

Imports retain candidate/case/generation, environment/implementation/binding/source and
artifact digests, observed/received times, provenance, closed evidence kind/outcome,
independence/health/attribution, local observation/attempt references and structured facts.
Facts carry actual status/control/baseline decisions, independent proof ID, native audit
pair digests or provider completion/non-issuance information. Freeform artifact text cannot
substitute for these predicates. Historical or operator assertions cannot become native
intake; a late receipt cannot backdate discovery before registration. Each case has at most
32 evidence records. A changed import under an existing ID conflicts.

All provider calls have a ten-second/256-KiB bound. Effects run in a compiled subprocess
with a 120-second hard lifetime and inherited ownership locks, including after parent
death. Sixteen unresolved credential intents, 1,000 cases, 10,000 observations and a
32-MiB journal bound cap storage. Every effect reserves 256 KiB before dispatch.
Do not assume OAuth/SVID issuance stopped because a client timed out: automatic lifetime
safety needs an independently reviewed server-completion bound and the applicable TTL;
unknown bounds require explicit provider evidence and resolution.
