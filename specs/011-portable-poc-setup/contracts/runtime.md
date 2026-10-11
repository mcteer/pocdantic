# Runtime Contract: Portable PoC Setup

## Setup interface (planned; unavailable before implementation)

`agent setup init --mode user-jwt|delegated-exchange` creates a private non-overwriting
configuration example at `.env.local` with mode 0600 and no symlink traversal; never reads tokens from flags,
never provisions providers, never rewrites existing config/journals. A conflict returns a fixed
reason and manual edit instructions. No command emits configured secrets or tenant identifiers.

`agent setup check` performs local validation only. Optional `--network` runs bounded public
OIDC metadata/JWKS, Vault seal and database transport observations without user/API token issuance,
SQL, phone prompts or administrative API calls. Default report is JSON-safe CapabilityObservation
projection plus required short setting names, repair steps and ownership. Local success exits 0;
missing/invalid required baseline configuration exits 2; storage or unresolved recovery exits 3.
Optional unsupported demonstrations do not block a compatible baseline. Network observations do
not mark authorization demonstrated. Maximum 32 rows, 10-second call and 30-second total budget.

Live baseline validation uses existing local workspace sign-in and the trusted broker's fixed
read operation, separately from setup commands. It names issuance/read/revocation effects and
records allow/deny/cleanup without model-authorized effects. No default prompt or operator-token
fallback. The validation guide supplies exact existing CLI/workspace commands at implementation.

## Identity and endpoint trust

One OAuth-config builder honors provider selection for CLI and workspace. A generic deployment
never derives Verify discovery from leftover API-client settings. Explicit trusted_hosts bounds
cross-host metadata endpoints; preserve issuer pinning, HTTPS, response bounds, no redirects,
RS256/ES256, configured typ, kid, iss/sub/aud/iat/exp and access/ID identity continuity.
Baseline signature verification uses discovery/JWKS without requiring a separate agent/service
client secret. Only interactive login exchanges use LOGIN_CLIENT_ID/LOGIN_CLIENT_SECRET.
No opaque token or permissive claim mapping. User scopes and existing deterministic policy
remain required. Certificates use verified explicit CA trust, never verify=False.

## Vault routes and lifecycle

`delegated-exchange`: retain exact user/actor/RAR verification, OAuth-resource-server access,
path-scoped acquisition and exact cleanup authorization. No route changes after a failure.

`user-jwt`: verify user access JWT and deterministic database policy, write durable login intent,
POST only configured `auth/{mount}/login` with configured role/JWT, privately capture a revocable
native service token, write lease intent, acquire only exact configured database target, run the
existing bounded parameterized query. The configured Vault role must independently constrain
identity and read path. Use exact lease cleanup, then native token `auth/token/revoke-self`;
require definitive successful cleanup, shield cancellation and preserve both unknown dispositions.
Always attempt token cleanup even after lease cleanup fails. A self-revoke acknowledgement
does not replace the independent synchronous lease receipt; unknown lease outcomes stay blocked.
Reject unsupported token type/missing TTL or cleanup capability. Capture a bounded returned token/accessor into private ownership before validating TTL or other
response properties, so a malformed response still triggers cleanup. The shared 30-second
cleanup budget reserves at most 20 seconds for the lease and the final 10 seconds for token
self-revocation; timeout/draining retains ownership and unresolved status. Native token TTL must be
positive and at most 300 seconds, with lookup-self confirming service type, nonperiodic behavior
and explicit_max_ttl of 1–300 seconds. Remaining lifetime must exceed the selected operation
deadline plus 30 seconds reserved for cleanup; insufficient time blocks read issuance. The
renewable flag may be true or false, but the harness never renews. No root, static
operator credentials, arbitrary mounts chosen by model output or issuer/subject substitution.
This route's label and evidence explicitly say user JWT, not delegated actor enforcement.

## Configuration and durable evidence compatibility

Short settings: DATABASE_AUTH_MODE, VAULT_JWT_AUTH_MOUNT, VAULT_JWT_AUTH_ROLE,
VAULT_DATABASE_MOUNT, VAULT_DATABASE_ROLE, OAUTH_TRUSTED_HOSTS, OAUTH_CA_FILE, VAULT_CA_FILE.
Each CA file applies only to its provider client, including isolated network diagnostic workers;
retain DATABASE_SSLROOTCERT for PostgreSQL. Existing VAULT_READ_PATH and
all documented aliases preserve precedence; inconsistent legacy/new target inputs fail before
issuance. Keep workload/governance roles separate from human roles. Shared DatabaseTarget drives
credential validation, readiness, journal invariants and trusted importer classification.
Source classification pins configured mount/context, not arbitrary source-supplied prefixes.
Existing journals migrate without erasing failed/uncertain operations; old evidence stays tied
to its original route/target. Configuration changes never unblock unresolved cleanup.

## Evidence and acceptance

Ordinary tests use independently defined IBM Verify/generic-provider fixtures and custom
Vault targets; no ambient credentials. Real recipe targets IBM Verify and Keycloak on independent
Vault deployments and records versions and prerequisites actually used. Missing resources remain
blocked with exact instructions. A colleague performs two timed setup runs; assistant simulations
do not satisfy colleague usability. Feature portability records are separate from the original
fifteen acceptance rows. Documentation links to authoritative provider setup, avoids unstable UI
menu guesses, and gives expected values/results without publishing tenant identifiers.

## Baseline policy, recovery and validation interface

Administrator examples use a dedicated PoC database role. Its policy allows exact credential
read, token lookup-self/revoke-self and sys/leases/revoke with required lease_id/sync fields,
lease_id restricted to the configured role prefix and sync=true only. No default-policy
inheritance or extra identity policies may broaden this reviewed profile. The trusted adapter
rejects sibling lease handles, lists, traversal, prefix/force revocation and every other target.
Role-scoped provider cleanup and exact application ownership are distinct documented boundaries.

Journal v3 adds route-aware human ownership and linked token/lease attempts under one exclusive
effect owner; do not synthesize an actor identity for user-jwt. Finishing either child does not
release the shared effect lock until both cleanup workers finish. Private native token bearer
material, if required for restart cleanup, is SecretStr in the existing protected recovery store;
public projections never include it. Never persist database passwords for recovery. Persist
provider/namespace/trust context so cleanup cannot be redirected by changed current settings.
Existing v1/v2 journals remain readable/migratable without discarding unknown history.

Native-token self-revocation is cleanup, so containment/sign-out cannot suppress it. Workspace
completion and cleanup projections wait for both credential dispositions; a lease event alone
never signals complete cleanup.

`agent recover status`, `revoke --incident UUID` and `import --incident UUID` must recognize
both credential kinds. Exact native-token cleanup uses only captured owner authority; unknown
login responses require reviewed provider request/response evidence to identify a token or
confirm non-issuance. Existing revoked/not_issued proof must be kind-aware. No new login or
role-prefix listing to reconstruct ownership; missing native proof leaves the incident blocked
with exact administrator steps. The spec does not assume audit export is available everywhere.

Add an explicit `live-portability` validation suite to existing `agent validate` interfaces,
with named `user-jwt-read` and `user-jwt-denial` scenarios, and no original UC criterion mapping.
The denied case uses a separately verified user token lacking database:read and MUST stop before
Vault login, issue no credential and leave no cleanup work. Bind the negative identity privately
through the live validation input contract; no token flags or generated identities. Add
PORTABILITY_DENIED_TOKEN as an optional private setting required only for this negative live case.
Positive validation records both token and lease acquisition/cleanup. Existing delegated suites
remain delegated-only. `agent validate ready --suite live-portability` checks these requirements;
`agent validate run --suite live-portability --mode live` explicitly authorizes that suite's effects.

Persist route, target/trust fingerprint, source product and original observation time in the
existing private validation records. Never label a generic identity source as Verify or capture
user-jwt records as delegated proof. Capability reports can read existing trusted demonstration
records only for the same context; records older than 24 hours are unverified history. Execution
always revalidates identity and authorization regardless of capability status. No public network
check can establish provider permission or create demonstrated status. Missing capabilities in
metadata remain unknown unless an explicit compatible-provider contract establishes unsupported.

## Required baseline settings and observations

For browser setup, require LOGIN_CLIENT_ID, LOGIN_CLIENT_SECRET, OAUTH_DISCOVERY_URL,
OAUTH_ISSUER, OAUTH_AUDIENCE, compatible OAUTH_ACCESS_TOKEN_TYP, and LOGIN_SCOPES containing
openid and database:read. Require the configured Vault/DB target and selected model credential.
Do not require BEARER_TOKEN, OAUTH_CLIENT_ID/SECRET, ACTOR_AUDIENCE, VAULT_AUDIENCE or Verify
administrative/phone/telemetry inputs for user-jwt workspace readiness. Explicit live CLI suites
add their own positive BEARER_TOKEN and PORTABILITY_DENIED_TOKEN prerequisites, with precise
instructions for obtaining them through the approved login flow. Never export workspace
credentials to the browser or logs merely to satisfy a CLI test.

Local readiness cannot establish a fresh authenticated 403/expiry/permission observation; use
only existing trusted context-bound observations or report unverified. A private saved bearer
can be verified during explicit network checks using public JWKS, without invoking a token
endpoint; missing bearer does not block browser sign-in readiness. State why a check is unknown.
