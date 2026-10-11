# Research: Portable PoC Setup

## Standard Vault route

Decision: add explicitly selected `user-jwt` database authentication alongside existing
`delegated-exchange`; existing defaults remain delegated. No automatic fallback.
Rationale: broker.py currently supplies an exchanged JWT to X-Vault-Token; ordinary Vault
instead exchanges a verified JWT through its configured auth mount for a native token.
Alternatives: requiring advanced OAuth integration everywhere fails the ordinary-Vault goal;
operator-token fallback violates attribution and least privilege. Reusing governance's
workload login blindly conflates human and automation ownership.
Source: [Vault JWT authentication](https://developer.hashicorp.com/vault/docs/auth/jwt).

Standard mode proves verified human access and server-role enforcement, not actor/RAR semantics.
Vault JWT roles must bind issuer/audience/subject or approved group claims to an exact
SELECT-only role. A dedicated service token with a verified hard lifetime cap must support exact self
revocation; unsupported batch/non-revocable tokens block this recipe. Never use root or
operator tokens for database execution. Token issuance and database lease issuance each
need durable intent, private ownership, exact cleanup, and uncertain-outcome blocking.

## Identity compatibility

Decision: retain RS256/ES256 signed access JWT requirements and configurable expected typ;
add a bounded explicit HTTPS hostname allowlist to Settings and share OAuth config builders.
Rationale: generic providers can separate signing-key and authorization hosts; current
OAuthConfig permits trusted_hosts but Settings never supplies them. Workspace discovery
must honor provider selection even when old Verify administration settings remain present.
Alternatives: redirects/automatic trust weaken issuer and credential boundary guarantees;
opaque token introspection adds a separate integration contract and is out of scope.
Source: [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html).

## Advanced capabilities

Decision: advertise and document exchange/RAR, phone approval, administrative remediation,
governance and native audit independently. Metadata is evidence of advertisement only.
Rationale: ordinary sign-in does not establish exchange support; even generic token exchange
is insufficient for the current actor/path/lease authorization profile.
Alternative: universal-provider branding conceals unsupported demonstrations.
Source: [OAuth token exchange](https://www.rfc-editor.org/info/rfc8693/).

## One database target definition

Decision: validate custom database mount/role into a single credential target used by runtime,
readiness, recovery and source import classification. Existing `VAULT_READ_PATH` remains accepted.
Rationale: vault.py, validation/readiness.py, recovery/models.py and validation/importers.py
all assume database/creds. Classify native paths from trusted pinned deployment configuration,
not a raw evidence-selected prefix. Preserve old snapshots as their original deployment.
Alternative: changing only the HTTP path breaks evidence/cleanup and creates false portability.

## Repeatability and independent proof

Decision: non-overwriting local setup plus no-effect default checks; explicit named live
validation reuses workspace/broker boundaries. IBM Verify plus Keycloak is the target pair,
with separate Vault deployments, custom mounts and at least one namespaced test fixture.
Rationale: independently defined fixtures catch tenant coupling; real-provider and colleague
runs are distinct from offline software verification. No containers or provider resources
are launched automatically in ordinary tests or this planning phase.
Alternative: treating mock tests or another Verify tenant as live portability is insufficient.

## Dependencies and unresolved research

Use existing Pydantic, httpx, PyJWT, FastAPI, psycopg and Playwright; no new runtime dependency.
Versions for the real pair are recorded when actual deployments are supplied, not invented.
External access and colleague participation are explicit live prerequisites, not architectural
unknowns. License/redistribution rights for provider binaries are not assumed.

## Standard service-token compatibility and cleanup scope

Decision: accept either renewable flag for JWT-issued service tokens, never renew, and verify
`explicit_max_ttl` in a bounded `auth/token/lookup-self` response before database issuance.
Require a hard cap of 1–300 seconds and remaining lifetime greater than the operation deadline
plus a 30-second cleanup reserve. JWT role administrators set token_explicit_max_ttl, service
token type, no periodic behavior, and an explicit constrained policy without default-policy
inheritance. A bad token response is still an issued credential: attempt exact self-revocation
and preserve uncertain ownership if cleanup cannot be confirmed.
Rationale: JWT auth exposes lifetime/type controls and can return renewable=true; requiring
renewable=false would reject a normal supported deployment. See the
[JWT role API](https://developer.hashicorp.com/vault/api-docs/auth/jwt).

Decision: the example dedicated PoC policy allows only its credential path, lookup-self,
revoke-self and synchronous lease revocation constrained to `{mount}/creds/{role}/*` with
required scalar lease_id and sync=true. No wildcard system access, lease listing, prefix/force
revocation, token creation or renewal. The adapter additionally accepts only its recorded exact
handle. This policy permits role-scoped cleanup at the provider; it is not per-lease RAR proof.
Rationale: a static policy cannot anticipate a newly issued random lease handle. Publish this
boundary clearly and test both the provider role boundary and the adapter's ownership boundary.
Sources: [Vault policy parameter constraints](https://developer.hashicorp.com/vault/docs/concepts/policies)
and [synchronous lease revocation](https://developer.hashicorp.com/vault/api-docs/system/leases).

A failed lease revoke must not prevent best-effort self-revocation. Self-revocation also affects
that token's dynamic secrets, but must not fabricate an independent confirmed lease receipt.
Only the exact successful synchronous lease response resolves the lease automatically; otherwise
retain uncertainty for reviewed native recovery. Expiry or a later 403 does not prove cleanup.
Source: [token revocation](https://developer.hashicorp.com/vault/api-docs/auth/token).
