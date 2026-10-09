# Research decisions

- Decision: Pydantic AI Slim 2.55.0 with native Capability bundles and safe Instrumentation.
  Rationale: reusable tool behavior with no harness or provider dependency required in base.
  Alternative: full package/harness deferred until functionality needs it.
  Source: https://pydantic.dev/docs/ai/capabilities/overview/
- Decision: OIDC discovery with endpoint override and separate interactive/service client profiles.
  Rationale: Verify endpoints vary; client credentials do not authenticate a human.
  Source: https://docs.verify.ibm.com/verify/reference/handlemetadata
- Decision: RFC8693 subject/actor exchange with exact vault:path_access authorization_details.
  Rationale: retain delegation lineage; no impersonation fallback and no wildcard paths.
  Sources: https://docs.verify.ibm.com/verify/docs/token-exchange
  https://developer.hashicorp.com/vault/ai/oauth-server/rar/type-specification
- Decision: direct OAuth JWT in X-Vault-Token is distinct from workload JWT auth login.
  Rationale: each requires different trust/configuration and proves a different boundary.
  Sources: https://developer.hashicorp.com/vault/ai/iam/concepts/oauth-profiles
  https://developer.hashicorp.com/vault/api-docs/auth/jwt
- Decision: request-scoped DB credentials with connection close and explicit lease revocation.
  Rationale: TTL alone does not demonstrate post-request revoke; RAR does not govern SQL.
  Source: https://developer.hashicorp.com/vault/docs/secrets/databases/postgresql
- Decision: simulated infrastructure write and configurable workload issuer.
  Rationale: selected by project owner; no live destructive target or attestor assumed.
- Decision: Verify push eligibility must be proven in the tenant and device enrollment.
  Rationale: owning the app does not establish transaction-bound approval or tenant permissions.
  Source: https://docs.verify.ibm.com/verify/docs/multi-factor-authentication
