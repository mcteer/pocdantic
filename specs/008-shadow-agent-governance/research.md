# Research: Shadow Agent Governance

**Date**: 2026-10-10. Repository/design review and current primary documentation only.
No live tenant requests, configuration changes or credentials were used. Three research
agents investigated discovery, registry and SPIFFE contracts as required by the plan skill.

## 1. Separate observation from admission

**Decision**: Add `agent govern` with a separately versioned private governance store.
Reuse bounded parsing, authenticated relay and durable-file patterns, while keeping
unknown observations outside 006 run registration and 007 remediation enrollment.
**Rationale**: Existing `response/native.py` requires pre-enrolled object mappings.
Reusing that authority model for unknown discovery would require registration before
observation. An authenticated submitter alone does not prove native collector discovery.
**Alternatives**: Feed arbitrary unknown objects into remediation mappings; infer discovery
from local traces. Both confuse observation with authority.
**Contract**: Private source enrollment pins tenant product/version, collector and schema
receipts, scalar projection and relay authority. IBM describes telemetry discovery but
publishes no applicable tenant delivery/classification/triage schema here. Exact payload,
transport authentication and native lifecycle evidence are deployment prerequisites.
No generic Verify notification API or new Agent Identity preview dependency is assumed.
Sources: [IBM VIP](https://www.ibm.com/products/verify-identity-protection),
[IBM agentic identity protection overview](https://www.ibm.com/new/product-blog/agentic-ai-meets-identity-security-with-ibm-verify-identity-protection).

## 2. Explicit enrollment of one isolated entity

**Decision**: Provider administrators prepare the entity, exact OAuth alias, policies and
SPIFFE role. The workflow previews and explicitly creates only one registry record.
**Rationale**: This completes onboarding without becoming a provider administration suite.
Use `POST /v1/agent-registry/register` without `id`; the same API updates when an ID is
supplied, so updates are forbidden. Read by exact entity, reserved display name and returned
ID. Pin explicit policy defaults/RAR flags and read back all security-relevant fields.
No list-all discovery, auto-delete, restoration or blanket rollback is supported.
**Alternatives**: Automatic enrollment on detection, or editing existing registrations.
Both could expand authority or undo containment.
**Uncertainty**: The documented API has no CAS/idempotency key. A matching readback proves
current presence, not who created it. Lost submission remains unowned/uncertain unless
reviewed correlated provider evidence resolves it; no repeat POST based only on a 404.
Exclusive administration of the isolated candidate is a recorded live prerequisite.
Sources: [Agent Registry API](https://docs.hashicorp.com/vault/api-docs/secret/agent-registry),
[Agent Registry semantics](https://docs.hashicorp.com/vault/ai/iam/concepts/agent-registry).

## 3. Actor identity, ceiling and bootstrap

**Decision**: Verify actor issuer/subject, OAuth profile and exact alias-to-entity binding.
Use candidate direct OAuth for SPIFFE minting, never operator or human OBO credentials.
Vault's signed `vault.entity.id` must equal the approved candidate entity. The role template
and exact SPIFFE subject are separately reviewed; registry IDs do not define SVID subjects.
**Rationale**: OBO resolves the actor's registration but permissions also depend on the
human subject and RAR. Direct access uses the subject entity and baseline ACL. A registration
ceiling restricts OBO and cannot grant absent human permissions or constrain all other auth.
**Alternatives**: Reuse administrative minting; treat an OBO token's entity as the actor;
assume display-name equality binds identities. These do not prove workload provenance.
**Proof design**: Use dedicated synthetic KV-v2 fixture paths. For the excessive OBO read,
the human baseline and exact RAR permit the request but the ceiling excludes it. For direct
access, test the candidate baseline independently. Keep policies byte-digest pinned and
require actual provider responses plus healthy control; ambiguous policy attribution stays
inconclusive. No database lease is required by these probes.
Sources: [OAuth profiles](https://docs.hashicorp.com/vault/ai/iam/concepts/oauth-profiles),
[agent setup](https://docs.hashicorp.com/vault/ai/iam/setup-agent),
[RAR](https://docs.hashicorp.com/vault/ai/iam/concepts/rar).

### Candidate direct OAuth with required RAR

**Decision**: Add a candidate-only client-credentials request carrying exact
`authorization_details`; keep `optional_authorization_details=false`. Verify signed output
for exact candidate subject/audience/RAR and absence of `act` before Vault use. IBM's token
API exposes authorization details and OIDC app configuration supports constrained RAR, but
no complete cloud client-credentials propagation example was found. Actual signed output
is therefore a required capability check, never assumed from the API parameter alone.
If absent, instructions identify candidate JWT access-token mode, allowed `vault:path_access`
type and property filters for the exact paths. Unsupported deployments remain blocked.
**Alternatives**: Candidate-only subject exchange or optional RAR. Both require extra
reviewed configuration; neither is an automatic fallback or part of this implementation.
Sources: [Verify token endpoint](https://docs.verify.ibm.com/verify/reference/post_oauth2-token),
[Verify OIDC/RAR configuration](https://www.ibm.com/docs/en/security-verify?topic=sign-configuring-single-in-openid-connect-application),
[Vault optional RAR](https://docs.hashicorp.com/vault/ai/iam/make-rar-optional).

## 4. Native SPIFFE issuer and independent verifier

**Decision**: Native Vault SPIFFE is required for the selected 008 path; external issuers
need separate approved scope. Verify deployed version, entitlement, enabled mount and
role rather than assuming availability from Agent Registry. Bootstrap is already-authenticated
candidate direct OAuth; no native-token-login fallback is introduced.
**Rationale**: SPIFFE issuance appears in Vault Enterprise 2.0.0; Agent Registry requires
2.1.0. Neither authenticates an arbitrary unknown workload. Read exact config/role; mint
through `POST /v1/{mount}/role/{role}/mintjwt` with one pinned audience. `data.token` stays
in worker memory and is sent only to a separately spawned relying process over private IPC.
The relying process loads its own enrolled trust configuration and fetches public JWKS;
it verifies the token without calling an issuer validation endpoint. It is the local
independent relying service for this proof, exposed through `agent govern relying serve`
as a private Unix-socket service, never as a browser endpoint.
**Alternatives**: External SPIRE infrastructure, issuer self-validation, shared mutable
OAuth verifier configuration. These add scope or fail independent verification.
Sources: [release notes](https://developer.hashicorp.com/vault/docs/updates/release-notes),
[SPIFFE overview](https://developer.hashicorp.com/vault/docs/secrets/spiffe),
[SPIFFE API](https://developer.hashicorp.com/vault/api-docs/secret/spiffe),
[mint and verify example](https://developer.hashicorp.com/vault/docs/secrets/spiffe/mint-svid).

## 5. Verification profile and key rotation

**Decision**: Use Vault OIDC JWKS with `use=sig`, pinned HTTPS endpoints, one configured
algorithm and bounded freshness; no raw SPIFFE-bundle conversion. Enforce signature,
exact issuer, exact SPIFFE subject, one expected audience, signed entity provenance,
required finite integer issue/expiry times and a lifetime of at most 300 seconds.
**Rationale**: Standard JWT-SVID requires subject, audience and expiry; it does not require
`iss` or `iat`. Their presence here is a stricter Vault profile. Vault also publishes a
SPIFFE trust bundle using `use=jwt-svid`; silently treating that as OIDC JWKS is incorrect.
Require explicit trust-domain/issuer association independently of token contents.
Cache at most 60 seconds, cap response/key count, refresh once for an unknown key subject
to a ten-second refresh throttle, and reject ambiguous or expired trust. A successful empty
key set replaces the old cache and denies all tokens. Never follow token-supplied URLs.
Proof nonces are one-use local challenges; JWT-SVID itself remains a reusable bearer token.
**Alternatives**: Generic decode, arbitrary discovery hosts, unlimited stale keys or
claiming `jti` alone prevents replay. Each misses a security boundary.
Sources: [JWT-SVID specification](https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/),
[trust domains and bundles](https://spiffe.io/docs/latest/spiffe-specs/spiffe_trust_domain_and_bundle/),
[Vault OIDC verification example](https://developer.hashicorp.com/vault/docs/secrets/spiffe/mint-svid).

## 6. Issuance lifetime and bounded effects

**Decision**: Reserve intent/result capacity before candidate OAuth exchange, OBO exchange,
registration creation and SVID minting. Store only digests, verified expiry and uncertainty.
A lost identity response remains possible issuance through its conservative lifetime bound;
there is no immediate-revocation claim. If no verified bound exists, retain an unresolved pin.
**Rationale**: SPIFFE's documented API has no individual JWT-SVID revocation endpoint.
A role/registration removal or bootstrap revocation cannot invalidate every issued bearer.
Take the conservative bound from the last possible request-completion time plus reviewed
issuer maximum TTL and skew; use observed expiry if later. A client deadline/worker exit
does not prove server-side completion: require independent provider completion evidence or
a reviewed provider processing bound, otherwise retain unknown issuance. Drift also makes
the bound unknown.
**Alternatives**: Use request-start plus TTL, delete registration as cleanup, or discard
lost results. Each can report safety before the last possible credential expires.
Code basis: existing recovery/response private-file, child-ownership, intent and proof patterns
in `src/agent/recovery/` and `src/agent/response/providers/`; no new dependency required.

## 7. Chronology and closeout

**Decision**: Create a local controlled case, prove exact registry absence, run compiled
safe activity and receive native source evidence before permitting registration. Compare
bounded source and provider/local times, preserve the earliest evidence and reject a
backdated import as sole proof. Separate local triage and provider-managed state.
**Rationale**: Historical detection cannot be established by a current missing registration.
F11-T5 specifically needs native audit correlation. Existing demo-tier audit unavailability
remains blocked and cannot be repaired by another human token.
**Alternatives**: Treat successful local intake as native discovery or combine all seven
claims into one success bit. Both overstate acceptance.
Sources: [HCP tier features](https://developer.hashicorp.com/vault/cloud/get-started/deployment-considerations/tiers-and-features),
[constitution](../../.specify/memory/constitution.md). The supplied private design was
reviewed for scope; its document and source evidence remain excluded from publication.
