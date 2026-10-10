# Validation summary

Owner: mcteer. Observed: 2026-10-09.

## Implementation result

All T001–T031 implementation tasks are complete. The real signed human/agent,
Verify token-exchange, HCP Vault and PostgreSQL flow completed successfully with
the live model. This completes feature 001 implementation; broader customer
acceptance and deployment attestation remain separately gated below.

## Software validation

90 deterministic harness tests and six ignored local chat-host tests passed.
Lint, formatting, locked dependencies, Spec Kit, runtime configuration, repository
privacy and distribution privacy checks passed. An installed slim-base wheel
completed the offline demo outside the repository. Playwright/WebKit desktop and
mobile chat smoke checks passed; screenshots remain private.

Signed mock-transport tests cover separate subject/actor verification, exact returned
RAR claims, scoped namespace-qualified leases, distinct exact-lease cleanup grants,
cleanup failure and cancellation. Conversation history preserves context while fresh
policy and containment checks run for every request. Chat tests cover host/origin,
CSRF, session expiration, PKCE callback binding/replay and private local diagnostic
control. The entire chat/ directory stays ignored and publication guards reject it.

## Live delegated credential proof

The human signed in through a separate confidential OIDC application using S256 PKCE.
The broker independently verified the human API token and client-credentials actor,
then verified the exchanged Vault-audience token's exact subject, actor and read RAR.
Vault issued an ephemeral database credential and the fixed record-1 SELECT succeeded
against PostgreSQL over trusted TLS. A second signed token exchange authorized only
sys/leases/revoke with the acquired lease ID as its required and sole allowed value.
The broker revoked that lease before returning a completed result. An independent
operator lookup subsequently returned invalid lease, confirming removal.

No operator Vault credential was used in agent execution. Administrative credentials
were used separately for provisioning and the independent post-run lookup. Raw tokens,
claims, leases, source-system configuration and diagnostic evidence remain private.
Earlier component checks proved UPDATE denial, unrelated Vault-path denial, role
removal and rejection of revoked database credentials. A direct actor-only request
without human delegation or RAR was denied by live Vault.

## Integration corrections

Both PoC applications use Verify's newer OIDC provider. The administrative API client
retains independent discovery configuration. Standard application management created
the human application using existing lifecycle permissions; dynamic registration was
unavailable. Both applications have single-user assignments and disabled birthright
access. Vault has explicit issuer/external-ID aliases and a registered agent with a
narrow ceiling; RAR is required and default OAuth policies are disabled.

Vault namespace-qualified lease IDs require a dotted suffix; cleanup now validates
that suffix while rejecting other roles, nested paths and traversal. Verify's existing
vault:path_access schema rejected parameter-bound cleanup fields. Its schema was
extended with required_parameters and allowed_parameters while preserving its other
configuration. The reusable schema in config/ and README document this prerequisite.

## Remaining customer acceptance

Implementation completion does not establish all customer/vendor acceptance criteria.
The 15 full acceptance records remain blocked pending owner-reviewed evidence, audit
correlation, telemetry export, deployment-specific workload attestation, VIP/SVID,
suspension and remediation behavior. Deployment remains configurable as requested.
The infrastructure write remains the selected simulated restart. Verify action-bound
phone approval for that simulation was separately proven; it is not a live
infrastructure change.

## Governance and privacy

Constitution 1.2.0, sanitized Spec Kit artifacts, ADRs and contribution/review workflows
are versioned. CI validates every feature without private machine state. Customer
design sources, credentials, local chat, inventories and raw evidence stay excluded.
