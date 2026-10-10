# Validation summary

Owner: mcteer. Observed: 2026-10-09.

## Software baseline

85 deterministic harness tests passed with the server, Logfire and PostgreSQL extras.
Lint, formatting, lockfile, configuration and distribution privacy checks passed.
An installed slim-base wheel completed the offline demo outside the repository.

## Live component checks

Verify action-bound phone approval completed a simulated infrastructure restart.
HCP Vault issued SELECT-only PostgreSQL credentials over trusted TLS.
Read succeeded, UPDATE was denied, unrelated Vault paths were denied, the leased
role was removed on revoke and a fresh read with revoked credentials was rejected.
The scoped validation token was revoked. No administrative credential was passed to
the model. Raw source-system evidence and target configuration remain private.

## Remaining acceptance

Full signed user/actor delegation, workload attestation, telemetry export and
deployment-dependent VIP/SVID evidence remain pending. Component tests do not satisfy
those gates. All 15 full acceptance criteria retain explicit blocked dispositions
pending the required reviewed evidence.

## Governance

Constitution 1.2.0, sanitized Spec Kit artifacts, review workflow and ADRs are versioned.
CI validates all features independently of machine-local state. Customer design sources,
credentials, live inventories and raw evidence remain excluded.

## Delegated identity follow-up

Signed mock-transport tests prove independently validated human and actor identity,
exact returned subject/actor/RAR claims, and distinct parameter-bound lease cleanup.
Failure and cancellation revoke the acquired lease. Host-supplied conversation history
preserves context without bypassing fresh run policy and containment checks.

Five local chat-host tests pass separately, covering shell assets, host/origin checks,
expired sessions, CSRF, PKCE binding, callback replay and token privacy. The entire
chat/ directory is ignored and rejected by the publish policy. Browser visual review
is pending because no browser surface is available in this session.

Dynamic registration returned HTTP 403 despite the configured lifecycle entitlement.
The standard application-management API succeeded with that same client. A separate
human application now has signed JWT access tokens, S256 PKCE, the three approved
agent scopes, and a single-user assignment; birthright access is disabled. Credentials
remain private. The local host's login redirect matches the registered callback.
T022/T030 remain pending real human sign-in and the delegated live credential chain.


## Live provider and identity preparation

Both PoC applications use Verify's newer OIDC provider, which advertises token exchange.
The agent JWT signature, issuer and audience verify against that provider. The administrative
API client retains its independent provider configuration. HCP Vault accepted a separate
OAuth profile for the new issuer, explicit human and actor aliases, and an agent registry
record with a narrow database-read/exact-lease-revocation ceiling. RAR remains required;
default policies are disabled for the new OAuth profile. The agent baseline is empty.

These setup calls succeeded against the live services; they do not establish successful
user delegation or database use. The local host captures sanitized stage evidence privately
and runs read-only record-1 validation following human sign-in. T022/T030 remain pending.

A live direct-actor credential request returned HTTP 403 without human delegation
or RAR, confirming that the agent cannot acquire a database lease on its own.
The distribution guard explicitly rejects chat/ paths even if packaging configuration changes.
