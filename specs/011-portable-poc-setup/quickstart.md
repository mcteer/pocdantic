# Validation Guide: Portable PoC Setup

See [the colleague setup guide](../../docs/setup.md) for implemented commands and administrator examples.

## Colleague prerequisites

Install existing Python/uv prerequisites. Ask the provider administrator for a confidential
OIDC application with the workspace's documented loopback callback, signed access tokens and
required read scope; ask the Vault administrator for a JWT role constrained to that identity,
a dedicated SELECT-only database role, exact lease cleanup and revocable short-lived tokens.
Use approved HTTPS endpoints and CA files. Advanced demonstrations have separate prerequisites.
The implementation must publish exact commands and administrator policy examples in docs/setup.md.
Do not paste credentials into chat or command-line flags.

## Baseline repeatable flow

1. Run `uv sync --locked --extra server --extra postgres`; Verify administration and telemetry
   are not required for the generic baseline.
2. Run `uv run agent setup init --mode user-jwt`. Edit the generated private configuration
   using your supplied issuer, audience, app credentials, Vault auth/database targets and trust.
3. Run `uv run agent setup check`; correct only missing settings it names. Repeat and verify
   the existing private file and recovery history were preserved. If the report specifically
   says recovery is uninitialized, run `uv run agent recover init` once, then check again.
   Existing unresolved recovery is repaired using its instructions, never reinitialized.
   Enroll the existing local response controls as described in docs/setup.md; this does
   not enable provider remediation or change provider settings.
4. Run `uv run agent setup check --network`; public reachability is separate from authorization.
5. Start the existing workspace with `uv run agent workspace` (including the selected model
   credential where task submission uses the model), complete sign-in, run
   the fixed database-read demonstration. For deterministic live CLI checks, use the approved
   login flow to configure a fresh BEARER_TOKEN privately, and set a separately
   supplied negative test identity in private PORTABILITY_DENIED_TOKEN, then run
   `uv run agent validate ready --suite live-portability` and
   `uv run agent validate run --suite live-portability --mode live`. Confirm
   both lease and native-token cleanup. These are explicit live effects, not setup operations.
6. Sign out. Record actual outcomes, versions, private evidence references and limitations.

## Software validation

Run focused setup, portable identity/Vault and WebKit suites, then the CI gates documented in
AGENTS.md, offline validation/demo, both-profile security regression and distribution privacy.
Independent fixtures cover custom mount/namespace, issuer/audience/time/typ mismatch, missing
scope, untrusted cross-host metadata, unsupported exchange, 403, network timeout, repeated setup,
loss of either issuance response, failed cleanup, cancellation, replay and legacy migration.

## Real portability and colleague validation

Repeat steps 1–6 for IBM Verify and Keycloak using separate Vault instances and record actual
versions. Standard baseline success does not prove exchange/RAR or phone approval. Repeat setup
twice with a colleague unfamiliar with the repository; measure <=30 minutes per run excluding
explicitly logged external provisioning/human response waits and zero undocumented assistance.
If deployment access or colleague participation is missing, leave its task uncompleted and give
specific administrator/configuration requirements. Never provision remote services from CI.

The generated baseline lists only interactive OIDC credentials, issuer/discovery/audience and
scope/purpose settings, Vault endpoint/auth/database targets, PostgreSQL endpoint/name/TLS and
the selected model credential. Namespace, custom CA and trusted hosts are conditional. Agent
service OAuth, Verify administrative credentials, phone and telemetry settings are optional
advanced sections. The negative test token is needed only for explicit acceptance testing.
Provider administrator examples must constrain the role and native token lifetime per the
[contract](contracts/runtime.md); all sensitive values stay in `.env.local` or private inputs.
