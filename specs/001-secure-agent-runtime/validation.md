# Validation summary

Owner: mcteer. Observed: 2026-10-09.

## Software baseline

62 deterministic tests passed with the server, Logfire and PostgreSQL extras.
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
