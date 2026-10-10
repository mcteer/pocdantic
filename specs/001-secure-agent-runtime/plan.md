# Implementation Plan: Secure agent runtime

Owner: maintainer. Date: 2026-10-09. Spec: [spec.md](spec.md).

## Summary
Deliver a reusable local/runtime baseline and live integration adapters. Keep tenant provisioning
and customer acceptance behind explicit evidence gates. Simulate infrastructure writes by default.

## Technical Context
Python 3.12+, Pydantic AI Slim 2.55.0, Pydantic settings, HTTPX, PyJWT cryptography.
Optional extras: Google/OpenAI/Anthropic, Logfire, FastAPI server, Psycopg PostgreSQL.
Deterministic TestModel/FunctionModel tests run offline; live probes never dump response secrets.
Single process baseline with logical child isolation; workload issuer configurable.

## Constitution Check
PASS: slim base, optional extras, trusted policy, no model secrets, bounded execution and explicit
live acceptance. Sanitized governance and specifications are versioned; customer sources and local tooling state
are excluded from tracked deliverables.

## Project Structure
src/agent/: settings, schemas, security, oauth, vault, approval, telemetry, capabilities,
runtime, api and cli. config/: reusable agent profiles. tests/: deterministic boundary tests.
scripts/: privacy/spec checks and hook installer. specs/: requirements/contracts/evidence status.

## Implementation Phases
1. Lock dependencies, configure privacy hooks/CI, typed inputs and settings.
2. Verified identity, deny-by-default policy, safe audit, exact-action approval contracts.
3. Native capabilities, parent/child factory and bounded service/CLI.
4. OAuth/Vault/database adapters, discovery/probes, optional authenticated server.
5. Acceptance evidence validation, containment, documentation and negative tests.

## Gates
Software: privacy + spec consistency + lint + tests + package inspection.
Live P1: real user login and workload mapping (100 independent authentications with stable entity).
Live P2: Vault RAR/ACL/ceiling denies, DB grants/revocation and exact-action Verify push.
Live P3: actual VIP origin, measured remediation, shadow discovery and independent SVID validation.
Live P4: witnessed assessment of all 15 criteria and owner signoff.
No local test may promote a live gate. Missing environment facts remain explicitly blocked.

## Complexity Tracking
Approval backend is an interface; simulated decisions exist only in offline demo/tests.
Baseline containment is process-local and cannot claim external session/token revocation.
A SQL allowlist and DB role grants complement Vault RAR; free-form SQL is never a tool argument.


## Delegated identity follow-up design

Keep the local chat host and PKCE callback in ignored chat/, outside the published
harness. Use separate human-client configuration and server-side expiring sessions.
Extract strict delegated claim validation and keep read/revoke token exchange in the
trusted broker. VaultClient accepts a trusted revoke callback; malformed lease data and
cancellation still use it. Existing operator-token provisioning retains its default cleanup.

Threat review: state/host/path/issuer and duplicate parameter validation prevent callback
substitution; PKCE binds the code to this process; tokens remain in private server memory.
Host and origin checks plus per-session CSRF protect authenticated mutations.
Conversation history is host-owned and isolated by user, thread and profile.
Never trust ID tokens as API tokens or copy provider errors into output. Signed user/actor
validation occurs before exchange. Parameter-bound cleanup grants cannot revoke other
leases. No externally denied request falls back to administrative credentials.
