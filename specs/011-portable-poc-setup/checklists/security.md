# Boundary Review: Portable PoC Setup

**Reviewer**: coding assistant, planning review, 2026-10-11.
Checked means designed; new security-sensitive implementation still requires owner review.

- [x] Verified identity, purpose, audience and scopes precede Vault issuance.
- [x] Standard JWT and delegated exchange have distinct authority and evidence labels.
- [x] No silent downgrade or privileged operator fallback.
- [x] Explicit endpoint and CA trust preserve HTTPS and bounded no-redirect requests.
- [x] Both token and lease issuance have durable ownership before dispatch.
- [x] Unknown issuance and cleanup preserve blocking state, never replay for diagnosis.
- [x] Custom targets propagate into recovery and trusted evidence classification.
- [x] Legacy migration and deployment changes cannot erase or reattribute history.
- [x] Default setup checks issue no credentials and preserve existing private files.
- [x] Negative, cancellation, cleanup, replay and privacy tests are planned.
- [x] Real portability and colleague checks remain separate external acceptance.

Planning review refinement: standard JWT token renewal flags are compatible with hard lifetime
caps and no renewal operations. Static cleanup permissions are role-scoped with exact application
ownership; this does not claim per-lease delegated enforcement. Both recovery kinds, immutable
cleanup context, explicit 20/10-second cleanup budgets and shared completion are covered.
