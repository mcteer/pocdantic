# Boundary Review: Monty Database Sandbox

**Reviewer**: coding assistant, planning review, 2026-10-12.
Checked means requirements/design reviewed, not implementation verified or owner merge approval.

- [x] Verified identity and trusted profile precede execution; every callback rechecks authority.
- [x] Monty exposes only the query callback; credentials, host objects and ambient access are excluded.
- [x] Controlled remote-command attempts distinguish engine rejection from model refusal.
- [x] SQL lowers to a closed plan; every unsupported syntax/node/field rejects before Vault.
- [x] Database grants, read-only transactions and bounded execution remain independent constraints.
- [x] Both authentication routes preserve durable custody and exact cleanup before returning rows.
- [x] Cancellation owns host tasks independently of the Monty worker and drains before releasing locks.
- [x] Limits cover parse, compute, wall time, memory, source, output, callbacks, sleep and session state.
- [x] Private inspection is owner-scoped, bounded and transient; telemetry/evidence excludes source data.
- [x] Optional dependencies preserve base installations and use reviewed pins/licenses/worker identity.
- [x] Real engine, synthetic providers, isolated PostgreSQL and live acceptance are distinctly labelled.
- [x] Existing fixed-query and original fifteen-criterion/four-case closeout semantics remain intact.
- [x] Negative, replay, cleanup, sign-out, malicious data, browser and cross-platform tests are required.
