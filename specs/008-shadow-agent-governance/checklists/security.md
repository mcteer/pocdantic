# Security requirements review: Shadow Agent Governance

**Reviewed**: 2026-10-10. Design coverage review for 008, not software completion or vendor acceptance.
**Sources**: [spec](../spec.md), [plan](../plan.md), [model](../data-model.md),
[contracts](../contracts/runtime.md), [research](../research.md).

- [x] Unknown observations grant no registry, minting or execution authority (FR-001–005).
- [x] Discovery requires actual collector classification/notification and pre-registration chronology (FR-001–003).
- [x] Source authentication, bounds, projection, replay and generation races are specified (FR-002).
- [x] Accountable owner, direct candidate identity, alias/entity and policy bindings are independently reviewed (FR-005).
- [x] Exact registration create excludes update/delete and automatic enrollment (FR-006).
- [x] Lost registration response, matching foreign state and uncertain 404 never authorize automatic retry (FR-007).
- [x] Effect capacity, inherited ownership, process drain and no I/O under control locks are defined (FR-007, FR-015).
- [x] New containment can commit while provider I/O runs and blocks later phases without restoring registrations (FR-015).
- [x] Candidate direct OAuth requires signed exact RAR, no act claim and no fallback to weakened registration flags (FR-009).
- [x] Native SVID mint uses the candidate credential and exact signed entity provenance (FR-009–010).
- [x] The separate relying service has independent pinned trust and no minting credentials (FR-010).
- [x] JWT header/key/URI/time bounds, cache expiry/rotation and one-use proof challenges are defined (FR-010).
- [x] Credential material stays memory-only and unknown server issuance remains pinned without a proven completion bound (FR-011).
- [x] Provider ceiling denial and direct ACL denial have separate controlled attribution (FR-012).
- [x] Local triage, native lifecycle and first observation cannot overwrite one another (FR-013).
- [x] Browser owner isolation, safe output and sign-out clearing are specified (FR-014).
- [x] New private artifacts, renamed files, distributions and telemetry receive canary checks (FR-016).
- [x] Per-test evidence, review, latest contradiction and demo-tier audit limitations remain explicit (FR-017).
- [x] Required negative/crash/race/performance checks and module/function documentation are tasked (FR-018).

No design exception to the constitution is required. These markers record review of
requirements and contracts; implementation tasks remain unchecked and native criteria blocked.
