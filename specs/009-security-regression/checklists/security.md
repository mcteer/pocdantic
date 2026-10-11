# Security Requirements Review: Security Regression Validation

**Created**: 2026-10-10
**Reviewer**: coding assistant, planning boundary review
**Feature**: [spec](../spec.md) and [plan](../plan.md)

Checked means the requirement is specified and reviewed, not implemented or vendor-accepted.

- [x] CHK001 Scope: Function 12 has fourteen build items and ten tests; Function 13 signoff/client-count experiments are explicitly excluded. [spec context]
- [x] CHK002 Authority: No new live mode, provider effects, credentials, administrative route or acceptance override is exposed. [FR-011, FR-014]
- [x] CHK003 Isolation: Temporary source snapshot and guards precede test collection, including native database seams and subprocess inheritance. [plan flow4]
- [x] CHK004 Inputs: Catalog selectors, profiles and commands are compiled and bounded; arbitrary pytest options are rejected. [C02–C03, contract commands]
- [x] CHK005 Completeness: All selected parameter items require passed setup/call/teardown, complete inventory and terminal seal; skip/xfail/xpass cannot pass. [C11]
- [x] CHK006 Identity: Signed authority, purpose, actor/RAR,100-run stable mapping and foreign remap expectations are explicit. [FR-003, FR-008]
- [x] CHK007 Escalation: Four hostile-content sources and inverse human/agent privilege pairings have independent controls. [FR-004]
- [x] CHK008 Approval: Denied/pending/timeout/expiry/replay/mutation require zero privileged issuance/effects. [FR-005]
- [x] CHK009 Revocation: JWT, lease, fresh login, held session and next issuance are separate outcomes. [FR-006]
- [x] CHK010 Containment: Partial failure, duplicates, both hold scopes and fresh-root-only recovery are explicit. [FR-007]
- [x] CHK011 Privacy: No raw pytest log/exception/parameter text is retained; canaries cover every new report/scan boundary. [C12, FR-009]
- [x] CHK012 Storage: Owned modes, links/inodes, immutable records and strict preflight precede inherited storage helper side effects. [C10, C14]
- [x] CHK013 Bounds: Time, count, byte, drain and report performance limits are measurable. [C07–C09, SC-004]
- [x] CHK014 Freshness: Actual code/test/policy/dependency bytes and versions bind results; historical evidence cannot be current. [FR-010]
- [x] CHK015 Ownership: Every failure has severity/role/reproduction; no ordinary high-severity waiver flag exists. [FR-013]
- [x] CHK016 Native proof: Ten compiled native blockers preserve exact prerequisite/action/recheck and unavailable audit. [contract native table]
- [x] CHK017 Compatibility: Development tooling avoids runtime package/API/schema/dependency changes; narrow fixes require original-contract regressions. [plan]
- [x] CHK018 Validation: Repeatability, two actual policies, independent stories, publication/distribution and existing CI gates are required. [quickstart]
- [x] CHK019 Completion: Software tasks and live acceptance remain independent; no missing native capability excuses unfinished software. [T038–T040]

19/19 requirements-quality checks satisfied. Implementation must treat these markers as read-only.
