# Boundary Requirements Review: Repeatable PoC Workflow

**Date**: 2026-10-12
**Reviewer**: Coding assistant, design review only.
**Scope**: [spec](../spec.md), [plan](../plan.md), [runtime contract](../contracts/runtime.md),
[agent bootstrap contract](../contracts/agent-bootstrap.md). Checked means requirement quality,
not implemented behavior, actual human policy review, or maintainer merge approval.

- [x] Offline paths are specified to ignore both dotenv and environment authority before live Settings construction (FR-001).
- [x] Readiness/guide cannot instantiate providers, issue credentials, mutate stores or export telemetry (FR-003/004/009).
- [x] Recipe/model/action selectors are closed, bounded and cannot become arbitrary shell execution (FR-002/009).
- [x] Supported provider secrets have consistent private-file/environment precedence and remain in trusted adapters (FR-003/009).
- [x] Root mismatch fails before private reads/writes; existing state and fingerprints are not moved or reset (FR-005/006).
- [x] Missing state is distinguished from unreadable, partial, busy, held and mismatched state (FR-004/005).
- [x] Enrollment instructions require real unchanged-policy review and do not confer authority themselves (FR-004/006/007).
- [x] Local setup authorization excludes remote provider administration and destructive reset (FR-006/007).
- [x] Retry rules distinguish non-effectful rechecks from uncertain effects and never replay issuance/reads automatically (FR-006/007).
- [x] Agent guidance explicitly preserves sign-in, read, denial and cleanup evidence distinctions (FR-007/011).
- [x] Tests include poisoned environments, no-network dispatch, repeated state, root isolation and artifact privacy (FR-008/009).
- [x] Compatibility and existing advanced-provider behavior remain explicit; unknown guided integrations cannot become false-green (FR-003/010).
- [x] Live/colleague prerequisites and owner review remain separate from software and planning completion (FR-011).

No constitution exceptions. Implementation must obtain owner review of new credential-loading,
root-precondition and state-classification boundaries before merging; this checklist cannot replace it.
