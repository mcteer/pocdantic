# Validation ledger: Operational reliability

## Planning and companion documentation — 2026-10-10

Specification and clarification completed; user selected exact repair steps plus recovery
checks. Plan/research/design and tasks are planning artifacts. No 005 runtime code or live
provider configuration has been changed, and no 005 runtime test pass is claimed.

Root AGENTS.md is a separately requested companion documentation change on this branch.
It is linked from CONTRIBUTING.md; the publication allowlist adds only that exact root
file. The existing staged-secret regression now also covers AGENTS.md. Publication suite:
26 passed. All-feature Spec Kit gates, targeted Ruff lint/format checks, staged diff
whitespace review, and the index/history privacy gate passed. Task validation found 35
sequential checklist entries, full coverage of 16 requirements and 8 success criteria,
and all 13 model constraints quoted in their implementation tasks. Contributor instructions require useful module/function documentation. A
comprehensive code-commenting pass is queued for a separate branch after the user switches
models; it has not started.

## Planned live validation dispositions

| Case | Current disposition | Evidence/review |
|---|---|---|
| Normal read with confirmed synchronous cleanup | Blocked: not run for 005 | No source collected; reviewer pending. |
| Known-handle operator recovery retaining valid session | Blocked: not run for 005 | Requires a safely resolvable incident and authorized cleanup. |
| Unknown acquisition correlated to native lease | Blocked: native export/linkage not established | No invented mapping; reviewer pending. |
| Pre-execution denial proving non-issuance | Blocked: exact native proof not collected | Generic failure is insufficient. |

Deterministic software tasks can complete with supported cases validated synthetically and
an explicit live disposition recorded. A blocked live claim is not a completed live proof.
Acceptance.json preserves all 15 existing UC criteria as blocked; those criteria are
legacy vendor acceptance, not a substitute for the 005 FR/SC task coverage matrix.

## Historical limitations

The two unknown credential acquisitions recorded in 004 remain unreconciled. A new
journal cannot supply their missing native handles or correlation. Prospective enrollment
must not be described as resolving them. Existing 003 native audit/denial limitations
remain separately tracked. No prior exception or merge instruction is extended to 005.

## Delivery prerequisite

At last inspection main did not have the protections required by constitution 1.2.0.
Before any later merge, verify required validate, PR review, stale-approval dismissal,
and prevention of force pushes/deletion, and obtain actual maintainer review. Planning
completion is not a delivery approval or claim these controls are configured.
