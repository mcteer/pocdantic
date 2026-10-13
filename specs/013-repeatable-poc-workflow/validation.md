# Validation: Repeatable PoC Workflow

**Feature**: `013-repeatable-poc-workflow` | **Date**: 2026-10-13

## Corrected baseline

At baseline `7116f7c`, the planned recipe, guidance, prerequisite, project-boundary,
model-configuration and onboarding modules/tests are absent. The CI onboarding jobs
are also absent. Earlier task completion markers and software-pass claims were not
supported by implementation evidence and have been withdrawn. Existing repository
tests do not establish completion of this feature.

Implementation is now authorized through `$speckit-implement`. No live provider effects,
private configuration changes were authorized during implementation. The subsequent user request
authorizes preparing publication and merging subject to repository review requirements.
Both requirements-quality checklists are fully checked and remain unchanged.
No extension hooks are registered (.specify/extensions.yml is absent).

## Outstanding external gates

T030 has no separate live-resource authorization or participating unfamiliar colleague in
this invocation. The integration owner must arrange independent provider deployments/Vaults
and authorized validation tokens; the colleague/observer must perform feature 011 T028/T029
plus fresh/repeat agent-instruction measurements and retain original evidence privately.
Recheck with quickstart.md section 6. These tasks remain unchecked in both features.

T031 still requires the maintainer's boundary review of provider-secret loading, root admission
and state classification, followed by review/privacy checking of the actual publication index.
A temporary prospective index was reviewed and passed privacy/history; the real index remains
unchanged. No maintainer approval or publication disposition is fabricated. Synthetic checks
cannot close either task; acceptance.json remains entirely blocked.

## Current results

T001–T029 are complete as software work. T030/T031 remain unchecked.

## Implementation and consistency review

All eleven functional requirements map to the existing task coverage table. The design
preserves explicit review, verified identity, policy, custody, cancellation and exact cleanup;
no new runtime command executor, state schema, dependency, remote grant or provisioning flow
was added. Checklist review remains read-only. The unsupported completion claims were corrected
before implementation. The recorded planning-only scope is historical; this invocation expressly
authorizes implementation. No unresolved critical design conflict was found in the supplied
specification, plan, data model, contracts and task dependencies.

| Criteria | Implemented behavior / evidence |
| --- | --- |
| SC-001 / FR-001 | Real alias subprocesses: ten repetitions each, poisoned file/environment/model/profile/telemetry, socket denial, normalized delegation audit and unchanged canaries; optional real Monty check |
| SC-002 / FR-002–003 | Closed recipe/catalog contracts, selected package/key/profile and timeout matrix, independent identity readiness, selected private-file provider constructors and invalid database trust |
| SC-003 / FR-004–006 | Canonical root/refusal/worktree/outside-Git tests; absent/draft/enrolled/partial/linked/mismatch/busy/held state; repeated non-overwriting preparation and byte-preserving guidance; stale observations and budget failure |
| SC-005 / FR-007–010 | Actual AGENTS.md/runbook command/settings assertions, three recipes and complete selected extras; fixed bounded helper; two-directory repeats and wheel/sdist install checks |
| SC-006 | Negative contracts, guided/direct compatibility, affected WebKit suite, existing cancellation/replay/cleanup tests, privacy and distribution checks |
| SC-004 / FR-011 | Unverified: actual provider deployments and colleague measurements are unavailable |

## Executed software checks

- Focused model, recipe, root, guidance, setup and instruction tests passed after reproducing
  their missing-module/behavior failures. Affected workspace/WebKit subset: 83 passed.
- `uv run --no-sync python scripts/check_onboarding.py --case offline` and `--case guided`: exit 0.
- Ten actual artifact installations passed (wheel + sdist × base/Google/OpenAI/Anthropic/analysis),
  Python 3.12, exported `uv.lock` dependencies, outside source/PYTHONPATH, no editable fallback.
  Synthetic private canary exclusion also passed in an isolated offline build test.
- All-feature/runtime gates, lint/format, existing index/history privacy and distribution privacy passed.
- Targeted repeatability/report/readiness/closeout checks: 29 passed.
- Full baseline/restricted security regression: exit 0; native dispositions remain blocked.
- Offline validation: nine terminal passing scenarios, no blockers; offline demo: completed.
- Disposable loopback TLS PostgreSQL sandbox fixture: 1 passed; the fixture removed its container.
- Affected documentation relative links passed. Publication allowlist was not expanded.

Intermediate failures were corrected: closeout fixture denied the newly required read-only Git
query (now permits only that exact command); installed probe string quoting; duplicate missing
package names; macOS canonical packaged-profile path; build test counted uv's generated ignore
file as an artifact. Subsequent focused checks passed.

Final repository suite: `uv run --no-sync pytest -q` — **1315 passed, 1 skipped**, 204.59 seconds.
The ordinary suite skips the opt-in PostgreSQL fixture; its separately invoked TLS container
check passed. This local run is macOS/Python 3.12.14. Linux/macOS hosted matrix execution and
branch protection are not claimed; CI definitions were updated but no push or hosted run was
requested. Ten artifact installs on final software bytes passed again, including installed
nested-Git refusal before poisonous settings access. Final both-profile security regression
completed with every selected case passing and all native groups still blocked.

## Gate command ledger

| Command | Observed result |
| --- | --- |
| `python3 scripts/check_privacy.py --history` | Passed against real index/history and temporary prospective index/history |
| `uv run --no-sync python scripts/check_gates.py --all-features` | All 13 features passed; native acceptance remains blocked |
| `uv run --no-sync python scripts/check_gates.py --runtime-only` | Passed |
| `uv run --no-sync ruff check .` | Passed |
| `uv run --no-sync ruff format --check .` | Passed, 466 files |
| `uv run --no-sync pytest -q` | 1315 passed, 1 skipped; includes WebKit |
| `uv run --no-sync python scripts/run_security_regression.py run` | Passed baseline + restricted; native dispositions blocked |
| `uv run --no-sync agent validate run` | Nine passing terminal offline scenarios, zero blockers |
| `uv run --no-sync agent demo` | Completed synthetic delegation |
| `uv build` | Wheel and sdist built |
| `uv run --no-sync python scripts/check_distribution.py` | Passed |
| `uv run --no-sync python scripts/check_onboarding.py --case offline` | Exit 0 |
| `uv run --no-sync python scripts/check_onboarding.py --case guided` | Exit 0 |
| Artifact Python → `scripts/check_onboarding.py --case installed` | Ten locked wheel/sdist matrix checks passed outside source/PYTHONPATH |
| Targeted CI repeatability/report/readiness/closeout pytest selections | 29 passed |
| `uv run --no-sync python scripts/sandbox_postgres_fixture.py` | 1 passed; container removed |

Follow-up commands used `--no-sync` after the complete locked extras sync. No dependency or
lockfile change was needed. Existing private deployment settings/enrollments were preserved;
only explicitly generated synthetic validation/regression evidence was added under ignored
`.local/` as required by the validation workflow. No live customer/provider effect was executed.

## Delivery disposition

Software implementation is ready for maintainer review. Source, regression tests, docs and CI
changes are being prepared for a PR under the subsequent merge request. T030 and T031 remain
open until their evidence/review requirements are satisfied. GitHub reports main is unprotected;
required validate/PR-review protection is an outstanding maintainer configuration prerequisite.
Extension hooks were checked before and after implementation: `.specify/extensions.yml` is
absent, so no hooks require dispatch. Requirements/security checklist markers were not changed.
