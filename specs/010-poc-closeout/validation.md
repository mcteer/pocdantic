# Validation: End-to-End PoC Closeout

All 38 software tasks are implemented and validated. Validation completed October 10, 2026
(local time), using synthetic temporary evidence and the existing offline CI workflows.
No live demonstration, 100-user provider experiment or actual witnessed signoff was performed.
The fifteen native acceptance entries remain blocked.

## Software results

| Command/check | Actual result |
| --- | --- |
| `python3 scripts/check_privacy.py --history` | Passed against the staged tree and reachable history |
| `uv run python scripts/check_gates.py --all-features` | All ten feature gates passed; native criteria remain blocked |
| `uv run python scripts/check_gates.py --runtime-only` | Passed |
| `uv run ruff check .` | Passed |
| `uv run ruff format --check .` | 379 files formatted |
| `uv run --group browser pytest -q` | 1,129 passed in 153.35 seconds, including WebKit |
| `uv run python scripts/run_security_regression.py run` | Completed successfully across all ten cases and both baseline/restricted profiles |
| `uv run agent validate run` | Offline suite: nine scenarios passed; fifteen native rows remain blocked |
| Targeted ten-run/10,000-event CI performance tests | Two passed in 1.94 seconds |
| `uv run pytest -q tests/test_validation_readiness.py tests/test_validation_closeout.py` | 27 passed in 4.05 seconds |
| `uv run agent demo` | Completed with synthetic adapters |
| `uv build` | Wheel and source distribution built |
| `uv run python scripts/check_distribution.py` | Passed |

The final full suite includes the four CLI experiment flows, current source-review rejection,
plaintext-token rejection, actual byte quotas and complete phase-gate dependencies. All 127
closeout tests passed within the full suite. A bare assessment keeps witness/core gates blocked;
counting requires all four measured scenarios, and a failed measurement fails its assessment report.

Both distributions contain all twelve maintained closeout modules. Importing the source adapters,
command dispatcher and regression parser directly from the wheel succeeds without contributor-script
imports. An AST check confirms module, class and function docstrings throughout the new runtime.
No dependencies, environment variables, public allowlist entries or CI authorities were added.

## Executed synthetic lifecycle and requirement coverage

The quickstart's four stories were exercised through isolated private fixtures:

- US1: prepare, inspect, all eight guides, inventory amendment and stale-revision rejection.
- US2: original-byte import/extraction, exact profile and extraction reviews, fixed-root capture
  for all four member families, all fifteen independent predicates, contradictory evidence,
  conservative timing, assessment and historical applicability.
- US3: prepare before external operation times, original activity/mapping/roster imports,
  exact 100-operation cohorts and CLI measurement for all four scenarios. Expected totals are
  1/1/101/100. Reuse and increment are distinct. Repeated subjects, remapping, scope/month
  mismatches, incomplete exports, reporting lag and later review rejection cannot pass.
- US4: criterion reviews, customer/vendor exceptions, immutable blocked core and final handoff,
  actual-source-shaped witness receipts, five separate role records, explicit conflict
  supersession and accepted/exception/failed decision precedence. Same-person role records
  remain separate. Missing witness, wrong digest/role, stale context and unsafe cleanup reject.

Decision-precedence unit tests isolate the final acceptance reducer by substituting successful
count/software outcomes. Independent tests exercise actual original-byte count reconciliation and
regression collection/item/terminal reconstruction. All fixtures are simulated; neither test type
constitutes native acceptance or authenticates a reviewer label.

| Design mapping | Implemented verification |
| --- | --- |
| F13.01–F13.07 | Frozen inventory, guides, typed capture/import and fifteen original criterion reducers (US1/US2) |
| F13.08–F13.10 | Witnessed review, sealed readout/evidence core and separately sealed handoff (US4) |
| F13.11–F13.13 | Pre-operation experiments, exact scoped client counts and qualified comparison (US3) |
| F13-T1/T2/T3 | UC1+UC2 / UC3 / UC4 proof projections; final witness and owner requirements retained |
| F13-T4 | Complete fifteen-row matrix; final acceptance additionally requires full software regression closure |
| F13-T5/T6 | Repeated-agent scenario / remaining three exact native count scenarios |
| P4-G1–P4-G5 | All five remain visible and blocked until the complete qualified proof/signoff decision |

Privacy canaries cover native names, private reviewer prose, malicious source strings and known
credential shapes across console/error projections, Markdown, both packages and publication rules.
Tests deny settings initialization, network/socket and subprocess effects and assert zero attempted
effects. Supporting attachments require exact-byte sanitization review. PNG/JPEG framing and trailing
payload checks prevent mislabeled/damaged containers; image sanitization remains a human decision.

Storage tests cover ownership/modes, symlinks/hard links/special files, changed inodes, competing locks,
seal/head interruption, fresh retries, missing/extra/corrupted bytes and lock replacement before head
publication. Bounds tests cover deadlines, depth, individual/aggregate bytes, partial-write quota,
revision limits, ten unchanged read-only reports and 10,000 normalized activity records under five
seconds. Partial objects stay private and visible; no automatic repair, replay or deletion occurs.

## Compatibility and current native limitations

Existing `validate`, `respond` and `govern` command behavior remains unchanged. Closeout dispatches
before Settings initialization and performs no provider execution. Native capture uses original pure
reducers at actual capture time. Old validation closeout snapshots without complete run/context
closure remain operator evidence and require recapture. Unsupported regression catalogs remain
software-only and cannot satisfy complete current software coverage. Code/dependency, inventory,
source or review drift qualifies current applicability without rewriting captured outcomes.

| Missing prerequisite | Responsible owner | Exact action | Expected local recheck |
| --- | --- | --- | --- |
| Audit-capable Vault exports; demo-tier audit is unavailable | Vault owner | Supply an approved audit-capable environment/export linked to the actual operations, or record customer/vendor agreement on a qualified criterion exception | Import and review exact original bytes; reassess UC1-05 and audit obligations |
| Reliable registered-device denial flow | Verify owner | Repair the previously failing phone flow with provider support; separately authorize one deliberate denied/timeout check with independent zero-issuance evidence | Capture exact decision/action/resource bindings and Vault issuance history; reassess UC2 |
| Native VIP finding and collector schema | VIP owner | Supply reviewed event schema plus correlated finding, control/remediation and notification receipts using existing 007/008 workflows | Recapture the incident/candidate and reassess UC3/UC4 with original reducers |
| Independent bootstrap/SVID/relying and ceiling proof | Vault/Verify owners | Supply actual independently verified credentials and narrower native ceiling/read/deny evidence from the existing governance proof workflow | Capture candidate history; verify all original UC4 obligations |
| Complete activity exports and declared delay | Vault owner | Obtain the scoped activity export for the exact cluster/namespace/mounts/calendar period, before operations and after all operations plus the confirmed reporting delay | Import/review original baseline/final/mappings/roster; run `closeout measure` |
| 100 verified subjects and approved scenario execution surface | Verify/Vault owners and agent engineering | Provide the genuine subject/entity cohort and externally execute the approved 100-operation harness for each required mode; agent-only/direct surfaces may be unavailable | Prepare first, import actual successful roster and post-mappings, then measure all four scenarios |
| Actual witnessed core review and five decisions | PoC lead and each named role | Hold the real review of the sealed core; record original meeting receipt and each role's explicit decision against its exact digest | Import/review witness, append role decisions, generate a new handoff and inspect applicability |

These are explicit native acceptance prerequisites, not unfinished software tasks. Closeout never
launches demonstrations, provisions users, acquires credentials, changes provider settings, sends phone
prompts, uploads evidence or edits public acceptance automatically. Report exits distinguish current
full acceptance (0), failure/invalid integrity (1), and incomplete/historical/qualified-exception state (2).

Documentation validation: all 46 closeout/guide command forms parse through the actual complete CLI parser; changed relative file links resolve.


A full-suite rerun exposed an existing WebKit operator-cleanup test race: asynchronous status
reads could hold the nonblocking recovery lock. The test now retries only the explicit
`recovery_busy` result while its mocked provider call count is zero, within its existing two-second
budget. Provider cleanup is never retried, and production behavior is unchanged. Focused browser
and privacy checks passed (28 tests); actual individual/package byte-limit checks passed with all
seven bounds tests. Recognizable plaintext provider-token shapes and token fields reject; Vault's
irreversible audit HMAC representation remains usable.
