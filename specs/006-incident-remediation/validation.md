# Validation ledger: Incident containment and exact cleanup

**Date**: 2026-10-10. **Stage**: implementation and local software validation.
The required software is implemented; final delivery checks are recorded below.
Checklists review requirements/design, not vendor acceptance.

## Roadmap traceability

The supplied roadmap identifies Function 10 as incident-driven remediation. Feature
006 builds its local containment and dynamic-credential ownership foundation. This is
an incremental delivery boundary, not a reduction or completion of the full roadmap.

| Roadmap element | 006 disposition |
|---|---|
| Receive trusted risk signals | Implement normalized authenticated relay contract and separately labeled local operator input |
| Choose exact response scope | Implement root tree or stable definition mapped by trusted policy |
| Block and cancel local work | Implement durable admission/effect guards, cancellation and generation-aware release |
| Revoke temporary credentials | Implement attributable exact cleanup after owner drain, durable action history and recovery receipts |
| Measure response | Implement local timestamps/monotonic durations; source age and unavailable measurements explicit |
| Native VIP collector/detection | Follow-on integration; no native event contract or collector evidence claimed |
| External agent block and same-JWT denial | Follow-on provider control and independent still-valid-token enforcement proof |
| Compromised-user sessions/suspension | Follow-on identity mapping, explicit scope, authorization and restoration |
| Static-secret rotation | Follow-on exact-role action and downstream observation |
| Teams notification | Follow-on configured Workflows delivery and retry/idempotency semantics |
| Native downstream session loss | Follow-on provider observation; local lease cleanup is insufficient proof |
| Shadow-agent discovery/enrollment | Function 11 follow-on |
| Native Vault audit correlation | Unavailable on the recorded Development-tier cluster; preserve existing blocked disposition |

## Software evidence

| Requirements / success criteria | Implemented evidence |
|---|---|
| FR-001–004, FR-017 / SC-001 | Exact signed source authentication; bounded strict intake; atomic holds before acknowledgment; retained-event idempotency; API source isolation and capacity rejection. `test_response_auth`, `test_response_intake`, `test_response_models`, `test_response_store`. |
| FR-005–007, FR-012 / SC-002–003 | Trusted root registration, inherited descendant guards, fresh checks around model/token/credential/SQL boundaries, 250ms cancellation watcher, immutable acquisition ownership. `test_response_guard`, `test_broker`, runtime/API/workspace regressions. |
| FR-008–011 / SC-003–004 | Lossless v1→v2 migration, immutable legacy attribution, ordinary-owner receipt join, exact scoped administrative cleanup, denied/unknown/uncertain partial disposition, no automatic effect replay. `test_response_migration`, `test_response_coordinator`, `test_response_crash`, existing recovery lifecycle/proof/crash suites. |
| FR-013–016 / SC-005–006 | Complete-set/revision release, fresh generations, safe independent outcomes/timings, unavailable clock values, owned browser detail and same-user session isolation, metadata-only action events, renamed-artifact rejection. `test_response_cli`, WebKit `test_workspace_containment`, observability/telemetry/publication/privacy suites. |
| FR-018 / SC-007 | Full offline containment→drain→exact cleanup→reconcile→release path extends the existing cleanup-cancelled scenario; CI, repeatability, build and publication checks below. |

Real database effects remain globally serialized. Historical synthetic sibling records
test attribution selection, not simultaneous native lease acquisition. The SIGKILL
subprocess test proves that inherited effect/root descriptors remain owned until the
surviving child exits. Migration rename-failure tests see a complete v1 or v2 snapshot;
existing real credential crash tests retain uncertainty at every provider boundary.

## Optional live disposition

**Not run.** This implementation turn did not separately authorize a new live risk-relay
identity or automatic operator cleanup. Production response enrollment/policy is required
before live execution; temporary fixtures exercised software without changing providers,
using a human token, or sending phone prompts. No native signal, external JWT denial,
user/session suspension, rotation, Teams delivery or downstream session-loss result is
claimed. The Development-tier audit limitation remains independently blocked.

## Native acceptance

[acceptance.json](acceptance.json) retains all 15 original criteria with explicit blocked
dispositions. UC1/UC2 are not re-accepted by this planning package; prior evidence stays
in its original feature. UC3 still needs native detection and external enforcement
proof beyond 006. UC4 shadow governance is not implemented here. No prior evidence is
rewritten and no software pass promotes these statuses automatically.

The demo cluster's audit capability is a known tier limitation. Do not request another
dashboard search, access grant or human token as a supposed fix for that limitation.
Any future environment change is separate work with its own evidence and authorization.

## Delivery review

Source module/function documentation and trust-order comments were reviewed, including
child descriptor retention, cleanup exemption, migration, short-lock contention, action
intent and observer failures. Public usage/configuration includes exact enrollment,
migration, repair and release commands without additional environment variables.
Requirements/security checklist markers remain unchanged from the read-only prerequisite
review (16/16 and 23/23); implementation evidence is recorded here.

Maintainer security review and required target-branch protections remain PR/merge delivery
requirements. Local software checks do not claim remote CI, a maintainer approval, native
acceptance or permission to mutate providers. No extension hook file is installed.

Final local results:

| Command/check | Result |
|---|---|
| `uv run --group browser pytest -q` | **559 passed**, 96.28s; real WebKit included |
| `uv run agent validate run` | **9/9 pass**, including durable response lifecycle |
| Ten-repeat-run / 10,000-event report budget and readiness/closeout suites | **29 passed**, 5.47s |
| `uv run agent demo` | Completed synthetic result |
| `uv run ruff check .` / `uv run ruff format --check .` | Passed; 198 files formatted |
| `uv run python scripts/check_gates.py --all-features` | All six features pass; native dispositions preserved |
| `uv run python scripts/check_gates.py --runtime-only` | Passed |
| `uv build` / `uv run python scripts/check_distribution.py` | Wheel/sdist built; distribution privacy passed |
| `python3 scripts/check_privacy.py --history` | Staged tree and immutable history passed |
| `git diff --cached --check` | Passed |
| Module/function documentation and task trace review | Passed; 42/42 tasks completed; FR/SC mappings retained |

The final staged-tree check follows this evidence update. Native acceptance and
maintainer/branch-protection requirements above remain separate from these local passes.


PR CI follow-up: the push run passed all gates; the initial pull-request run found
short control-lock contention in the WebKit release fixture (558 pass, one failure).
The fixture now retries only the documented `response_busy` result for up to two
seconds; navigation does not drain a server request already in flight. Production
locking and stale/unsafe-release assertions remain unchanged. CI is rerun on the fix.

The next CI rerun identified two additional fixture races: reload before sign-out
completion, and synthetic recovery intent competing with journal inspection. WebKit
now waits for the signed-out UI before reloading; recovery fixtures retry only busy
journal locks before synthetic intent/inspection, never provider cleanup or proof.
