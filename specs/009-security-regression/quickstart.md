# Validation guide: Security Regression Validation

The commands below exercise the implemented contributor tooling. Every routine command
is synthetic; do not load customer
configuration or start a provider workflow to satisfy software validation.

## Prepare development tooling

```sh
uv sync --locked --extra server --extra logfire --extra postgres --group dev --group browser
uv run --group browser playwright install webkit
uv run python scripts/run_security_regression.py list
```

Expected listing: all fourteen build items and ten Function 12 groups mapped to named cases,
fixed selectors and explicit native prerequisites. List creates no state. Missing dependencies
return a closed dependency_missing result, with instructions to run the locked sync above.

## Execute and reproduce

```sh
uv run python scripts/run_security_regression.py run
uv run python scripts/run_security_regression.py run
uv run python scripts/run_security_regression.py report --run UUID
uv run python scripts/run_security_regression.py run --case approval-effects --profile restricted
```

Use each returned run UUID in report. Two full runs execute both baseline and restricted
profiles, producing four independent profile executions total. Expected: distinct run IDs,
identical expected classifications, current content digests and every selected item terminal.
ALT-1 is permitted only in baseline; POC-1 remains the shared permitted control. Existing
fixed-policy tests explicitly state fixed applicability. A single-case reproduction is
partial; omitted groups stay incomplete/not_selected. Nothing promotes native acceptance.

Artifacts live only beneath `.local/security-regression/<UUID>`. Inspect through report;
raw pytest exception/log/stream bodies are discarded. Failure output identifies case,
severity, owner, reason and compiled reproduction command. Preserve failed runs. Never
reset response/recovery/governance state to make a regression run pass.

## Independent story checks

| Story | Scenario | Required result |
| --- | --- | --- |
| US1 coverage | Missing/duplicate selector, renamed test, omitted parameter, collection-only, skip/xfail/xpass, failed teardown | No current full pass; exact group/case and closed reason, no raw pytest text |
| US2 authority | Signed identity/actor/RAR mutations; four injection sources; inverse policy pairings; approval states;100 actual runs and foreign workload | Valid controls, denied forbidden effects, distinct run identities with stable approved mapping; synthetic provider behavior labeled |
| US3 failure/privacy | Independent lease/JWT/new-login/held-session results; partial multi-action incident; both containment scopes and recovery; canaries | No combined false success, no replay, exact held scope, safe notification distinction, no secret leakage |
| US4 reporting | Two runs×two profiles; changed source/test/policy/lock; interrupted child; copied/corrupt artifacts;10,000 results | New UUIDs, expected policy delta, historical old results, bounded nonpassing interruption/corruption and report under 5 seconds |

Runner contract tests use disposable fixture catalogs and never recursively select themselves.
Timeout tests shorten an injected internal clock/budget only; production command limits cannot
be increased. Test parent death, process-group cleanup and child watchdog independently on
macOS/Linux. Isolation tests poison environment/plugin settings and use sentinel files and
connection spies; assert guards run before collection and affect native driver seams too.

## Required final software gates

```sh
python3 scripts/check_privacy.py --history
uv run python scripts/check_gates.py --all-features
uv run python scripts/check_gates.py --runtime-only
uv run ruff check .
uv run ruff format --check .
uv run --group browser pytest -q
uv run python scripts/run_security_regression.py run
uv run python scripts/run_security_regression.py run
uv run agent validate run
uv run pytest -q tests/test_validation_runner.py::test_ten_repeatable_runs_under_budget tests/test_validation_report.py::test_ten_thousand_normalized_event_report_budget
uv run pytest -q tests/test_validation_readiness.py tests/test_validation_closeout.py
uv run agent demo
uv build
uv run python scripts/check_distribution.py
```

Record exact result counts, durations, source/test/policy content digest, versions, scope,
privacy/build checks and review in validation.md. No native run is required to complete
009 software: each of the ten native rows must instead retain its exact blocked disposition
from [runtime contract](contracts/runtime.md#native-function-12-dispositions). The existing
15-row customer acceptance file stays blocked without separate reviewed native evidence.
Function 13 owns final witnessed end-to-end acceptance and client-count experiments.
