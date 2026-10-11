# Implementation Plan: Security Regression Validation

**Branch**: `feature/009-security-regression` | **Date**: 2026-10-10
**Spec**: [spec.md](spec.md)
**Input**: Function 12 and the clarified 009 specification.

## Summary

Build a contributor-only regression entry point with a fixed executable coverage catalog,
reuse existing security assertions, fill the boundary gaps identified in [research](research.md),
and produce private immutable software results plus a safe ten-group summary. Native
prerequisites are compiled blocked dispositions. No production command or authority is added.

## Technical Context

**Language/Version**: Python 3.12+ with committed uv.lock.
**Primary Dependencies**: Existing pytest 9.x, pytest-asyncio, Pydantic, HTTPX fixture transports
and cryptographic test signers. No new dependency or environment variable.
**Storage**: `.local/security-regression/<run UUID>/`, existing PrivateStore/RunWriter with
strict wrapper checks; separate ephemeral maintained-source snapshot and synthetic test roots.
**Testing**: pytest contract, unit, negative, subprocess/deadline, privacy and joined-boundary
regressions. Existing full CI retains WebKit; this matrix does not launch browsers. New regression
tests also extend the existing test isolation fixtures for ordinary pytest execution.
**Target Platform**: macOS and Linux contributor/CI environments with POSIX process groups.
**Project Type**: Repository development tooling, excluded from runtime distributions.
**Performance Goals**: 600 seconds for selection/collection/two-profile execution, plus
10 seconds drain; 10,000 item-result report within five seconds excluding I/O.
**Constraints**: At most 256 security cases, 512 unique function selectors, 10,000 expanded
item results across both profiles, 8 MiB report, 100 MiB run storage. Strict details are in
[data-model](data-model.md) and [contract](contracts/runtime.md).
**Scale/Scope**: Four stories; fourteen Function 12 build mappings and ten test groups; two
fixed policies and a 100-execution identity drill. Function 13 remains separate.

## Constitution Check

| Principle | Pre-research gate | Post-design gate |
| --- | --- | --- |
| Slim reusable runtime | Pass: existing development dependencies | Pass: no runtime package/API or dependency addition |
| Trusted security boundaries | Pass: unchanged authority contracts | Pass: real trusted paths with synthetic adapters, negative and zero-effect assertions |
| Secret isolation | Pass: no private input required | Pass: pre-collection snapshot isolation, normalized metadata only, publication guards |
| Evidence before acceptance | Pass: no native proof assumed | Pass: ten blocked native records, no acceptance write/review override |
| Bounded observable execution | Pass: explicit budgets required | Pass: process ownership, watchdog/drain, count/byte bounds, complete phase results |
| Reviewed reproducible delivery | Pass: specification and requirements review | Pass: content/config identity, test-first tasks, CI and documentation gates |

No exception is requested. Narrow runtime fixes are allowed only when a regression proves
an existing contract violation; substantial new behavior requires a follow-up specification.
This planning run performs no implementation or live operation.

## Architecture and flow

1. **Validate catalog and selection**: load strict compiled case/group/build mappings.
   `list` is read-only. `run` accepts only known group/case/profile labels, with a full
   two-profile default. Each descriptor documents actual assertions, severity, role and
   enforcing boundary. No user selector, expression, file, plugin or command injection.
2. **Capture tested content**: enumerate regular eligible maintained files under src/agent,
   tests, scripts and public config, plus pyproject.toml/uv.lock. Use stable relative paths
   and exact bytes; reject symlinks/unsafe publication content. Copy to a fresh private
   temporary snapshot, hash the copied bytes and include new maintained untracked files.
   No dotenv, .local, design, .git, cache or browser state is copied. Snapshot imports must
   resolve to snapshot code, verified in a regression against editable-install leakage.
3. **Create private run**: strict preflight of the fixed report root and existing ancestors
   before PrivateStore can chmod anything; create a new UUID directory and immutable
   manifest with selected cases/profiles/content/version identity. Parent retains the run
   lock and exclusive metadata channel. This root is not a runtime recovery journal.
4. **Bootstrap test child**: one process group per profile, sequential profiles sharing the
   total budget. Minimal explicit OS environment, no user site/plugin autoload/addopts.
   Set cwd and default roots to snapshot/scratch, disable Settings dotenv before importing
   test modules, deny external socket/DNS/HTTPX and native driver connection seams. Compile
   the allowed local Git fixture operations and guarded Python helper entry points; no shell,
   arbitrary subprocess or provider CLI. Uncontrolled subprocess selectors are excluded.
5. **Collect and execute**: plugin records complete expanded item inventory before and after
   deselection; compare exact sets and known selectors. Shared selectors execute once per
   profile. Every item needs passed setup/call/teardown without xfail/xpass; collect-only,
   skipped, missing, duplicated or altered selection cannot pass. Require exit zero AND a
   matching terminal seal. Fixed startup and collection hook order precedes test imports.
6. **Persist normalized facts**: metadata channel carries bounded strict records only. Parent
   drains/discards all raw stdout/stderr. No longrepr, log record, captured text, skip reason,
   native identifier, host path or parameter value enters retained/public records. Test
   counters use only registered numeric properties; arbitrary pytest user_properties drop.
7. **Finish or contain**: parent enforces total deadline and drains group; child watchdog
   also exits by deadline if parent dies. Use TERM then KILL/reap within ten seconds, ensure
   no owned descendant survives before success. A killed parent leaves an unsealed run;
   report projects it incomplete after lock release without continuing any tests.
8. **Report**: verify immutable artifacts, run/profile/selection/content bindings and final
   seal; aggregate cases then groups. Compare current maintained bytes with captured content
   and record current/historical freshness. Report missing current content as unknown, never
   current. Native records stay blocked. Partial selections label omitted groups not run.

### Integration decisions

- Reuse PrivateStore primitives, but enforce owned0700 directories/owned0600 single-link
  regular files and matching inode before/after reads in the new wrapper. Do not weaken or
  silently migrate existing validation/recovery/response/governance storage.
- Regression content identity is independent of cached runtime implementation_revision;
  it includes tests, helper scripts, policy fixtures, static assets and dependency lock.
- `baseline` and `restricted` are fixed policy objects in test support. POC-1 remains a
  valid read control; ALT-1 changes from permitted to denied. New integration tests consume
  the profile. Existing tests with intentionally self-contained policies retain their
  assertions under both profiles; the report states their configuration applicability.
- Both high-human/narrow-agent and low-human/broad-agent ceiling combinations are explicit
  parameters inside the intersection drill under both profiles. A separate fixture oracle
  computes ACL ∩ ceiling ∩ RAR. Adapter tests verify handling, not native Vault semantics.
- Stable identity testing executes the trusted runtime 100 times, with fresh verified
  fixture credentials and distinct run/request/token references. A fake identity resolver
  maintains one approved mapping; foreign workload attempts are rejected through the
  bootstrap/binding boundary. This tests the mapping contract, not actual Vault billing.
- Provider fault drills compose existing real worker/guard/proof/report functions with
  isolated fake providers. Never just assert a hand-constructed expected report.
- Explicitly catalog existing local-network/subprocess tests that are excluded from this
  selection with alternate safe selectors; full repository CI retains their coverage.

## Project Structure

```text
specs/009-security-regression/
  spec.md  plan.md  research.md  data-model.md  quickstart.md  tasks.md
  validation.md  acceptance.json  checklists/  contracts/runtime.md
scripts/
  run_security_regression.py
  security_regression/
    __init__.py  models.py  catalog.py  isolation.py  plugin.py
    runner.py  store.py  report.py
  publish_policy.py                         # add private regression artifact shapes
  check_privacy.py  check_distribution.py    # existing checks, no new privileges
tests/
  conftest.py                               # isolate new tests in ordinary pytest too
  security_regression_support.py             # fixed policies, counters, injected services
  test_security_regression_catalog.py
  test_security_regression_models.py
  test_security_regression_isolation.py
  test_security_regression_execution.py
  test_security_regression_store.py
  test_security_regression_report.py
  test_security_regression_identity.py
  test_security_regression_escalation.py
  test_security_regression_policy.py
  test_security_regression_approval.py
  test_security_regression_revocation.py
  test_security_regression_incident.py
  test_security_regression_containment.py
  test_security_regression_privacy.py
  test_security_regression_repeatability.py
  test_security_regression_bounds.py
  ... existing identity/runtime/broker/provider/governance/telemetry tests reused
.github/workflows/ci.yml
README.md  CONTRIBUTING.md  docs/usage.md
```

The coverage catalog selects security assertions, not the runner's own meta-tests; this
avoids recursive runner execution. Full pytest runs all meta-tests. The entry point remains
outside the wheel and sdist; existing package include rules require no expansion.

## Delivery phases and independent checkpoints

1. Setup/foundation: strict metadata, immutable storage, isolated snapshot/child lifecycle.
2. US1: validated complete catalog and actual collection/phase accounting, safe CLI.
3. US2: signed-authority, four-source escalation, two-way policy, approval and 100-run gaps.
4. US3: independent revocation paths, partial incident, dual-scope/recovery and privacy drills.
5. US4: report/freshness/native blockers, real policy delta and repeated runs, CI.
6. Polish: contributor documentation, threat review, privacy/distribution and full gates.

Tests precede changed behavior; use independent fixtures for each story. US1 can validate
fixture catalog/execution results without later native or joined scenario work. US2 and US3
can run their focused tests without report storage. US4 uses bounded fixture records before
integrating the complete catalog. Final delivery requires all stories, not only the MVP.

## Validation and compatibility

Run [quickstart](quickstart.md). Preserve existing CLI, runtime, storage and acceptance
contracts. The only routine CI addition is the complete synthetic regression command;
keep all existing gates. Any exposed runtime bug receives a regression and boundary review
before a minimal fix. No maintenance of provider configuration, live call, push or merge
is part of this planning scope.
