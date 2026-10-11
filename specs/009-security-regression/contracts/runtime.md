# Contributor tooling contract: Security Regression Validation

This is a repository development interface. It is not part of the installed agent runtime.
No operation below contacts a live provider or accepts credentials.

## Commands

```sh
uv run python scripts/run_security_regression.py list
uv run python scripts/run_security_regression.py run
uv run python scripts/run_security_regression.py run --group F12-T4
uv run python scripts/run_security_regression.py run --case approval-effects --profile restricted
uv run python scripts/run_security_regression.py report --run UUID
```

No subcommand defaults to `run`. `list` emits safe compiled catalog metadata and ten native
prerequisites without creating state or loading application settings. `run` defaults to all
cases and both profiles. Optional repeatable `--group` selects the union of groups; repeatable
`--case` selects case IDs instead; these two selection modes are mutually exclusive. Duplicate
or unknown values fail before starting a child. `--profile` selects exactly one known profile
for reproduction, otherwise both. Subsets are always labeled partial and omitted groups are
incomplete/not_selected. Reports may return selected-pass for a current partial run but must
never call that a full pass. There are no live, input-file, output-root, waiver, timeout-extension,
pytest-argument, retry, accept, approve, import or arbitrary command options.

`report --run UUID` verifies only that existing immutable run and compares current maintained
content. It never reruns tests, copies native evidence, repairs private state or writes an
acceptance file. Active run returns run_busy; abandoned/unsealed run returns incomplete.
CLI prints one bounded safe JSON object, with no path, traceback, provider data or raw failure
message. Human usage guidance explains closed codes and provides commands using known IDs.

### Exit behavior

| Exit | Meaning |
| --- | --- |
| 0 | Valid list, or every selected software case passed and content is current; full/partial is explicit |
| 1 | Test assertion/phase failure, unexpected pass, isolation violation or drift/integrity contradiction |
| 2 | Invalid selection, missing dev dependency, unsafe/unavailable storage, skipped/xfail/missing execution, busy/incomplete report, native prerequisites alone |
| 130 | User interruption after bounded process cleanup |

Native blocked rows do not change an otherwise passing synthetic run's exit code. Timeout,
lost child or cleanup_unknown uses exit2 with an incomplete/interrupted software state. A
nonzero pytest exit always prevents pass; classify infrastructure/collection/no-tests separately
from assertion failure. A selected fail dominates incomplete/blocked status for exit1, except
explicit user interruption130. Current-content-unavailable or historical report is nonzero.

## Closed vocabulary and public projection

Allowed reason codes: `catalog_invalid`, `unknown_selection`, `empty_selection`,
`selection_incomplete`, `collection_failed`, `test_failed`, `test_skipped`, `expected_failure`,
`unexpected_pass`, `phase_missing`, `protocol_invalid`, `content_changed`, `timeout`,
`interrupted`, `child_failed`, `storage_error`, `limits_exceeded`, `unsafe_path`, `run_busy`,
`incomplete_run`, `not_selected`, `native_evidence_required`, `audit_unavailable`,
`dependency_missing`, `isolation_failed`, `cleanup_unknown`, `artifact_mismatch`,
`current_content_unavailable`, `internal_error`. Passing records use no reason.

Each failure inherits case severity/owner. A compiled next-action registry covers every code.
Reproduction uses `run --case CASE --profile PROFILE` with validated catalog labels. Storage
or integrity errors instruct preserving the run and rerunning into a new UUID after fixing
ownership or investigated corruption; never instruct deletion/reset to bypass a result.
Unknown errors map to internal_error without exception text. No longrepr, captures, warnings,
log records, native values, subject/entity names, environment values, absolute paths or parameter
IDs are printed. Safe case selector paths are compiled repo-relative catalog metadata only.

## Collection and result protocol

The parent starts a fixed bootstrap with private run/profile/selection/content IDs and a
bounded inherited metadata descriptor, not a shell command. Explicitly load pytest-asyncio
and the reporter after isolation, before collection. Use supported pytest hooks:
`pytest_collection_modifyitems` with a wrapper to record before/after deselection,
`pytest_collection_finish` to seal selected item identities, `pytest_collectreport` for
collection failures, `pytest_runtest_logreport` for setup/call/teardown, and
`pytest_sessionfinish` for completion. Disable terminal/capture report output forwarding.

Collection inventories are chunked into bounded frames, followed by a count/digest seal;
no single frame contains an unbounded node list. Each unique selector expands to at least one node, and all nodes it expands to are required.
Collection-only cannot pass. Record a digest of each exact node ID; keep raw parameter text
inside child memory. The parent checks run/profile identities, monotonic sequence, selection
membership, duplicate/extra nodes and all phases. A setup/teardown error fails the item even
if its call passed. Skip, xfail and xpass are explicit nonpasses. No retry/lastfailed/maxfail/
filtering plugins or environment options are accepted. The final seal covers the collected
inventory, results, counts and process completion; results without a seal remain incomplete.

The reporter sends allowlisted normalized events, then one compact ItemResult per node.
Parent incrementally drains metadata and discards raw stdout/stderr without accumulation.
Metadata frames and retained records are bounded by C07/C09. No log body is retained even
on protocol failure. Optional counters use registered numeric properties only; tests must
assert forbidden effects directly, and missing metrics cannot be interpreted as zero.
A protocol-complete pass proves the selected assertions executed; it cannot detect a vacuous
assertion. Catalog review and the new tests' independent controls are required for that reason.

Hook semantics: [pytest hook reference](https://docs.pytest.org/en/stable/reference/reference.html#pytest.hookspec.pytest_runtest_logreport),
[skip and xfail](https://docs.pytest.org/en/stable/how-to/skipping.html),
[pytest exit codes](https://docs.pytest.org/en/stable/reference/exit-codes.html).
The implementation uses the locked installed versions and tests the stronger completeness
contract, including successful call followed by failed teardown.

## Isolation, process and storage boundary

Copy only regular eligible maintained files under fixed source/tests/scripts/public-config
roots plus pyproject.toml/uv.lock. Include content needed by reused tests and publication
helpers, excluding dotenv, private directories, Git internals, customer design, caches and
browser state. No external symlink traversal; source mutation during snapshot creation fails
content binding. Preserve relative file layout. Ensure agent imports resolve inside snapshot.

Only minimal OS execution variables needed by the selected interpreter are inherited; no
HOME/CODEX_HOME reassignment. Use explicit temporary cwd/root overrides, disable user-site,
plugin autoload and dotenv; ignore PYTEST_ADDOPTS/PYTHONPATH from the caller. Python and Git
binaries resolve before env clearing, and command lists are compiled with shell=False.
Allow local Git fixture commands only under snapshot/scratch (no fetch/push/remote commands).
Nested Python helpers, if any are selected, must use the same guarded bootstrap and deadline.

Install denied external socket connect/connect_ex/sendto/DNS and HTTPX transport guards
before collection; deny native psycopg connections unless tests inject their documented fake
connection seam. Permit in-process ASGI/MockTransport and owned scratch Unix sockets only.
Attempts are recorded as isolation_failed even when a test catches the denial exception.
Explicit sentinel tests verify no ambient dotenv, local state or external dispatch is touched.
These guards prevent accidental live effects in trusted tests; they are not a malicious-code sandbox.

Parent retains exclusive run lock, starts a new POSIX process group, enforces the 600-second
budget, and terminates/kills/drains within10 seconds. Child watchdog kills the owned process group at the deadline if the parent
exits. Any controlled descendants must stay in that group or be rejected; success requires
no owned work remains. Reporting a still-locked run is busy. Never resume or replay incomplete
work. Temporary snapshot cleanup occurs only after drain; report cannot reset external state.

New root `.local/security-regression` must already be ignored by Git. The wrapper checks
existing ancestor ownership/mode before using PrivateStore, then checks exact regular-file
identities around reads. RunWriter provides bounded atomic immutable writes. Final seal binds
normalized artifacts by SHA-256. Neither local ownership nor a digest authenticates provider
origin. All generated artifacts remain private even if renamed into publishable folders.

## Native Function 12 dispositions

All rows are blocked in this contributor report. Reuse the referenced feature workflows only
in separately authorized isolated environments; this tooling cannot execute or authorize them.

| Test | Owner | Missing prerequisite | Concrete action and expected recheck |
| --- | --- | --- | --- |
| F12-T1 | identity | Reviewed live signed-token/actor/RAR denial evidence | Identity/Vault owners configure isolated actors; use 008 readiness and candidate proofs plus 002 live delegation checks; review actual rejection and zero downstream issuance for each mutation. |
| F12-T2 | agent | Reviewed complete integrated escalation evidence | Run the authorized UC2 read/write sandbox with hostile synthetic prompt, ticket, child result and parameters; inspect trusted dispatch/credential evidence showing no forbidden action. |
| F12-T3 | vault | Both native human/agent policy pairings and path/capability/parameter controls | Configure isolated human baseline, ceiling and RAR; run 008 permissions workflow and reviewed negative requests, requiring healthy controls and actual provider denials for each layer. |
| F12-T4 | identity | Working device approval flow and correlated issuance evidence | Use 002/003 single-scenario live-phone workflow with an available approver; deny/expire/replay/mutate the exact action and review zero privileged credentials. App failure stays blocked. |
| F12-T5 | database | Authorized old/new login, held-session and next-Vault-call proof | Use 007 before/event/after proof workflow with independent healthy actor; revoke isolated lease and verify each path separately. Do not equate live JWT with revoked lease or a closed client with server session loss. |
| F12-T6 | integration | Reviewed VIP route and multi-action downstream receipts | Use 007 native intake with an isolated incident; exercise duplicate/lost/partial response and inspect retained holds plus notification acceptance/delivery separately. |
| F12-T7 | security | Authorized provider trace/audit exports for spot review | Run existing publication gates and synthetic canary tests; owners privately inspect actual exported prompts/logs/traces. Unavailable demo-tier Vault audit remains blocked, with no request to enable it through this tool. |
| F12-T8 | security | Reviewed before/after native policy evidence | Provider owner changes one isolated permission through existing administration, then reruns the same authorized controls; verify intended decision change and new configuration evidence. |
| F12-T9 | vault | Stable native alias/entity mapping and isolated100-run evidence | Owner runs100 authorized executions of one definition and reviews entity lookup plus foreign-workload rejection. Client billing/cardinality experiments are deferred to Function 13. |
| F12-T10 | security | Licensed SVID setup and both authorized containment scopes | Use 008 independent identity proof and 007 root/definition proof/recovery workflows; check bad SVIDs and every covered execution/access path with healthy siblings. |

Specific command contracts and setup: [003 quickstart](../../003-live-evidence-closure/quickstart.md),
[007 quickstart](../../007-provider-remediation/quickstart.md),
[008 quickstart](../../008-shadow-agent-governance/quickstart.md).
Native steps unsupported by an existing compiled workflow remain owner-run checks in a
separately authorized plan; 009 does not invent an endpoint or require those live effects
to complete the software implementation.
