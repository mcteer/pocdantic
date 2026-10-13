# Implementation Validation Quickstart

**Status**: Implemented software validation recipe. Guide flags, test files and the onboarding
script below are available. Software validation does not authorize live setup; existing private
deployment state must remain untouched.

## 1. Reproduce the locked software environment

From the repository root, after implementation authorization:

```sh
uv sync --locked --extra server --extra logfire --extra postgres --extra sandbox --extra google --extra openai --extra anthropic --group dev --group browser
uv run --no-sync playwright install webkit
```

All three model extras here are for synthetic provider-construction tests, not baseline operator
installation. No real provider key is needed. The operator uses only the selected model extra.
Use the same committed lockfile; do not update dependencies to make an optional installation pass.

## 2. Focused regressions

```sh
uv run --no-sync pytest -q tests/test_offline_entrypoints.py tests/test_setup_recipes.py tests/test_setup_guidance.py tests/test_project_boundary.py tests/test_model_configuration.py tests/test_setup_walkthrough.py
uv run --no-sync pytest -q tests/test_setup_commands.py tests/test_setup_readiness.py tests/test_setup_evidence.py tests/test_setup_portability.py tests/test_portable_oidc.py tests/test_portable_vault.py tests/test_portable_recovery.py
```

Expected: poisoned dotenv/environment does not affect offline entry points; missing local
prerequisites cannot pass selected-recipe readiness; legacy direct provider resolution remains;
three repeated setup cycles preserve state; blocked/mismatched/partial state never suggests init
or replay; guide/check perform no provider I/O and no writes. All synthetic stores are temporary.
Tests must not read a developer's .env.local or use their real enrolled .local tree.

## 3. Real-entry-point walkthrough

The contributor helper is fixed-case and subprocess-based, not a shell interpreter:

```sh
uv run --no-sync python scripts/check_onboarding.py --case offline
uv run --no-sync python scripts/check_onboarding.py --case guided
```

It creates temporary synthetic projects, denies live dispatch and captures bounded summaries.
Offline includes ten consecutive actual CLI demos and compares normalized outcomes, plus invalid
.env/environment/model/profile/telemetry cases. Guided includes selected-provider package/key
matrices, absent/draft/enrolled/blocked states, three repeats, two independent directories and
wrong-root invocations. It invokes only compiled test cases; no commands from JSON are executed.
Expected: exit 0 for all selected software assertions; incomplete dependencies are reported as
incomplete, never success. Every child has a deadline and drains/terminates before completion.

The script's exact contract: `--case offline|guided|installed`; exits 0 pass, 1 assertion/failure,
2 prerequisite unavailable, 130 interruption. Overall deadline 180 seconds with ten seconds drain;
individual offline child at most thirty seconds. No raw stdout/stderr dumps or generated evidence
outside temporary/ignored private directories. The installed case assumes its package environment
already exists; it never installs or downloads dependencies itself.

## 4. Installed-artifact smoke checks

Build and inspect artifacts using the existing distribution gate. Run the installed smoke in
separate base, server/postgres-plus-selected-provider, and analysis environments. Each must import
the built package from its installed location, not src or editable installation. Use a temporary
working directory outside this Git tree, no PYTHONPATH pointing to source, no customer variables,
and controlled synthetic provider stubs where required. Record Python/uv versions and selected
extras in sanitized output.

Checks: agent/pocdantic help and demo, packaged profiles/suites/static assets, setup guide/check
behavior with missing packages, private-file provider keys, and root handling outside Git. Build
sdist and wheel; test both installation paths and ensure private canaries are excluded. Follow
the committed lock resolution when materializing dependency environments; do not resolve fresh
unpinned transitive versions from a wheel install. CI uses existing uv tooling to install the
built artifact into those locked environments without editable-source fallback.

## 5. Full software gates

Run the authoritative .github/workflows/ci.yml gates, including all-feature/runtime gates, privacy
against proposed index/history, lint/format, pytest/WebKit, security regression, offline validation
and demo, build/distribution privacy, targeted repeatability/report/readiness/closeout checks and
applicable sandbox platform/PostgreSQL checks. Ordinary onboarding tests never provision providers.
The separately invoked existing sandbox PostgreSQL fixture retains its own explicit CI scope.

Review staged diff/privacy after staging for publication. Passing a local working-tree check alone
does not establish what will be committed. Record actual results and unavailable checks in
[validation.md](validation.md); leave unexecuted tasks unchecked.

## 6. Authorized actual agent/colleague exercise (external prerequisite)

Follow [agent bootstrap](contracts/agent-bootstrap.md) with only administrator-provided base
variables and the maintained AGENTS.md/docs. Do not supply remote admin credentials to the agent.
Run the two real-provider baseline checks and two fresh unfamiliar-colleague setups already
required by feature 011 T028/T029, not a substitute duplicate acceptance exercise. Record actual
provider versions, participant role, duration and every excluded wait privately; publish only a
sanitized summary. Add one warm-repeat measurement targeting at most five minutes active work.

For each run separately record: locked install → smoke → local check → public network check →
reviewed enrollment → listening workspace → human sign-in → allowed read → independently supplied
denied check (if authorized/available) → exact cleanup. Resume and repeat without deleting state.
Two different OIDC products with separate Vault instances are required for portability proof.

If any administrator resource, participant, policy review or denied token is unavailable, stop at
that boundary and record the exact owner/action/recheck. Do not report the whole PoC as complete
because the software tests passed. Software validation and documentation maintenance authorize none of these live effects.
