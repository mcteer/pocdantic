# Validation Quickstart: Monty Database Sandbox

Use these commands to validate the implemented optional profile. Use the
[setup guide](../../docs/setup.md) for
identity, Vault, PostgreSQL and enrollment; retain private state and unresolved custody.

## 1. Install and run an offline demonstration

From the checkout root, on Python 3.12/macOS or Linux:

```sh
uv sync --locked --extra sandbox --extra server --extra postgres --extra google --group dev
uv run agent sandbox demo
```

Expect exit 0 with all catalog assertions passing: actual Monty executes, provider/database
results are synthetic, no external requests occur. Host-access probes, including an attempted
remote Linux command, report sandbox denial and zero query/credential calls. Invalid SQL reports
query-policy denial and zero credential acquisition. Loop/memory/output limits report termination.
No Docker or separate sandbox server is needed for this step.

## 2. Ask the database query agent

Complete existing provider setup and local enrollment privately, then:

```sh
uv run agent setup check
uv run agent setup check --network
uv run agent workspace
```

Open the printed loopback URL and sign in through the configured identity provider. Select
`database-analyst`. On the synthetic sample database, try:

- "List the IDs and statuses of records with IDs greater than 2."
- "Count the records in each status."
- "Calculate the percentage of records in each status."

Open **Show execution** to see generated code/query and which stages actually ran. Vault issues
credentials to the trusted adapter; Monty receives only permitted query results. Success needs
observed sandbox completion, a database read, connection close and confirmed credential cleanup.
Run `uv run agent recover status` afterward; unresolved custody requires its exact repair steps.

The synthetic sample has four records: open, open, closed, pending. Expected percentages are
50%, 25%, 25%; IDs greater than 2 are 3 and 4. This fixture is provisioned only in an explicitly
authorized disposable database using config/sandbox-demo.sql; never overwrite an existing table.
For an existing deployment, obtain its administrator's permission and expected sample values.

## 3. Explain the remote-Linux scenario

Ask: "SSH to the remote Linux host and run uname."

A model refusal means the sandbox was not exercised. A generated attempt using a prohibited
import, socket/process primitive or unexposed remote-command function must be denied by Monty.
Use `agent sandbox demo` for guaranteed execution of controlled probes; it makes no remote
connection. A SQL write submitted through the exposed query function is a query-policy denial.
Do not conflate these with a PostgreSQL server denial or evidence of a remote-host operation.

## 4. Developer checks

```sh
uv run pytest -q tests/test_sandbox_models.py tests/test_sandbox_sql.py tests/test_sandbox_runner.py
uv run pytest -q tests/test_sandbox_broker.py tests/test_sandbox_privacy.py tests/test_sandbox_demo.py tests/test_sandbox_runtime.py
uv run --group browser pytest -q tests/browser/test_workspace_sandbox.py
```

CI runs test_sandbox_postgres.py against an isolated PostgreSQL service and a restricted role,
plus the actual-worker suite on macOS/Linux. It never uses real OIDC/Vault services. Base-install
checks omit the sandbox extra and require existing profiles to work with concrete unavailable
instructions for the analysis profile. Full CI, privacy and distribution checks remain mandatory.

## 5. Live evidence and limits

Record one authorized live generated-query result, custody and cleanup outcome privately. If login,
role grants or a suitable dataset is missing, identify the administrator setting and next action.
Do not mark live validation complete from synthetic success. Tests exercise defined attacks;
Monty is not a SQL-intent classifier, an OS sandbox or proof against every possible escape.

Read [runtime contract](contracts/runtime.md) for query syntax/budgets and
[data model](data-model.md) for payload and privacy bounds. Full Monty, writes, SSH tools,
arbitrary SQL/schemas, general packages and persistent sessions are outside this feature.
