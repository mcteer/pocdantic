# PoCdantic

A Pydantic AI agent harness with verified identity, scoped tools, delegated database
access, and exact-action approvals. Python code lives in `src/agent`.

## Get started

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). Run from the canonical checkout
root; installed use outside Git uses the chosen deployment directory.

```sh
uv sync --locked --no-dev
uv run --no-sync agent demo
uv run --no-sync agent validate run
```

The demo and nine validation scenarios use synthetic data and make no network calls.

## Configure a live run

Choose a recipe: `offline` for rehearsal, `workspace-read` for signed-in fixed reads,
or `workspace-analysis` for Monty analysis. `agent setup guide --recipe workspace-read`
shows read-only next steps; `agent setup check` retains its JSON contract. Install the complete
selected extras set with `uv sync --locked --no-dev --extra server --extra postgres --extra google`
(replace Google with OpenAI or Anthropic when selected; analysis adds `--extra sandbox`).
Use `uv run --no-sync agent ...` afterward to retain those extras.

For a repeatable OIDC/Vault browser PoC, start with the [colleague setup guide](docs/setup.md).
It includes a configuration worksheet and a prompt for agent-assisted setup;
[AGENTS.md](AGENTS.md#help-someone-set-up-the-poc) defines the coding-agent workflow.

For a fresh browser baseline, create private configuration with
`uv run --no-sync agent setup init --mode user-jwt` only if absent, or supply settings
through the environment. [.env.example](.env.example) lists optional integration inputs;
existing installations retain their enrolled route and state. Offline runs need no inputs.

Available extras are `google`, `openai`, `anthropic`, `logfire`, `server`, `postgres`, and
`sandbox`. Keep the entire selected set in each locked sync. An authenticated CLI run uses
the already installed environment and a privately supplied user token:

```sh
uv run --no-sync agent run --task 'Summarize POC-1' --profile parent
```

Authenticated runs require a signed user access token and a configured OAuth provider.
Database and phone approval each require their own integration settings. See the
[runtime guide](docs/usage.md) for setup and commands, and the
[configuration reference](docs/configuration.md) for optional overrides.

Environment names are short: `MODEL`, `BEARER_TOKEN`, `OAUTH_CLIENT_ID`,
and `DATABASE_HOST`. Existing `POCDANTIC_*` names and the `pocdantic` command
remain supported; short variable names take precedence within the same source.
Environment variables override `.env.local`.

## Browser workspace

Follow the [setup runbook](docs/setup.md) for OIDC login, the selected model key,
Vault/database settings, trust and local recovery/response enrollment. The three `LOGIN_*`
settings are part of that configuration. Inspect current next steps first:

```sh
uv run --no-sync agent setup guide --recipe workspace-read
uv run --no-sync agent setup check --recipe workspace-read
```

After the guide's required preparation and policy review, a successful local check permits
`uv run --no-sync agent workspace`. Confirm the printed callback matches the login
application's registered callback, then open the actual loopback URL and sign in.
Local readiness, sign-in, an allowed read and confirmed cleanup are separate results.
See [browser setup](docs/usage.md#browser-workspace) for details.
Use **Check connection** for diagnostics and **Check recovery** after operator repair.
Live database access first requires [prospective recovery enrollment](docs/usage.md#durable-recovery).

For generated database analysis, install the `sandbox` extra and select `database-analyst`.
Run `uv run --no-sync agent sandbox demo` to see real Monty computation and blocked remote-command
attempts with synthetic data. See [Monty setup](docs/setup.md#monty-database-query-agent).

## Development and evidence

See [CONTRIBUTING.md](CONTRIBUTING.md) for tests and review requirements, and
[architecture decisions](docs/adr/README.md) for the design.

Live evidence and generated reports stay in ignored `.local/` directories.
A deterministic test pass does not establish live product enforcement; customer
acceptance requires real evidence and review.

No project license has been selected. Bundled Spec Kit assets retain their
[upstream notice](.specify/THIRD_PARTY_LICENSE.txt).

Local readiness and immutable evidence closeout are described in the [runtime guide](docs/usage.md#local-readiness-and-closeout).

Live work also requires [local response enrollment](docs/usage.md#incident-containment).
Optional [provider remediation](docs/usage.md#provider-remediation) adds enrolled native-event
intake, exact provider controls, independent checks, and guided recovery.

[Shadow agent governance](docs/usage.md#shadow-agent-governance) adds reviewed discovery,
exact enrollment and independent identity/permission proofs through `agent govern`.

Contributors can list, run, and inspect the synthetic security regression matrix with
`uv run --no-sync python scripts/run_security_regression.py run`; see [contributor checks](CONTRIBUTING.md#security-regression-checks).

Use `agent closeout` to guide demonstrations, assess private evidence, reconcile client counts,
and prepare a reviewed handoff. It runs locally; see the [closeout workflow](docs/usage.md#poc-closeout).
