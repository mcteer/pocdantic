# PoCdantic

A Pydantic AI agent harness with verified identity, scoped tools, delegated database
access, and exact-action approvals. Python code lives in `src/agent`.

## Get started

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync --locked --group dev
uv run agent demo
uv run agent validate run
```

The demo and nine validation scenarios use synthetic data and make no network calls.

## Configure a live run

Copy [.env.example](.env.example) to `.env.local` and enable only the integrations
you need. Offline runs need no environment variables. Defaults cover model selection,
timeouts, limits, and agent profiles.

Install the relevant extras: `google`, `openai`, `anthropic`, `logfire`,
`server`, or `postgres`. For example:

```sh
uv sync --locked --extra google --extra server --group dev
uv run agent probe
uv run agent run --task 'Summarize POC-1' --profile parent
```

Authenticated runs require a signed user access token and a configured OAuth provider.
Database and phone approval each require their own integration settings. See the
[runtime guide](docs/usage.md) for setup and commands, and the
[configuration reference](docs/configuration.md) for optional overrides.

Environment names are short: `MODEL`, `BEARER_TOKEN`, `OAUTH_CLIENT_ID`,
and `DATABASE_HOST`. Existing `POCDANTIC_*` names and the `pocdantic` command
remain supported; short variable names take precedence within the same source.
Environment variables override `.env.local`.

## Development and evidence

See [CONTRIBUTING.md](CONTRIBUTING.md) for tests and review requirements, and
[architecture decisions](docs/adr/README.md) for the design.

Live evidence and generated reports stay in ignored `.local/` directories.
A deterministic test pass does not establish live product enforcement; customer
acceptance requires real evidence and review.

No project license has been selected. Bundled Spec Kit assets retain their
[upstream notice](.specify/THIRD_PARTY_LICENSE.txt).

Local readiness and immutable evidence closeout are described in the [runtime guide](docs/usage.md#local-readiness-and-closeout).
