# Guidance for coding tools

This file applies throughout the repository. Follow explicit task scope and preserve
unrelated work. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[project constitution](.specify/memory/constitution.md) before changing behavior.

## Project map

- `src/agent/`: Python runtime, identity verification, policy, approvals, and trusted adapters.
- `src/agent/response/`: durable incident intake, root guards, exact cleanup and local release.
- `src/agent/recovery/`: private acquisition ownership, migration and operator repair.
- `src/agent/workspace/`: local browser workspace; static assets use plain JavaScript and CSS.
- `src/agent/setup/`: fixed recipes, prerequisite checks and read-only state guidance.
- `src/agent/model_config.py` and `src/agent/project.py`: trusted provider-key loading
  and root admission.
- `src/agent/validation/`: deterministic scenarios, private evidence, readiness, and closeout.
- `tests/`: unit and integration checks; `tests/browser/` uses Playwright with WebKit.
- `config/`: sanitized profiles and schemas; tenant settings belong in local configuration.
- `specs/`: versioned requirements, plans, contracts, tasks, and sanitized validation records.
- `docs/adr/`: architecture decisions. `docs/usage.md` and `docs/configuration.md` hold details
  that would make the README too long.
- `scripts/`: quality gates and explicitly invoked local provisioning tools.

Use `agent` for CLI examples and short environment-variable names from `.env.example`.
Preserve documented legacy aliases unless a task explicitly changes compatibility.
Keep examples synthetic and avoid personal names, tenant identifiers, and repeated branding.

## Help someone set up the PoC

Use [docs/setup.md](docs/setup.md) and [docs/configuration.md](docs/configuration.md).
Implementing a feature and operating an installed PoC are distinct scopes. A setup request
means carry out authorized local preparation and reach a signed-in workspace and successful
read; it does not authorize source edits or remote provider policy/grant changes.

Select `offline` for rehearsal, `workspace-analysis` for Monty/query work, otherwise
`workspace-read`. Establish the canonical deployment root first: stateful CLI commands refuse
nested Git directories, linked roots and unavailable Git discovery. Installed use outside Git
uses cwd; stateful commands still require Git for root discovery. Preserve `.env.local`,
`.local/`, the existing route and policy drafts. Separate checkouts/worktrees are separate
deployments; never copy enrollment or erase holds.

Base inputs are process environment variables or owner-only `.env.local`; environment wins.
Ask only for missing names and their administrator. Never request secrets in chat or dump values.

| Inputs for fresh live setup | Supplying owner / default |
| --- | --- |
| `DATABASE_AUTH_MODE`, `OAUTH_PROVIDER` | Operator: explicit `user-jwt`, `generic` for fresh baseline; preserve enrolled routes |
| `OAUTH_DISCOVERY_URL`, `OAUTH_ISSUER`, `OAUTH_AUDIENCE` | Identity administrator: audience distinct from browser client |
| `LOGIN_CLIENT_ID`, `LOGIN_CLIENT_SECRET`, `LOGIN_SCOPES` | Identity administrator: authorization-code/PKCE; `openid database:read` |
| `VAULT_ADDR`, `VAULT_JWT_AUTH_ROLE` | Vault administrator: constrained human JWT role; mount defaults to `jwt` |
| `VAULT_DATABASE_MOUNT`, `VAULT_DATABASE_ROLE` | Vault administrator: defaults `database`/`poc-readonly`, verify these exist |
| `DATABASE_HOST`, `DATABASE_NAME`, `DATABASE_PORT` | Database administrator: SELECT-only role and record 1; port defaults to `5432` |
| `MODEL_MODE`, `MODEL`, `GATEWAY_REGION`, `GATEWAY_ROUTE`, `GATEWAY_MODELS`, `GATEWAY_API_KEY` | New live setup: Gateway administrator supplies the private key/region/route and reviewed native model; existing enrolled direct mode uses its selected provider key |
| `OAUTH_CA_FILE`, `VAULT_CA_FILE`, `DATABASE_SSLROOTCERT`, `OAUTH_TRUSTED_HOSTS` | Respective administrators when custom trust is needed; no wildcard/bypass |
| `VAULT_NAMESPACE`, `OAUTH_ACCESS_TOKEN_TYP` | Respective administrators when applicable; actual token type, default `at+jwt` |

New live setups require `MODEL_MODE=gateway`, an explicit native model (`google-cloud:`,
`openai-chat:`, `openai-responses:` or `anthropic:`) and exact allowlist. Do not translate a GLA
model silently. Existing enrolled operators may explicitly retain `MODEL_MODE=direct`; identify
it as lacking Gateway protection. In direct mode, the selected private key is
`GOOGLE_API_KEY`, `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`; never request its value in chat. Missing mode requires a deliberate migration choice.
Before private model work, obtain an expiring Gateway review of actual routing, blocking,
spending/pricing and remote retention evidence. `agent gateway status` is read-only. Fixed
`agent gateway probe --case CASE` uses synthetic inputs but may spend money and requires separate
operational authorization; local setup scope does not authorize remote policy/billing changes.
`agent gateway review --reviewer operator --decision reject` blocks later dispatch even with
broken configuration/evidence. Approval requires complete exact live source evidence. Preserve
all recovery/enrollment and holds; do not bypass denial by changing route, key or model.

Offline needs none of these inputs. Delegated-exchange also needs its documented OAuth client,
secret and Vault audience; do not silently switch routes. Browser setup requires neither a saved
bearer/denied token nor a Vault/admin token or phone authenticator.

1. Install the entire selected extras set together with Python 3.12+ and committed `uv.lock`:
   `uv sync --locked --no-dev` for offline; add `--extra server --extra postgres --extra google`
   for reads, replacing only `google` with `openai` or `anthropic` when selected; analysis adds
   `--extra sandbox`. Later syncs can remove omitted extras. Follow-up commands use
   `uv run --no-sync agent ...`. Run `agent demo`; analysis also runs `agent sandbox demo`.
   For `offline`, run `agent setup guide --recipe offline` and `agent setup check --recipe offline`,
   report the synthetic result and finish. Steps 2–6 apply only to live recipes.
2. Create configuration with `agent setup init --mode user-jwt` only if absent and file input
   is desired. Existing exported inputs need no duplicate file. Run `agent setup guide --recipe
   workspace-read --format json` and `agent setup check --recipe workspace-read`, substituting
   the selected literal recipe. Exit 2 means input/dependency/root repair; exit 3 means
   enrollment, review or recovery; exit 0 means local prerequisites only. Unknown guided model
   integrations require integration-owner review. A nonzero exit does not authorize init.
3. For authorized live setup, run `agent setup check --recipe workspace-read --network`:
   public metadata/seal status and bounded TCP only. Follow available actions;
   `after-prerequisites` actions require their prerequisites first. Only wholly absent recovery
   permits `agent recover init`.
   Partial/busy/held/mismatched/damaged state needs status and documented repair, never reset.
4. With valid recovery and wholly absent policy, run `agent respond init --prepare`. Present
   the actual draft choices: local-only intake, no sources, no remote control authority,
   automatic provider cleanup false. Preserve context/definition/issuer. Run `agent respond init`
   only after actual explicit review of that unchanged policy; reuse already supplied review.
   Existing enrollment skips preparation/review/init. A template or setting is not approval.
5. Recheck, then launch `agent workspace` with process/session ownership. Verify it responds and
   return the actual listening loopback URL and callback printed by the process; confirm the
   callback matches the administrator-registered login application.
   Do not invent a running server or silently change a port/callback. Use Playwright/WebKit for
   authorized browser help: open the URL, choose Sign in, have the user authenticate, and continue
   after return to the workspace. Never request or export cookies/tokens.
6. Select `database-reader`, request record 1; analysis selects `database-analyst` and count by
   status. Use observed stages and exact cleanup, not model narrative. Run `agent recover status`.
   Separate CLI allow/deny checks require supplied private tokens and authorized effects.

Retry a non-effectful local check once after actual repair. Repeated unchanged failure ends in
its exact code, owner, next action and recheck; new supplied inputs can begin another cycle.
Never automatically retry uncertain issuance/reads, enrollment races or provider effects.
Finish with selected recipe/route/extras, observed software checks, actual URL/callback/process
state, and separate sign-in/read/denial/cleanup dispositions plus concrete remaining actions.
Optional/native acceptance requires private source evidence and review. Local setup authorization
does not authorize remote administration; provide the runbook's administrator steps instead.

## Development

Use Python 3.12+ and the committed `uv.lock`. Install only the extras needed for the task.
The CI environment is reproduced with:

```sh
uv sync --locked --extra server --extra logfire --extra postgres --extra sandbox --extra google --extra openai --extra anthropic --group dev --group browser
uv run --no-sync playwright install webkit
```

Behavior changes follow specification → clarification → plan/research/contracts →
requirements review → tasks → consistency analysis → implementation → validation.
Use the available Spec Kit skills when requested. Select the intended `specs/` feature;
`.specify/feature.json` is an ignored local pointer, not a shared source of truth.
Do not implement when the requested scope ends at planning. Small documentation fixes
need documentation validation rather than a new feature specification.

Use typed Python, strict boundary models, small provider-independent adapters, and the
existing package structure. Add dependencies only with a stated purpose, license review,
and lockfile update. No project license has been selected; do not assume redistribution
rights for third-party material.

Document each maintained source module and function so a contributor unfamiliar with
the system can understand its purpose. Explain inputs, outputs, side effects, and failure
behavior where they are not obvious from the signature. Comment the reasons for security
checks, ordering, cancellation, and cleanup decisions; avoid comments that merely repeat
the next statement. Keep documentation accurate when behavior changes. Use docstrings
for Python and appropriate function/module comments for JavaScript and scripts.

## Security and evidence

- Derive identity from verified credentials and authorize every effect deterministically.
  Model output never grants authority. Child permissions must remain narrower.
- Keep tokens, passwords, native credential handles, and raw provider responses in trusted
  adapters or approved private evidence storage. Never put them in prompts, browser
  responses, exception text, traces, fixtures, or committed documentation.
- Keep `.env.local`, `.local/`, customer documents, browser traces, and source-system
  evidence out of Git and distributions. Use sanitized summaries for review.
- Preserve execution bounds, exact-action approvals, cancellation containment, and cleanup.
  Uncertain issuance or cleanup must not be reported as success. Do not replay effects to
  diagnose failures or bypass blocks by clearing local state.
- Use fixed parameterized SQL and least-privilege grants. The optional database-analyst
  profile may propose SELECT queries only through the closed sandbox admission/compiler;
  never execute its original SQL or expose credentials to generated code. Ordinary tests must not call live
  providers, send phone prompts, provision services, or change remote configuration.
- Synthetic tests prove application behavior. Vendor acceptance requires live source
  evidence and explicit review; record unsupported or unavailable checks as blocked.
- For authorized browser work, use Playwright/WebKit. If human authentication or a provider
  action is necessary, give the exact link, steps, and expected result. Reuse existing
  authorization; do not repeatedly ask for permission already granted.

## Validation and delivery

Run focused checks while editing. Behavior changes need meaningful regression tests;
authorization and adapter changes also need negative, cancellation, cleanup, and replay
coverage. Before delivery, run the applicable gates from `.github/workflows/ci.yml`:

```sh
python3 scripts/check_privacy.py --history
uv run --no-sync python scripts/check_gates.py --all-features
uv run --no-sync python scripts/check_gates.py --runtime-only
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync pytest -q
uv run --no-sync agent validate run
uv run --no-sync agent demo
uv build
uv run --no-sync python scripts/check_distribution.py
```

CI includes onboarding and locked artifact-install matrices, sandbox platform/container checks,
and targeted repeatability and readiness/closeout checks; its workflow
is the authoritative command list. Documentation-only work needs artifact, link, and
privacy validation; rerun affected tests if a supporting gate changes.

The privacy gate reads the Git index and history. Inspect `git diff --cached` and rerun
it against the proposed publication tree. `scripts/publish_policy.py` uses an explicit
allowlist; review any expansion and keep it as narrow as the requested artifact.

Trace completion to acceptance criteria and report software results separately from live
limitations. Update public usage/configuration guidance for behavior changes and record
migration steps. Never mark unexecuted tasks or unverified acceptance criteria complete.

PRs need a concise problem/result summary, validation, compatibility impacts, and remaining
live limitations. Follow the constitution's maintainer-review and branch-protection rules;
green CI alone does not authorize merging. Push, merge, publish, or change provider state
only within the user's requested scope.

## Help demonstrate Monty

For sandboxed database analysis, follow [the Monty setup section](docs/setup.md#monty-database-query-agent)
and [query contract](docs/usage.md#monty-query-contract). Install the optional sandbox extra,
run `uv run --no-sync agent sandbox demo`, then start the workspace and select `database-analyst`.
A live model-generated query uses the existing OIDC/Vault/PostgreSQL baseline and enrollment.
Do not give the program a database connection, Vault client, token, file mount, network or SSH tool.

Explain the remote-Linux-command scenario precisely: model refusal does not test Monty;
actual prohibited code execution does. Use the fixed offline probes to demonstrate sandbox
rejection, and distinguish it from the query tool rejecting SQL before credential acquisition.
Use the recorded stages and cleanup counts, not the model's narrative, to report success.
Missing optional packages require the documented install; never fall back to exec/eval/CPython.
