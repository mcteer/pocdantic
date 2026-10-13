# Agent Bootstrap Contract for AGENTS.md

**Status**: Implemented in PR #17 and incorporated into the maintained AGENTS.md/setup runbook.
This contract records the bootstrap requirements; the maintained documents are the operator entry point.

## Purpose and two distinct operating modes

1. **Implement requested feature**: select `specs/013-repeatable-poc-workflow` explicitly, read
   spec/plan/contracts/tasks and the constitution, resolve critical analysis findings, implement
   unchecked software tasks, run the applicable gates, update documentation and report remaining
   live limitations. Never mark a live/colleague/review task complete from synthetic execution.
2. **Set up an already implemented PoC**: use the workflow below. Do not alter maintained source,
   profiles or authentication policy to make an installation pass. The base variables configure
   an existing compatible deployment; they do not authorize building remote infrastructure.

A request ending at planning does not activate either implementation or live setup. The original planning
session ended after analysis; implementation was subsequently authorized and merged.

## Recipe and base-input contract

Ask for the intended recipe only if the user's request does not establish it. A generic request
to get the live PoC running selects workspace-read; a Monty/query request selects workspace-analysis;
an offline preview selects offline. Preserve an existing installation's explicit auth route.
Fresh live baseline uses user-jwt. Do not set delegated-exchange installations to user-jwt silently.

Base settings are supplied as process environment variables or in owner-only .env.local, never
in chat, command-line flags or generated tracked files. Check presence/source without printing
values. Never run `env`, `printenv`, shell tracing or a configuration dump to diagnose setup.
Use the existing short names and alias/source precedence.

| Category | Required for fresh live baseline | Owner/default |
| --- | --- | --- |
| Route | DATABASE_AUTH_MODE | user-jwt, selected explicitly for a new deployment |
| Provider selection | OAUTH_PROVIDER | generic for the portable baseline |
| Identity | OAUTH_DISCOVERY_URL, OAUTH_ISSUER, OAUTH_AUDIENCE | Identity administrator; audience is not assumed to equal login client |
| Browser | LOGIN_CLIENT_ID, LOGIN_CLIENT_SECRET, LOGIN_SCOPES | Identity administrator; scopes include openid and database:read |
| Vault | VAULT_ADDR, VAULT_JWT_AUTH_ROLE | Vault administrator; JWT mount defaults to jwt |
| Database | DATABASE_HOST, DATABASE_NAME | Database administrator; port defaults to 5432 |
| Credential target | VAULT_DATABASE_MOUNT, VAULT_DATABASE_ROLE when not using defaults | Vault administrator; defaults database/poc-readonly, not proof these resources exist |
| Model | Selected provider key: GOOGLE_API_KEY, OPENAI_API_KEY or ANTHROPIC_API_KEY | Operator/model administrator; MODEL must match the selected provider; preserve documented Google default |
| Conditional trust | OAUTH_CA_FILE, VAULT_CA_FILE, DATABASE_SSLROOTCERT, OAUTH_TRUSTED_HOSTS | Respective administrators; verified TLS, no wildcard trust or bypass |
| Conditional deployment | VAULT_NAMESPACE, OAUTH_ACCESS_TOKEN_TYP | Vault/identity administrators; preserve actual provider values |

Offline needs none of these. Model selection changes only model configuration, not provider
permissions. For existing delegated-exchange setups, also require the existing documented actor/
client/audience prerequisites; derive their exact names from the shared recipe checker, not a
second hand-maintained validator. No baseline VAULT_TOKEN, Verify admin credential, saved
BEARER_TOKEN, denied token or phone authenticator is required just to sign in through the browser.
CLI allow/deny validation has separate private token prerequisites and effects.

## Deterministic bootstrap procedure

### 1. Inspect without changing deployment context

- Read AGENTS.md, docs/setup.md and docs/configuration.md. Establish repository/deployment root,
  Python 3.12+, uv and required Git root-discovery tooling. Check installed commands without
  printing environment values. Do not reinstall tools unnecessarily; request a missing system
  prerequisite if installing it exceeds the granted scope.
- Determine fresh versus existing .env.local/.local from existence and safe status, not secret
  contents. Preserve all existing files, route selections, policy drafts and incident state.
- Use a separate checkout/worktree and private configuration for an independent deployment.
  Never copy or clear .local, move an enrolled project to evade a hold, or share one journal.

### 2. Install the complete selected extras set

Use the committed lockfile. Operator setup needs no dev/test extras:

```sh
# Offline baseline
uv sync --locked --no-dev
# Google fixed-reader baseline (substitute openai or anthropic only when selected)
uv sync --locked --no-dev --extra server --extra postgres --extra google
# Google analysis baseline
uv sync --locked --no-dev --extra server --extra postgres --extra google --extra sandbox
```

Each sync includes the complete selected set, because a later sync can remove omitted extras.
Do not use unpinned pip installs, --all-extras, or an optional provider fallback. Build an artifact
with `uv build` only when packaging/build output is requested; workspace setup does not need a
wheel rebuild. Implementation validation uses the separate full development/browser matrix.

Run commands against that already-synchronized environment (`uv run --no-sync agent ...`) so
subsequent commands cannot silently change optional-package selection. Smoke runs need no key:

```sh
uv run --no-sync agent demo
# Analysis recipe only; requires real Monty, not a simulated replacement:
uv run --no-sync agent sandbox demo
```

A failed offline smoke check is a software/dependency blocker, not a reason to request live secrets.

### 3. Collect only genuinely missing input

- If no private configuration exists and the user is using a file, use the existing
  `agent setup init --mode user-jwt` once. The generated template must not clobber supplied values.
  If sufficient variables are already exported, a file is not mandatory; do not create a
  duplicate source merely to satisfy a checklist.
- Run `agent setup guide --recipe SELECTED --format json` and `agent setup check --recipe SELECTED`
  with the literal selected recipe. SELECTED is explanatory notation, not text to execute.
- Apply mechanical dependency repairs within authorization; missing provider/client/CA/role values
  belong to the named administrator. Have the user enter secrets directly outside the conversation.
- Name conflicting sources/settings without printing values. Do not silently unset exported
  settings or overwrite an existing .env.local to prefer a different deployment.

### 4. Public network checks and safe local enrollment

- For a live setup request, execute the existing explicit `setup check --recipe SELECTED --network`
  within that authorization; explain it reads public metadata/seal status and checks TCP only.
  An unreachable provider is an administrator/network handoff, not permission to change grants.
- Use the guide's available versus after-prerequisites distinction. Only wholly absent recovery
  state permits `agent recover init`. Partial/unsafe/busy/blocked/mismatched state needs existing
  status/repair. A nonzero check exit alone is not evidence that init is safe.
- If recovery is ready and policy is wholly absent, run `agent respond init --prepare` once.
  Present the actual local-only policy's security choices for review without exposing private
  context selectors: local-only intake, no sources, no remote control authority, automatic
  provider cleanup false. Keep its generated context/definition/issuer unchanged.
- Run `agent respond init` only after actual explicit review of that unchanged policy. Existing
  valid enrollment skips this step. Reuse an already supplied review/authorization; do not solicit
  it again unnecessarily. A generated template, a key or a recipe setting is not policy approval.
- Recheck local readiness. Treat 2 as input/dependency repair and 3 as enrollment/recovery/review
  work, then branch by specific findings. Never reset journals or manufacture cleanup receipts.

### 5. Launch and verify the requested result

- Launch `agent workspace` using the selected installed environment. Keep the process under the
  harness's available process/session ownership, not an untracked duplicate daemon. If the harness
  cannot retain a foreground server, give the exact terminal command and say it is not yet running.
- Return the actual listening loopback URL and exact callback printed by the process. If the port
  is unavailable, choose another only with the matching registered callback; do not claim callback
  registration or silently change the provider. Do not treat printing the URL as proof of readiness;
  verify the local server responds without exposing session data.
- If authorized browser assistance is available, use Playwright/WebKit. Direct the user to Sign in,
  specify the expected return to the workspace, and pause for human authentication when needed.
  Do not request, paste or export login cookies/tokens. Do not log browser traces into Git.
- Fixed read: select database-reader and request record 1. Analysis: select database-analyst and
  use a supported query such as count by status. Verify observed execution and exact cleanup;
  the model narrative alone is not evidence. Never resubmit an uncertain job as a diagnostic.
- For an explicitly requested CLI allow/deny demonstration, use docs/setup.md's fixed live-portability
  commands only when the two private tokens are supplied and effects are authorized. Absence of
  a denied token blocks that check, not browser setup. No automatic phone prompt or admin fallback.
- Inspect `agent recover status`. Sign-in, allowed read, intentional denial, credential cleanup
  and optional provider acceptance are distinct milestones.

### 6. Bounded repair and final report

A local non-effectful check may be retried once after an actual input/package repair. If the same
unrepaired failure recurs, stop with its code, owner and exact next action. New user-supplied inputs
can begin another check cycle. Never automatically retry credential issuance, reads with uncertain
outcomes, provider effects, policy enrollment races or destructive actions.

Finish with:

- Selected recipe/authentication route and installed extras, without secret or tenant values.
- Software build/smoke/check results actually observed, including skipped/unavailable checks.
- Actual workspace URL/callback and whether its process is running.
- Separate sign-in, read, denial and cleanup dispositions; no inferred success.
- Concrete remaining user/administrator action, expected result and recheck command.
- Explicit optional/native feature limitations and private evidence location category only.

No further permission request is needed for already authorized local setup actions. New remote
administration, destructive changes, missing policy review and actual human sign-in are explicit
boundaries, not permission loops or failures to automate.

## Documentation acceptance

AGENTS.md must contain the concise base-variable contract, recipe/install selection, state/exit
branching, authorization boundaries and final-report requirements, with links to fuller examples.
Add automated assertions that its referenced commands/flags/settings exist and agree with the
compiled catalog. A scripted fresh and repeat walkthrough must exercise these steps without
undocumented source edits. Actual colleague timings remain a separate observed acceptance check.
