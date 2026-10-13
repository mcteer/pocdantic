# Runtime Contract: Repeatable PoC Workflow

**Status**: Proposed for implementation, not commands newly available today.

## CLI additions and compatibility

```text
agent setup guide [--recipe offline|workspace-read|workspace-analysis] [--format text|json]
agent setup check [--recipe offline|workspace-read|workspace-analysis] [--network]
```

Omitted recipe means workspace-read. Guide defaults to human-readable text; `--format json`
returns SetupGuide v1 from [data-model.md](../data-model.md). Guide never executes an action,
loads a provider model, exports telemetry or changes private files. Network access is forbidden.

Existing `setup init --mode user-jwt|delegated-exchange` stays explicit and non-overwriting;
no implicit init, mode selection or overwrite is added to guide/check. Existing `setup check`
continues returning SetupReport v1 JSON with its original fields and exit meanings. Its findings
are projected from the shared checks; precise package/key repairs appear as sanitized names and
fixed instructions. No default guide output is substituted for the old check response.

- Exit 0: selected local prerequisites satisfied; not proof of sign-in or provider authority.
- Exit 2: configuration, dependency, selected-recipe limitation or root repair needed.
- Exit 3: otherwise enrollment/review/recovery repair needed. If both categories exist, 2 wins.
- Parser errors for unknown recipe/options remain nonzero and effect-free.

`offline --network` is invalid and rejected before configuration reads/network dispatch. Offline
recipe checks only offline runtime/package prerequisites, not private configuration or enrollment.
All existing aliases and advanced direct runtime/model interfaces remain available.

## Recipe prerequisite matrix

| Boundary | offline | workspace-read | workspace-analysis |
| --- | --- | --- | --- |
| Base locked environment | Required | Required | Required |
| Server extra | No | Required | Required |
| PostgreSQL extra | No | Required | Required |
| Selected supported model extra/key | No | Required | Required |
| Sandbox extra/verified worker | No | No | Required |
| OIDC login and actual scope configuration | No | Required | Required |
| Selected database authentication route/target/trust | No | Required | Required |
| Recovery and response enrollment | No | Required | Required |
| Profile | Fixed synthetic definitions | database-reader/database-read | exact database-analyst/sandbox-python |
| Workspace bounds | No | TIMEOUT_SECONDS 1–180 inclusive | Same, plus existing sandbox bounds |
| Advanced phone/remediation/governance/audit | No | Optional, never baseline blockers | Same |

Model mappings: google-gla → google/GOOGLE_API_KEY; openai, openai-chat, openai-responses →
openai/OPENAI_API_KEY; anthropic → anthropic/ANTHROPIC_API_KEY. Keys can be supplied via the
private file or environment; environment precedence is preserved. Local checks validate presence
without provider requests. Selected constructor preserves the prefix's model kind. An unknown
prefix is a guided limitation, not a ban on legacy direct use.

Identity, model and database findings remain separate so missing sandbox/database prerequisites
do not falsely declare a working sign-in path unsupported. Existing evidence freshness/context
rules in setup.demonstrated remain unchanged; guide cannot invent stronger capability support.

## State/action behavior

| Observed state | Safe next action | Forbidden shortcut |
| --- | --- | --- |
| Missing package/settings | Show exact selected extras or missing names/owner | Print values, paid provider probe, create grants |
| Wrong repository directory/root unknown | Ask to use the deployment root / repair discovery | Read another .env or relocate .local |
| Recovery wholly absent and configuration valid | Offer existing recover init | Init on partial/blocked state |
| Valid recovery, response policy wholly absent | Offer existing respond init --prepare | Replace an existing draft/policy |
| Consistent response draft exists | Present review step, then enrollment only after real review | Assume draft generation is approval |
| Clear recovery and enrolled response | Recheck, offer workspace and exact sign-in procedure | Re-enroll, migrate or clear history |
| Busy owner | Inspect current owner/status and stop preparation | Kill owner, steal lock, replay request |
| Uncertain/held/damaged/mismatch | Existing recover/respond status and documented repair | Reset/reinitialize/change context to bypass |

Preconditions are explicit: policy preparation follows valid recovery; response enrollment follows
human review of that unchanged draft; launch follows current successful prerequisite checks.
Future conditional actions are marked after-prerequisites, not immediately executable. A response
read exception is never sufficient evidence that it is safe to initialize response state.

## Working-directory boundary

For CLI operations that load private Settings or write default deployment state, establish the
root before those reads/writes. Within Git, cwd must equal that working tree's top level, including
worktrees. Outside Git, cwd is the explicit deployment root. A missing Git executable, timeout,
permission error or malformed output is not proof that a directory is outside Git: fail closed
for stateful paths when root classification is unavailable. Noncanonical/linked paths retain
existing filesystem safety constraints. Do not change stored environment fingerprints.

Config-free help, demo, sandbox demo and validation list do not require this discovery. Offline
validation still owns its existing private artifacts and cannot use an arbitrary root to evade
privacy constraints. A wheel test outside Git must prove consistent .env/default-profile/store
resolution; a wheel test inside a nested Git path must prove refusal.

## Effect, privacy and evidence boundaries

- Two-second local and thirty-second public-network budgets; existing per-call ten-second bounds.
  No uncontrolled provider import, subprocess or filesystem scan in local checks.
- No automatic package installation from runtime guide; a harness may install the fixed extras
  under the user's setup authorization using the locked runbook.
- No guide secret fields, targets, raw exception text or native handles. Root repair uses generic
  instructions rather than embedding a private absolute path in JSON.
- No writes in guide/check, including permission repair or implicit evidence regeneration.
- Existing effect commands retain lock/admission/cancellation/cleanup/replay protections.
- Allowed-read success requires independently confirmed applicable credential cleanup. A supported
  baseline does not establish actor delegation, native remediation or original closeout acceptance.

## Regression obligations

Exercise real CLI subprocess dispatch, poisoned dotenv/environment, no optional provider install,
each selected provider's private-file key, repeated init/guide/check, root mismatch/worktree/wheel,
all state/action branches, damaged stores and concurrent changes. Assert no network, no secret
output, no store writes for read-only paths, no repeated effect and no false successful cleanup.
New smoke helpers accept only reviewed case selections; never shell commands from guide output.
