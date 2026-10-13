# Implementation Plan: Repeatable PoC Workflow

**Feature**: `013-repeatable-poc-workflow` | **Date**: 2026-10-12 | **Spec**: [spec.md](spec.md)
**Git branch during planning**: `main`; no implementation branch created or commits made.
**Input**: Assessment and the user's explicit agent-bootstrap/AGENTS.md requirement.
**Disposition**: Design and task handoff only. Wait for the user to change models and authorize implementation.

## Summary

The repository is reusable but still requires too much operator inference to repeat a PoC.
Fix the confirmed offline/configuration and preflight gaps, add a small read-only recipe guide,
make deployment-root handling unambiguous, and make AGENTS.md a tested bootstrap contract.
Reuse all existing authorization, recovery, response, workspace, validation and closeout effects.
Do not add a reset command, automatic provider provisioning or another workflow engine.

See [assessment](assessment.md) for evidence and [research](research.md) for decisions.

## Technical Context

- **Language/version**: Python 3.12+, current typed/Pydantic package; plain Markdown guidance.
- **Dependencies**: Existing Pydantic AI Slim, Pydantic Settings, optional server/postgres/model/
  sandbox packages. No dependency additions; retain committed uv.lock. Any later change requires
  explicit purpose, license review and a lock update, not an incidental bootstrap install.
- **Storage**: Existing .env.local and .local stores. Guidance is ephemeral and read-only. No new
  persistent setup database and no relocation/re-enrollment of current deployment state.
- **Testing**: pytest subprocess/unit/integration, Playwright/WebKit for affected browser behavior,
  package smoke tests, existing privacy/artifact gates and separate actual colleague measurements.
- **Platform**: Linux/macOS; source checkout/worktree and installed runtime outside Git.
- **Project type**: Installed CLI plus local browser workspace and coding-agent instructions.
- **Bounds**: Local check/guide two seconds; explicit public-network check retains ten seconds per
  call and thirty seconds overall. Bound root discovery within the local budget. At most 32
  findings and 16 action records; no arbitrary user strings in guide commands.
- **Success budgets**: Ten offline runs, each at most thirty seconds after install; three preserving
  setup cycles; actual fresh setup at most thirty minutes and warm repeat at most five minutes of
  active work with exclusions recorded, not silently subtracted.
- **Scale**: One enrolled deployment/owner per directory; three fixed recipes and three guided
  model integrations. No claim of production hosting or arbitrary provider setup coverage.

## Constitution Check

| Principle | Before research | After design |
| --- | --- | --- |
| Reusable slim runtime | Reuse existing packages/extras | No new dependency; lazy optional checks; compiled recipes only |
| Trusted security boundaries | No model authority or provider administration | Guide is not an executor; auth/policy/approval unchanged |
| Secret isolation | Existing private state must remain private | Names-only findings; keys passed only to trusted providers; no new raw report artifacts |
| Evidence before acceptance | Historical passes are not fresh live proof | Software checks separate from 011 T028/T029 and all fifteen native criteria |
| Bounded observable execution | Preserve existing cleanup/cancellation | Read-only bounded guide; no effect replay/reset or new cleanup owner |
| Reviewed reproducible delivery | Locked extras, Spec Kit and explicit handoff | Tests/tasks/contracts traced; actual maintainer review still required before merge |

No exceptions requested. Requirements-quality review is not owner approval of implemented code.
Existing policy review, human sign-in and remote administration boundaries remain hard stops.

## Project Structure

Planning artifacts under this feature: spec.md, assessment.md, research.md, data-model.md,
contracts/runtime.md, contracts/agent-bootstrap.md, quickstart.md, checklists/, tasks.md,
validation.md and the required blocked acceptance.json. Analysis is read-only and reported in the
conversation after task generation; it must not silently rewrite these artifacts.

Planned implementation locations:

```text
src/agent/
  cli.py                         offline dispatch, shared launch preconditions
  settings.py                    supported provider secrets; isolated synthetic construction
  project.py                     new bounded root precondition, not a state-root selector
  model_config.py                 new reviewed model descriptor/credential resolution
  setup/
    recipes.py                   new compiled recipe catalog
    guidance.py                  new read-only state-to-action projection
    prerequisites.py             new shared local prerequisite checks
    models.py                    strict guide/findings contracts; keep SetupReport v1
    commands.py                  guide parser + recipe-aware checks; preserve init behavior
    readiness.py                 reuse shared checks and existing demonstrated-evidence rules
  workspace/app.py                consume shared prerequisites; retain direct custom model support
AGENTS.md                        autonomous bootstrap and implementation handoff instructions
README.md                        short entry path and recipe choices
.env.example                     defaults/key names, no authority-bearing sample values
 docs/setup.md                   canonical human/agent recipe and repeat workflow
 docs/configuration.md           consistent key sourcing/aliases and route-specific instructions
 docs/usage.md                   remove conflicting baseline/optional feature statements
CONTRIBUTING.md                   targeted onboarding/install validation commands
 tests/test_offline_entrypoints.py
 tests/test_setup_recipes.py
 tests/test_setup_guidance.py
 tests/test_project_boundary.py
 tests/test_model_configuration.py
 tests/test_setup_walkthrough.py
 scripts/check_onboarding.py      compiled contributor smoke harness, not installed runtime executor
.github/workflows/ci.yml          onboarding/install matrix using existing gates
```

Names marked new are planned, not present. Reuse existing tests and stores wherever possible.
Do not edit a core store schema merely to make its state easier to display. If an existing status
method cannot distinguish a necessary state, add a read-only bounded classifier and negative tests.

## Phase 0 — Clarification and research (complete at planning)

Structured clarification found no critical unresolved question. The user explicitly requires
AGENTS.md-driven autonomy. Record the supplied-variable baseline and its review/sign-in limits
rather than claiming fully unattended remote provisioning. Research R1–R8 resolves architecture,
provider support, root behavior, compatibility and deferred lab work.

## Phase 1 — Design and contracts (complete at planning)

### A. Recipe catalog and shared prerequisites

- `offline`: basic demo plus offline validation; no model credentials, server, database or enrollment.
- `workspace-read`: current fixed read, using the configured route; guided default for fresh setup
  is explicitly user-jwt, without changing Settings' delegated-exchange compatibility default.
- `workspace-analysis`: same live baseline plus the sandbox extra and exact analyst profile.
- Each recipe carries fixed install extra names, required capabilities, command IDs, expected
  outcomes and effect labels. No shell, template evaluation or user-supplied commands.
- Setup and workspace share common launch checks. Separate identity readiness from model and
  database readiness; optional advanced features are informative, not baseline blockers.
- Preserve SetupReport v1 shape and exits 0/2/3; explicit `--recipe` chooses the checks. New guide
  output has its own schema, textual default and JSON option. Omitted recipe means workspace-read.

### B. Model configuration

- Add private SecretStr fields for OPENAI_API_KEY and ANTHROPIC_API_KEY, with documented source
  precedence consistent with existing settings. Keep GOOGLE_API_KEY behavior and aliases unchanged.
- A reviewed descriptor maps known prefixes to package probes, key names and trusted constructors.
  Do not instantiate a model or inspect raw credential contents in readiness. Preserve OpenAI chat
  versus responses selection. Unknown direct integrations retain existing runtime resolution, while
  guided recipes clearly state they cannot establish complete readiness for them.
- All configured secrets are injected into trusted provider constructors. No raw settings or native
  exception strings leave the boundary. Unrelated absent keys must not block selected providers.

### C. Offline dispatch

- Resolve `agent demo` without evaluating Settings() first. Use validated, fixed synthetic settings
  and profiles unaffected by .env.local, exported aliases, MODEL, PROFILES_FILE or telemetry values.
- Retain actual Monty isolation for sandbox demo and existing validation evidence semantics; no fake
  success when optional packages are unavailable. Use no provider package just to list help/recipes.

### D. Read-only state guidance

- Normalize observation into missing settings/packages, uninitialized recovery, policy absent/draft,
  ready, busy, held/uncertain, mismatched and storage-invalid states. Read neither private token
  contents nor raw evidence to construct instructions; reuse sanitized existing status projections.
- Action order is repair local inputs → explicit network check → absent recovery enrollment →
  absent policy preparation → human policy review → response enrollment → recheck → launch/sign-in
  → allowed/denied checks as authorized → recovery status. Skip already completed phases.
- A proposed action's future effect is not permission to execute it. Every effectful existing
  command rechecks state under its existing locks. Blocked/mismatched/damaged state offers inspection
  and repair only, never init, migration without prerequisites, launch-for-effects or automatic retry.
- No guide writes, state permission repair, provider calls, environment dumps or telemetry export.

### E. Root and reuse behavior

- Enforce the existing documented root-only working convention before private configuration loading
  in CLI operations that use deployment state. Reject nested Git directories with a safe root-repair
  instruction rather than mixing cwd config with top-level .local. Use a bounded Git query and
  distinguish “not a Git repository” from query failure. Detect linked/noncanonical roots per the
  existing safety rules. Installed usage outside Git uses the chosen cwd consistently.
- Keep current directories, context hashes and enrollments. This is not a migration or environment
  selector. Existing mismatches are repaired under their original configuration. Independent
  deployments retain separate checkouts/worktrees and never share/copied .local or .env.local.
- Environment-over-dotenv precedence remains; guide may name a setting's source/conflict but never
  print its value. It must not silently overwrite a user's shell exports to force another target.

### F. Agent-first documentation and autonomy

[contracts/agent-bootstrap.md](contracts/agent-bootstrap.md) specifies the intended AGENTS.md
procedure and minimal input matrix. Install the entire selected extras set in one locked sync;
run the rehearsal, then guide/check; create only absent configuration/state using existing commands.
Read policy before requesting review; reuse explicit prior review of unchanged policy/enrollment,
never assume a template or environment variable grants that review. Verify the real listening URL,
use WebKit when browser assistance is authorized, and pause only for genuine missing inputs.

One retry follows an actual local repair; repeating an unchanged failing check a second time ends
in a concrete handoff. No automatic live effect retries. Model implementation and local setup are
separate tasks: a setup request never authorizes source edits, and this planning session does not
start implementation. AGENTS.md must teach that distinction.

## Phase 2 — Implementation sequence (not started)

1. Review these contracts and capture regression tests for observed defects and compatibility.
2. Build small shared descriptor/root/recipe primitives with strict, bounded models.
3. Deliver US1 offline reliability independently.
4. Deliver US2 truthful prerequisites and US3 state-aware safe reuse.
5. Deliver US4 AGENTS.md/runbook bootstrap plus walkthrough/install tests.
6. Run focused and complete applicable CI; review publication and distributions.
7. With separately authorized live resources and a real colleague, complete the outstanding 011
   checks plus the warm-repeat timing; otherwise retain exact blockers and unchecked tasks.

Detailed file-level work and dependencies are in [tasks.md](tasks.md). Avoid broad CLI or store
refactors. Do not bundle follow-on container/provider administration work into this feature.

## Compatibility and migration

- Existing `agent`/`pocdantic`, environment aliases, auth defaults and setup init/check contracts stay.
- `setup init --mode` remains explicit/non-overwriting; a recipe never changes an enrolled mode.
- `setup check` remains JSON and read-only; guide is additive. Missing server/model prerequisites
  now correctly block a check instead of a later launch.
- Non-root Git invocation fails earlier: run from the deployment root; no files are moved.
- No enrollment schema migration. Profile/trust/provider changes still require existing recovery
  resolution and migration rules; guide reports rather than repairs them automatically.
- No license changes or new dependencies. No publication allowlist expansion is expected for these
  paths; verify the existing narrow rules rather than broadening them preemptively.

## Validation and handoff

Use [quickstart.md](quickstart.md) for implementation-time checks. Full CI is authoritative, including
privacy/index/history, all-feature/runtime gates, lint/format, pytest/WebKit, security regression,
offline validation/demo, package build/privacy, targeted budgets and relevant sandbox jobs.
Install smoke tests must run outside the source import path and with private canaries absent from
built artifacts. Capture only sanitized results in validation.md.

Complete a read-only consistency analysis after tasks. Critical/high design gaps must be resolved
before implementation. Owner security-boundary review remains required before merging. Planning
passes and implementation passes must be recorded separately; unexecuted tasks remain unchecked.

## Complexity Tracking

No constitution violations. Added structure is limited to shared descriptors, bounded prerequisite
checks and read-only guidance. A generalized workflow runner, state selector and local provider
stack were rejected/deferred because each adds authority/lifecycle complexity unrelated to the
confirmed first-order repeatability defects.
