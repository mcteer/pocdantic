# Research and Decisions: Repeatable PoC Workflow

Source inspection and synthetic probes at revision `719e0dc` are summarized in
[assessment.md](assessment.md). No live provider research or provisioning was necessary for this
workflow-only design. This feature adds no dependencies and does not assert new vendor support.

## R1 — Optimize the existing setup surface

**Decision**: Add a compiled recipe catalog and a read-only `agent setup guide`; make existing
`setup check` recipe-aware. Do not add a separate `poc` CLI, command executor, session database or
all-purpose bootstrap script. AGENTS.md orchestrates existing explicit commands.

**Rationale**: `setup/commands.py`, `setup/readiness.py`, recovery/response commands and workspace
already provide the effects. The missing layer is prerequisite coverage and safe next-step selection.
A harness can execute reviewed commands itself without giving runtime code shell authority.

**Alternatives**: A one-command provisioning wizard hides policy acceptance and provider effects;
a Makefile alone cannot classify recovery states; prose-only changes do not fix false-green checks.

## R2 — Make offline construction hermetic

**Decision**: Dispatch offline demo before loading live Settings, use a dedicated validated
synthetic settings factory that bypasses dotenv and process-environment sources, and load fixed
bundled/default synthetic definitions rather than ambient PROFILES_FILE. Apply the same invariant
to offline recipe checks; preserve validation's existing independent offline runner.

**Rationale**: `cli.execute` currently reads live configuration first. `_env_file=None` alone does
not disable environment input. The two failing CLI probes establish this concretely. Use explicit
validated defaults rather than globally mutating os.environ or bypassing boundary validation.

**Alternatives**: Swallowing Settings errors conceals real live errors. Clearing all environment
variables in process disrupts callers. Requiring users to move .env.local defeats repeatability.

## R3 — A shared, non-effectful prerequisite matrix

**Decision**: Define common recipe/provider prerequisites in small setup modules consumed by
setup checks and workspace admission. The model descriptor recognizes Google `google-gla:`,
OpenAI `openai:`/`openai-chat:`/`openai-responses:`, and Anthropic `anthropic:` for guided setup.
Use the locked Pydantic AI provider implementations, preserving each OpenAI model kind. Validate
these prefixes against the installed locked resolver during implementation, with contract tests.
Unknown provider strings retain legacy direct-runtime resolution but are explicitly unsupported
by guided readiness. Do not reject unrelated profiles globally because sandbox is absent.

**Rationale**: `workspace.app.prerequisites` already enforces constraints not present in setup.
`Settings`/`selected_model` explicitly plumb only Google's key; the other keys must be read and
passed consistently when supplied in .env.local. Missing-package inspection must not import a
provider in a way that constructs a model, opens a connection or exposes an exception.

**Alternatives**: Importing every provider defeats slim optional installs; attempting a paid model
request during local readiness changes its security/effect contract; claiming support for every
Pydantic AI backend would require an unbounded credential matrix.

## R4 — Guide, do not auto-approve

**Decision**: Guide observes existing state and returns compiled action identifiers, owners,
effects, prerequisites and safe commands. It never runs them. Existing setup/recover/respond
commands remain the only preparation/enrollment effect surfaces. A harness performs authorized
local steps, presents the response policy and pauses for actual review before enrollment.

**Rationale**: Existing stores pin policy/context and fail closed; reimplementation creates drift.
`ResponseStore.read()` failure must not automatically be interpreted as absence. Use explicit
status classification, distinguishing missing, prepared, busy, damaged, held and mismatched state.
No generic retry of an effect and no invented policy-review receipt.

**Alternatives**: Automatic enrollment after generating a policy violates the reviewed setup
boundary. A new apply/resume journal duplicates recovery and creates a new source of authority.

## R5 — Keep one deployment per directory, reject ambiguity

**Decision**: Preserve independent checkout/worktree deployment isolation. Add a small common
root precondition for CLI paths that load private configuration or default private stores. In a
Git working tree, current directory must be its top level. Outside Git, the explicitly chosen
current directory remains the deployment directory. Inability to establish the root safely is
an error, not a fallback that bypasses an existing journal. Do not relocate any files or change
stored fingerprints. Exempt truly configuration-free commands such as help, demo, sandbox demo
and validation list. Offline validation that writes evidence still uses its existing private store.

**Rationale**: Settings use cwd while recovery/validation use `git rev-parse --show-toplevel`.
Fail-fast is smaller and safer than introducing environment-switching state roots across all
subsystems. A wheel outside Git needs coverage, but no source checkout is required for runtime.

**Alternatives**: Automatically chdir upward can silently select a different environment; an
`ENVIRONMENT` variable routing .local among roots is an extensive custody/migration project;
copying state to a fresh path is never a repair.

## R6 — AGENTS.md is the operational entry point

**Decision**: Replace/extend its existing setup subsection with a concise deterministic procedure
and base-variable table, linking to docs/setup.md and docs/configuration.md for details. Include
a distinct implementer handoff versus user setup flow, complete locked-extra selection, bounded
repair loops, policy/sign-in pauses and the final evidence-aware report. Put the detailed draft
in [contracts/agent-bootstrap.md](contracts/agent-bootstrap.md) for implementation.

**Rationale**: The user's explicit follow-up asks for autonomous agent-harness bootstrap. A
recipe guide alone is not sufficient if the agent does not know when it may act. Existing
AGENTS.md already establishes local setup authorization and forbids remote changes; preserve it.

**Alternatives**: A separate hidden agent skill would not reliably load in other harnesses.
Duplicating all configuration docs in AGENTS.md would make drift worse. Environment secrets or
admin tokens in prompts are forbidden, not alternative configuration mechanisms.

## R7 — Validate the entry point, not just helper functions

**Decision**: Add subprocess tests and clean wheel/sdist smoke checks with synthetic environment,
network denial and temporary directories. Test install matrices without provider extras and with
each selected extra. Add a scripted walkthrough based on compiled guidance, plus actual colleague
validation separately. Store generated artifacts using existing private evidence locations.

**Rationale**: Existing focused tests pass (62), while real CLI probes fail; unit coverage alone
misses dispatch order and dotenv/environment interactions. CI currently has targeted base/sandbox
jobs but not a full onboarding/install matrix. No live resources are needed for software proof.

**Alternatives**: Counting documentation commands is not a usability measurement; synthetic
success does not close feature 011's T028/T029; mock browser sessions do not prove live sign-in.

## R8 — Defer a full local provider stack

**Decision**: Keep PostgreSQL fixture limitations explicit; do not expand this implementation into
a Keycloak/Vault/PostgreSQL provisioning platform. List it as a later measured optimization.

**Rationale**: Current Compose has a shared project name and port, retained data and expiring TLS;
adding two providers would require image/license review, TLS/bootstrap authority, isolated
ownership and teardown design. No such administration is authorized by this planning request.

**Alternatives**: Destructive lab reset as the recommended repeat path risks losing evidence.
Vendor-specific provisioning defaults would reduce the baseline's portability.

## Clarification disposition

All design unknowns have bounded decisions above. Actual administrator settings, licensed native
features, colleague participation and provider waiting times remain external validation inputs,
not unspecified software behavior. No constitution exception is requested.
