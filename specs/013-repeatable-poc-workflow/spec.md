# Feature Specification: Repeatable PoC Workflow

**Feature**: `013-repeatable-poc-workflow`
**Created**: 2026-10-12
**Status**: Planned; implementation not authorized in this planning session
**Input**: Assess whether the repository is optimized for easily repeatable PoCs, plan improvements for another model to implement, and include AGENTS.md instructions so an agent harness can build and prepare the PoC autonomously from base environment variables.

## Clarifications

### Session 2026-10-12

Structured scan completed with zero questions: functional scope, domain/state, interaction,
nonfunctional bounds, integrations, failure handling, constraints, terminology, completion
and placeholders are clear. Platform/package mechanics and report schemas belong in the plan.
No critical ambiguities detected worth formal clarification. No user answers are invented.

The user explicitly requests planning, not code changes. The follow-up requires an agent-facing
bootstrap contract, not merely a human setup guide. Reasonable defaults are recorded below;
no additional user answers are needed to prepare this plan. Configuration is not authorization
to administer remote services or erase enrollment. Autonomous means completing every authorized,
mechanically verifiable local step, with precise handoffs for genuinely human/administrator steps.

This feature builds on 011 portability and 012 sandboxing, rather than replacing their trust,
authentication, recovery or evidence systems. See [assessment](assessment.md) for the findings.

## User Scenarios & Testing

### User Story 1 — Rehearse reliably without live configuration (Priority: P1)

A presenter runs the offline demonstration before a meeting, including on a machine that has
incomplete or invalid live configuration. The same synthetic behavior works without contacting
providers or modifying the presenter's live state.

**Independent Test**: Execute the installed offline entry points repeatedly with clean and
poisoned configuration, denied network access and private-state canaries.

**Acceptance Scenarios**:
1. Given invalid live settings in a private file or environment, when the offline demo runs,
   then it completes with the same synthetic outcome as a clean run and does not load live authority.
2. Given no optional provider packages, when the basic demo runs, then it still works; requesting
   the optional sandbox demo without its package produces an exact install instruction.
3. Given existing enrollment and evidence, when an offline rehearsal runs, then enrollment is
   unchanged; any offline validation artifacts remain separately labelled synthetic.

### User Story 2 — Prepare only the selected demonstration (Priority: P1)

A presenter chooses an offline rehearsal, a signed-in fixed database read, or sandboxed database
analysis, then receives the prerequisites and next actions for that demonstration only.

**Independent Test**: A fixture matrix exercises missing packages/settings, invalid trust,
selected profiles, provider keys, workspace limits, enrollment and optional sandbox availability.

**Acceptance Scenarios**:
1. Given a missing server/model/database package, wrong workspace limit or missing selected
   model credential, when readiness runs, then it identifies the exact repair before launch.
2. Given basic database-read prerequisites, when that recipe is selected, then absent sandbox,
   phone, delegated exchange, remediation and audit capabilities do not block the baseline.
3. Given a supported non-default model integration configured privately, when the workspace
   launches, then it uses that configured credential without requiring a duplicate shell export.
4. Given a custom model integration outside the guided support matrix, when guidance runs,
   then it reports its limitation without declaring readiness or breaking legacy direct execution.

### User Story 3 — Repeat safely on an existing or separate deployment (Priority: P1)

A presenter resumes an existing PoC without clearing state, or prepares a second deployment in
an independent working directory, with clear instructions for first enrollment versus repair.

**Independent Test**: Exercise absent, prepared, enrolled, busy, blocked, damaged and
configuration-mismatched installations; repeat preparation and compare original files/state.

**Acceptance Scenarios**:
1. Given an existing private configuration and clear enrollment, when setup is repeated, then
   it skips creation/enrollment and points to readiness and launch, preserving configuration.
2. Given unresolved cleanup or context mismatch, when setup repeats, then it gives the original
   recovery procedure and never suggests reset, reinitialization or replay as a shortcut.
3. Given commands launched in a repository subdirectory, when configuration and journal roots
   could differ, then the workflow stops before reading private configuration or writing state
   and asks the operator to run from the deployment root.
4. Given two independent deployments, when each is prepared and inspected, then their
   configuration, journals and evidence stay separate; switching does not copy credentials/state.

### User Story 4 — Let an agent harness perform the mechanical setup (Priority: P1)

An operator supplies base settings privately and asks an agent to build and start a selected PoC.
The agent reads AGENTS.md, installs the locked prerequisites, diagnoses readiness, performs
explicitly authorized local preparation, and verifies the outcome without inventing success.

**Independent Test**: A fresh-checkout walkthrough driven solely by AGENTS.md and the public
setup guide completes the software steps with synthetic service boundaries. A real colleague
separately repeats the live procedure and records human/administrator waits.

**Acceptance Scenarios**:
1. Given sufficient base settings and authorized local setup, when a harness follows AGENTS.md,
   then it selects the recipe, installs all required extras together, runs the offline smoke check,
   inspects readiness, prepares absent state and reaches launch or a concrete review/sign-in gate.
2. Given missing settings, when the agent reports a blocker, then it asks only for missing names,
   identifies the supplying administrator and tells the user to enter secrets outside chat.
3. Given already reviewed/enrolled local policy and successful checks, when setup is requested,
   then the agent starts the workspace, returns the actual loopback URL and callback, and
   continues verification after human sign-in without repeatedly requesting setup permission.
4. Given an unavailable capability, unresolved incident or failed cleanup, when the agent
   finishes, then it distinguishes build success, reachable services, sign-in, allowed read,
   intentional denial and confirmed cleanup; no partial result is labelled end-to-end success.

### Edge Cases

- Invalid unrelated live settings affecting an offline command; ambient telemetry/proxy credentials.
- Missing optional extras, invalid selected model key, empty secret wrappers, unsupported model prefix.
- A later locked sync unintentionally removing extras required by the selected recipe.
- Different current-directory and Git-root resolution; installed wheel outside a Git checkout.
- Existing environment variables overriding a private file; aliases; conflicting old/new targets.
- Unsafe private-file permissions/links, partial enrollment, outstanding attempts, active owners.
- Changed profiles/trust/provider/database target; expired sign-in or unavailable optional support.
- Busy loopback port and callback mismatch; model refusal versus actual sandbox execution.
- Denial-token unavailability, network failure and uncertain issuance or cleanup.

## Requirements

### Functional Requirements

- **FR-001**: Offline demonstration entry points MUST ignore live configuration files and live
  environment settings, use fixed synthetic definitions, avoid provider/telemetry dispatch and
  leave live enrollment unchanged. Preserve the existing separate offline validation evidence.
- **FR-002**: Provide three bounded demonstration recipes: offline rehearsal, signed-in fixed
  database read, and signed-in sandbox analysis. Each MUST identify dependencies, setting names,
  execution effects, expected results and cleanup requirements; never accept arbitrary commands.
- **FR-003**: Guided readiness MUST cover every local launch prerequisite for the selected
  supported recipe, including optional packages, model credential source, workspace limits,
  profile capabilities and trust. It MUST distinguish local readiness, public reachability and
  demonstrated support. Existing direct custom-provider execution remains compatible.
- **FR-004**: Provide read-only, ordered next-action guidance derived from current configuration,
  recipe and actual enrollment state. Differentiate first setup, policy preparation/review,
  clear reuse, active ownership, repair and migration; do not generate misleading init actions.
- **FR-005**: Repeated preparation MUST preserve existing configuration and journals. Guided
  commands MUST prevent mixed configuration/state roots. Independent deployments use independent
  directories; no automatic state copying, context switching, journal relocation or destructive reset.
- **FR-006**: Preserve verified identity, deterministic authorization, exact cleanup, cancellation,
  replay protection and evidence/context binding. Convenience MUST NOT supply operator fallback,
  silently downgrade authentication, approve policy or replay uncertain effects.
- **FR-007**: AGENTS.md MUST define an executable agent bootstrap procedure from base environment
  variables, including supported defaults, minimal per-recipe settings, precedence, install/build
  steps, finite repair/recheck behavior, review/sign-in handoffs, launch and outcome reporting.
  Agents MUST reuse valid supplied settings and authorization, never request secrets in chat.
- **FR-008**: Add regression tests for the actual command-line onboarding path in clean and
  poisoned environments, repeated invocations, isolated deployments and installed artifacts.
  Ordinary tests MUST use synthetic boundaries without live provider mutations or phone prompts.
- **FR-009**: Reports and instructions MUST contain only bounded, sanitized setting names,
  closed reason/action identifiers and safe command recipes. No credential values, raw provider
  bodies, customer targets or native handles enter public summaries or tracked artifacts.
- **FR-010**: Preserve existing CLI names, aliases, authentication defaults and setup JSON/exit
  contracts. Public guides MUST agree on supported routes, optional capabilities and safe reuse.
  Document the deliberate fail-fast change for ambiguous working directories.
- **FR-011**: Record software repeatability separately from real deployment/colleague acceptance.
  Reuse 011's outstanding two-provider and colleague checks; do not mark them complete from
  fixtures or duplicate them as newly passed claims.

### Key Entities

- **Demo Recipe**: Reviewed demonstration scope with fixed prerequisites and safe steps.
- **Prerequisite Finding**: Missing/invalid input or unsupported capability and its responsible owner.
- **Setup Guidance**: Read-only observation and ordered next actions, not execution authority.
- **Deployment State**: Existing enrollment/recovery observations, not a new source of truth.
- **Walkthrough Measurement**: Actual elapsed time, excluded waits and demonstrated outcomes,
  with private raw evidence and a sanitized reviewed summary.

## Success Criteria

- **SC-001**: Ten consecutive offline rehearsals produce the expected synthetic outcome with
  zero provider calls and zero live-enrollment changes; each completes within 30 seconds after installation.
- **SC-002**: Every case in the documented prerequisite matrix identifies its exact repair before
  workspace launch; no known missing local launch prerequisite is reported as ready.
- **SC-003**: Three repeated setup/guidance cycles preserve pre-existing private configuration
  bytes and all enrollment records; unresolved attempts never disappear or become successful.
- **SC-004**: With supplied settings and healthy, enrolled dependencies, an unfamiliar colleague
  reaches a repeat workspace session within five minutes of active local work; two fresh setups
  each take at most 30 minutes. Exclude only recorded download/provisioning/human/provider waits.
- **SC-005**: An agent following only the maintained instructions reaches either a verified launch
  or an exact actionable handoff in every scripted walkthrough case, without source edits or
  undocumented commands. No unsupervised policy acceptance or remote administration occurs.
- **SC-006**: All new privacy, negative-boundary, cancellation/replay where affected, installation
  and documentation checks pass; software success never promotes native provider acceptance.

## Assumptions and non-goals

- Baseline is the existing user-JWT OIDC/Vault/PostgreSQL route; enrolled delegated-exchange
  installations keep that explicit route and its additional prerequisites.
- Administrators have already supplied compatible identity, Vault and database resources.
  Base variables cannot conjure provider applications, grants, certificates or human sign-in.
- Google, OpenAI and Anthropic are the initial guided model integrations, using existing extras.
  Unknown/custom integrations remain available through existing advanced runtime interfaces.
- An explicit local setup request authorizes installation and documented local preparation,
  not remote policy/grant changes or automatic acceptance of a newly generated response policy.
- Linux and macOS are the tested platform target. No new Windows promise or Python dependency.
- Full local OIDC/Vault provisioning, multi-tenant state-root switching, UI redesign, general
  workflow execution engines and lab destruction are follow-on candidates, not this implementation.
- Existing closeout/evidence stores remain authoritative. No parallel lifecycle journal or
  new vendor acceptance ledger is introduced for convenience.
