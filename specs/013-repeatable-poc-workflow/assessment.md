# Assessment: Is this optimized for easily repeatable PoCs?

**Reviewed**: 2026-10-12, source revision `719e0dc`.
**Verdict**: Strong reusable and security-conscious foundation; not yet optimized for low-friction,
repeatable operator/agent setup. Repeating deterministic software tests is much more mature than
repeating a fresh live deployment. Improve the existing setup surface, not the trusted runtime.

## What already works well

- `uv.lock`, optional extras and a slim base make dependency installation reproducible without
  requiring every integration (`pyproject.toml`, `.github/workflows/ci.yml`).
- Real offline entry points, nine synthetic validation scenarios, negative-boundary tests and
  WebKit coverage provide rehearsal and regression tools, not merely architecture documents.
- `docs/setup.md` and feature 011 supply a generic OIDC/user-JWT baseline, an administrator
  worksheet, non-overwriting private configuration and explicit public-only network checks.
- Recovery/response ownership, exact cleanup, context fingerprints and honest evidence distinctions
  make repetition safer. These are assets to preserve, not obstacles to remove with a reset button.
- Monty has deterministic no-provider probes, while model refusal, SQL rejection and actual sandbox
  rejection are correctly distinguished in the setup documentation.
- `AGENTS.md` already tells a coding agent to carry out setup, preserve state and stop for real
  administrator/human requirements. It needs a more mechanically executable decision procedure.

## Findings and recommended order

| Priority | Finding and evidence | Consequence | Recommended work |
| --- | --- | --- | --- |
| P0 | `src/agent/cli.py:execute` constructs `Settings()` before its demo branch; the later `Settings(_env_file=None)` still reads process environment | A supposedly offline rehearsal fails because of unrelated live configuration | Isolate demo settings and definitions before any live loading; test real CLI entry points |
| P0 | `src/agent/setup/readiness.py:local_check` checks psycopg but not server/model packages or the workspace's narrower timeout; workspace has a separate prerequisite function | Setup can report success although workspace cannot launch | Share prerequisite definitions; verify the selected recipe before launch |
| P1 | Model keys are specially handled only for Google in `Settings`, `selected_model` and setup; OpenAI/Anthropic are documented optional providers | Private-file versus shell-export behavior differs by provider; missing credentials may be found late | Explicit supported model descriptors and consistent trusted credential loading |
| P1 | Fresh setup requires init, local/network checks, recovery init, policy preparation/review/enrollment, another check and workspace launch | Repeat users and agents must reconstruct which commands are safe now | Read-only recipe/state-aware guide with exact next actions and effects; keep review gates |
| P1 | Settings/setup use current directory; recovery/validation resolve Git project root (`settings.py`, `setup/commands.py`, `validation/store.py:project_root`) | Subdirectory use can select one configuration and another journal | Fail fast for mixed roots before private reads/writes; test checkout/worktree/wheel behavior |
| P1 | `AGENTS.md` has prose steps, but no single base-input/recipe/exit-state contract | A harness must infer dependency selection and recovery branching and may repeatedly ask questions | Explicit autonomous bootstrap algorithm, bounded repair attempts and exact handoff/report contract |
| P1 | `docs/usage.md` database sections still describe delegated exchange as the universal route and say some subsequently implemented features are absent; configuration login notes universally say to retain actor credentials | Readers following different documentation paths get conflicting baseline instructions | Make setup the canonical short path; label route-specific/optional guidance and test links/contracts |
| P1 | Feature 011 T028/T029 remain unchecked: distinct live deployments and an unfamiliar colleague's measured repeat setups | Portable/repeatable software is not evidence that real users can repeat the PoC easily | Complete those existing external checks, add a warm-repeat measurement and retain honest blockers |
| P2 / follow-on | `compose.yaml` is PostgreSQL-only, uses global project name `pocdantic-lab` and fixed port 55432; `local_lab.py` retains data and reuses a CA for 30 days | Not a complete local baseline; copies can contend for the same Docker resources; expiry is manual | Separately scope isolated lab identities, expiry/status handling and an opt-in full reference stack |
| P2 / follow-on | `scripts/provision_database.py` expects `SUPABASE_DB_URI` and existing Vault; setup still needs multiple administrators | Fresh end-to-end live PoCs are not self-contained | Review provider-specific declarative provisioning packs separately, with narrowly scoped apply/destroy authorization |

P0 means fix before relying on a repeatable rehearsal/preflight claim, not a newly discovered
credential exploit. The provider-key and working-directory findings above are source-inspection
findings, not claims of executed live failures.

## Checks actually performed

Using the existing Python 3.12 environment, without installing anything or opening live services:

- 62 focused setup/portability/OIDC/Vault/recovery tests passed in 2.29 seconds.
- Real `agent demo` dispatch from a temporary directory succeeded with a clean environment.
- The same dispatch with synthetic `TIMEOUT_SECONDS=not-a-number` failed, exit 1, both as an
  environment variable and in a temporary `.env.local`. Only the closed error code was emitted.
- With isolated synthetic enrollment, `local_check` returned exit 0 for timeout 200 while
  `workspace.prerequisites` reported `TIMEOUT_SECONDS` missing/invalid.
- With isolated synthetic enrollment and server-package discovery simulated absent, setup still
  returned exit 0 and no missing settings. This is a mocked missing-dependency probe, not an
  installation test proving every absent-package behavior.

An initial temporary-store probe was rejected because the operating system temporary-directory
alias was not canonical; rerunning with the canonical temporary path produced the observations
above. No security check was bypassed or changed.

No real `.env.local` values or private evidence were displayed. No workspace was started, no
provider was contacted/provisioned, no human login occurred and no remote database read was made.
The full application suite was not rerun for this planning-only assessment. Historical validation
records are useful context, not fresh validation results.

## What not to build first

Do not add a broad `reset`, copy `.local/` between deployments, automatically accept policies,
replace existing evidence/cleanup stores, or turn a green preflight into a support claim.
Do not require Docker for the offline preview or ordinary baseline. A full local identity/Vault
stack would be useful, but carries image/license, TLS, bootstrap authority, fixture lifecycle and
platform costs. Deliver the smaller high-confidence workflow first, then use measured setup
friction to decide whether that separate project is worthwhile.

## Delivery slices

1. **Reliable rehearsal and truthful preflight**: offline isolation and shared recipe prerequisites.
2. **Safe repeat workflow**: state-aware guidance and unambiguous deployment roots.
3. **Agent-first bootstrap and public runbook**: base-variable contract, deterministic decisions,
   unattended authorized local work and explicit review/sign-in handoffs.
4. **Proof**: subprocess/install/walkthrough regression, full software gates, then authorized
   two-provider and colleague measurements. None of the live checks is automatically authorized
   by this planning request.

The detailed [plan](plan.md), [contract](contracts/runtime.md), [agent bootstrap contract](contracts/agent-bootstrap.md)
and [tasks](tasks.md) are the handoff to the implementation model.
