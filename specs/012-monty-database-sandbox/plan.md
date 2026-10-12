# Implementation Plan: Monty Database Sandbox

**Branch**: `012-monty-database-sandbox` | **Date**: 2026-10-12 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/012-monty-database-sandbox/spec.md`

## Summary

Add an optional `database-analyst` profile that exposes `run_python(code)`. The model writes
Python containing a supported SELECT and computes over results. Real local Monty executes
that code; its sole host function `query_database(sql, parameters)` crosses a deterministic
query-policy boundary before existing Vault issuance and PostgreSQL execution. Demonstrate
permitted computation, denied remote-Linux commands and rejected SQL with distinct outcomes.

Preserve fixed-reader behavior. Generalize the trusted broker only through a typed read plan,
not arbitrary callbacks supplied by a model. Each query acquires and cleans up its own credentials.
Generated code never receives them. Full Monty and general remote execution are out of scope.

## Technical Context

**Language/Version**: Python >=3.12; initial feature matrix Python 3.12 on macOS arm64/Linux x86_64.
**Primary Dependencies**: Existing slim 2.55.0, Pydantic, httpx, psycopg; optional sandbox extra
with Monty 1.1.0 and SQLGlot 30.22.0. No AI harness or Full Monty dependency.
**Storage**: Existing private recovery journals. Bounded session memory for demonstration
source/results; metadata-only CLI demonstration output, no new raw-source persistence.
**Testing**: pytest, real Monty workers, mocked identity/Vault, isolated PostgreSQL CI service,
Playwright/WebKit, negative/cancellation/replay/privacy and existing full regression gates.
**Target Platform**: Local macOS/Linux; native package installation, no additional sandbox service.
**Project Type**: Existing Python CLI/runtime and local browser workspace.
**Performance Goals**: One generated program, at most three sequential queries, 2s computation,
30s active sandbox execution and 30s terminal cleanup; exact payload bounds in runtime contract.
**Constraints**: No ambient host authority, operator credential fallback, general SQL, persisted
sandbox snapshots, automatic provider configuration, or raw execution telemetry.
**Scale/Scope**: One active sandbox worker per local workspace/process; existing run admission
continues to bound work. Scope is the public.poc_records demo table and its approved built-in types.

## Constitution Check

Pre-research and post-design checks both pass at planning level:

- I: New engine/parser are optional extras with license/lock review tasks; existing slim runtime
  and profiles stay usable without installation.
- II: Verified principal and immutable host-bound run precede policy/query admission and every
  acquisition. Monty grants no authority. SQL input lowers to a closed plan; database grants remain.
- III: Credentials stay in trusted adapters and journals. No raw code/SQL/rows in traces or public
  evidence. Owner-scoped inspection is transient, bounded, inert and authenticated.
- IV: Real Monty tests, mocked providers, isolated PostgreSQL and reviewed live outcomes have
  distinct labels. Fifteen native acceptance records remain blocked without their own evidence.
- V: Finite budgets, separately owned callback tasks, exact cleanup and cancellation containment
  are required. Unknown issuance and cleanup preserve recovery blocks; replay is prohibited.
- VI: Spec, clarification, design, checklist, tasks and read-only analysis precede implementation.
  Source comments, dependency notices, documentation, CI and owner review are delivery tasks.

The user's generated-query request explicitly extends AGENTS.md's fixed-query convention for
one profile. T002 will update that guidance narrowly; existing fixed SQL remains unchanged.
No constitution exception is needed. Planning review is not final owner approval or live proof.

## Project Structure

### Documentation (this feature)

```text
specs/012-monty-database-sandbox/
  spec.md, plan.md, research.md, data-model.md, quickstart.md, tasks.md
  contracts/runtime.md
  checklists/requirements.md, checklists/security.md
  acceptance.json, validation.md
```

### Source Code (repository root)

```text
src/agent/sandbox/
  __init__.py       # Optional integration boundary; no eager engine imports
  models.py         # Strict private and public contracts
  sql.py            # Closed ReadPlan admission/compiler
  sql_worker.py     # Bounded isolated parser protocol
  runner.py         # Pinned worker, limits, host-task ownership and drain
  capability.py     # One model tool and authorization bridge
  demo.py           # Fixed positive/negative real-Monty probes, synthetic host
  commands.py       # agent sandbox demo CLI
src/agent/{capabilities,runtime,security,schemas,broker,vault,cli}.py
src/agent/workspace/{app,runs,models}.py
src/agent/workspace/static/{app.js,index.html,style.css}
src/agent/setup/readiness.py
src/agent/validation/models.py
config/agents.json
config/sandbox-demo.sql
scripts/{publish_policy.py,check_distribution.py}
tests/test_sandbox_{models,sql,runner,broker,privacy,demo,runtime,postgres}.py
tests/browser/test_workspace_sandbox.py
```

**Structure Decision**: Keep the interpreter, parser and host bridge in one optional package.
Reuse existing broker/recovery/workspace semantics. No separate server or general tool platform.

## Implementation phases

1. Verify the locked engine API, license and worker paths on target platforms. Add optional
   dependencies and dependency-free unavailable handling before registering the new profile.
2. Build strict data/boundary models, bounded parser worker, closed plan compiler and policy
   tests. Reject unsupported SQL before any credential request. Add actual PostgreSQL semantics
   tests to CI, using a dedicated service and synthetic tables/grants only.
3. Integrate the owned Monty worker/callback lifecycle with the two broker routes. Keep the
   30-second cleanup reserve outside cancelled active execution; do not rely on Monty's worker
   cancellation to stop host coroutines. Existing 10-second generic model tool timeout must be
   overridden for this tool so it cannot cut off cleanup; the runtime still enforces its global
   deadline. All terminal paths drain callbacks before releasing effect ownership.
4. Add the interactive profile, CLI demo and owner-scoped workspace explanation. Offline demos
   use real Monty and fake providers. Show model refusal separately from sandbox rejection.
5. Document setup and scenarios; run full gates and reviewed authorized live validation. Record
   missing human login/provider prerequisites with exact instructions, never simulated success.

## Validation strategy

Per-story tests precede integration. Every denied query fixture asserts zero credential attempts
and SQL executions. Real worker tests assert zero host callbacks for host-access probes, bounded
resource failure and fresh-session isolation. Both broker auth modes cover successful cleanup,
lease/token failure, cancellation and unknown issuance. Parser/compiler results run against a
restricted PostgreSQL role in an isolated service. WebKit verifies ownership, sign-out, inert
code display and unavailable support. Existing fixed-reader tests remain unchanged in behavior.

CI adds a Python 3.12 macOS/Linux sandbox smoke job and a Linux PostgreSQL integration job;
ordinary tests do not contact real providers. The main validate job installs the sandbox extra
and runs all required gates. Base-install regression explicitly runs without that extra.
Dependency pins and runtime binary identity are included in evidence revision inputs.

## Complexity Tracking

No constitutional violations. One additional parser worker is justified by the need to bound
untrusted parsing without blocking the workspace or leaving an unkillable thread. Its protocol
returns only a proposed closed plan, independently validated by the parent before compilation.
