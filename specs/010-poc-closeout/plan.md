# Implementation Plan: End-to-End PoC Closeout

**Branch**: `feature/010-poc-closeout` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)
**Input**: Function 13 and the clarified guided-execution scope.

## Summary

Add a local `agent closeout` workflow to freeze environment inventory, display existing native
execution guides, capture bounded evidence, assess all fifteen criteria, reconcile four controlled
client-count scenarios and build a private witnessed closeout package. Existing provider tools
execute live work. This command group performs no network, authentication, provisioning or effects.
Missing native capabilities produce explicit usable blocked reports rather than unfinished software.

## Technical Context

**Language/Version**: Python >=3.12, committed uv.lock.
**Primary Dependencies**: Existing Pydantic and argparse/stdlib; no new dependencies or extras.
**Storage**: Fixed ignored `.local/closeout/`, owned 0700 directories/0600 files, immutable revisions,
content-addressed private attachments, sealed core and final handoff directories.
**Testing**: pytest synthetic integration, negative/store/privacy/CLI tests; existing WebKit and full CI.
**Target Platform**: Existing macOS/Linux POSIX local operator environment.
**Project Type**: Additive installed CLI and provider-independent evidence library.
**Performance Goals**: 15 criteria + 10,000 activity records <=5 seconds pure computation; <=30 seconds
per local operation including cleanup; no network or sleep awaiting provider readiness.
**Constraints**: [data-model.md](data-model.md) C01–C20; source roots read-only; no fabricated acceptance;
no automatic changes to existing acceptance ledgers, state journals, provider settings or security controls.
**Scale/Scope**: Four stories, thirteen build items, six tests, five exit gates, fifteen criteria,
four 100-execution/subject scenarios, five signoff roles. All counts have explicit coverage mapping.

## Constitution Check

| Principle | Before research | After design |
| --- | --- | --- |
| Reusable slim runtime | Pass: reuse installed stack | Pass: additive package, no dependency/extra change |
| Trusted security boundaries | Pass: guided scope | Pass: fixed guides, no dispatch; claims cannot grant authority |
| Secret isolation | Pass: ignored private evidence | Pass: bounded imports, explicit projection/review, scanner rejection |
| Evidence before acceptance | Pass: separate proof/decision | Pass: fifteen predicates, native provenance and actual witness records |
| Bounded observable execution | Pass: local computation bounds | Pass: C04–C08 quotas, CAS revisions, seal-last, interruption tests |
| Reviewed reproducible delivery | Pass: complete planning first | Pass: requirement/task maps, full existing CI, compatibility review |

No constitutional exception requested. The boundary review checklist records requirements quality,
not completed implementation or authenticated human signoff. Implementation must retain these markers.

## Project Structure

```text
specs/010-poc-closeout/
  spec.md, plan.md, research.md, data-model.md, quickstart.md, tasks.md, acceptance.json
  contracts/runtime.md
  checklists/requirements.md, checklists/security.md
src/agent/closeout/
  __init__.py, models.py, catalog.py, store.py, sources.py, assessment.py
  counting.py, review.py, package.py, commands.py
src/agent/cli.py                         # additive registration/dispatch
src/agent/validation/closeout.py          # pure helper extraction only if needed
src/agent/validation/report.py           # preserve non-persisting reconstruction
src/agent/governance/report.py           # preserve pure assessment semantics
scripts/publish_policy.py                # reject new private shapes, no allowlist expansion
tests/closeout_support.py                # temporary synthetic fixture builders
tests/test_closeout_{models,catalog,store,sources,assessment,counting,review,package,cli,privacy,bounds}.py
README.md, docs/usage.md, CONTRIBUTING.md # short entry and complete operator instructions
```

**Structure Decision**: Reuse existing pure assessment functions through typed adapters. A separate
package avoids overloading the older four-case live closeout. The new installed package must never
import contributor-only `scripts/` modules; security regression captures are closed-schema software
summaries and cannot certify native evidence. Data-model fields and format rules are normative.

## Data flow and boundaries

1. `prepare` validates an explicit owner-only inventory and creates a new immutable dossier revision.
   It reads no `.env.local` and initializes no provider/runtime settings. `guide` uses compiled labels
   and safe local IDs only; it does not interpolate provider-selected shell arguments.
2. `capture` selects a typed local member UUID and approved fixed source root. It snapshots a bounded
   reference closure and relevant scope history with safe descriptor reads, compares before/after
   inventories, and invokes pure evaluators at the actual capture time. Zero writes to source roots.
3. `import` admits declared source formats and source profiles. Native records require original
   bytes, digests, source identity and exact selected facts; operator assertions remain operator proof.
   Imported source data never chooses commands, network targets or arbitrary Python expressions.
4. `assess` evaluates all fifteen catalog predicates independently, preserving operation/proof/review
   differences. Failed cleanup or contradictions take precedence; absent/unknown proof is blocked.
   Current and historical applicability are separate from the immutable captured outcome.
5. `experiment` fixes baseline scope/cohort before the first experiment operation; `measure` verifies
   all execution/mapping/activity records and performs scoped set reconciliation. Unknown execution
   modes, privileges and missing cohorts remain operator prerequisites, never invented runner commands.
6. `review` records criterion decisions after eligibility checks. `package` seals a core containing
   allowlisted matrix/readout/guides, reviewed attachments and the exact evidence index. Package reviews
   then bind five roles to that core digest. `handoff` creates a distinct sealed package of that core
   plus applicable attestations/final decision. No hash includes itself or mutable review records.
7. `inspect` and `report` recompute integrity/applicability without writing, touching source locks,
   retrying effects or advancing the dossier revision. Post-capture evidence updates require a new
   explicit capture/assessment/package; old failures and incomplete attempts remain inspectable.

## Evidence eligibility and timing

[The contract proof matrix](contracts/runtime.md#criterion-proof-matrix) is the source of truth.
Generic `Evidence` model validation or an existing process exit 0 never establishes eligibility.
Preserve Function 10's 300-second native observation limit when capturing; never backdate evaluation.
A frozen eligible result can support historical demonstration review with explicit historical scope.
Later current drift/contradiction prevents unqualified current acceptance and is shown in the handoff.

For UC3-04, combine correlated trigger/revocation intervals, including source uncertainty. Report
lower/upper latency bounds; the conservative upper bound must be below 1,800 seconds to prove faster
than the lower end of the stated 30–60-minute baseline. Overlapping/inverted clocks are unknown proof;
HTTP acknowledgement and worker completion are not revocation observations.

## Threat and failure analysis

| Threat/failure | Required response | Verification |
| --- | --- | --- |
| Source claims pass without native enforcement | Typed provenance and per-criterion predicates; no bypass field | forged/synthetic/operator fixtures |
| Omitted later failure or mixed environment | Include scoped history; exact environment joins; current drift | contradictory/mixed-scope captures |
| Mutable/symlink/hardlink source or package | Descriptor identity/mode/owner/link checks and final inventory match | swap/link tests before/after reads |
| Poisoned env, guide command injection | No Settings/client construction; compiled templates + validated IDs | zero-network/poisoned-env/hostile text tests |
| Review stale or impersonated label | Exact digest, explicit role attestation, documented local identity limit | stale/duplicate/conflicting reviews |
| Activity totals look plausible but cohort is false | Exact successful execution and actual mapping roster, scoped set joins | duplicate humans, overlaps, lag tests |
| Raw attachment or provider error leaks | Reject secret-bearing inputs; private originals; allowlisted output | canary checks of output, logs and handoff |
| Partial writes, capacity exhaustion, concurrency | Reserve quota, CAS under local lock, seal last, no overwrite/reset | crash/timeout/full/competing revision tests |

## Compatibility and migration

Existing `agent validate`, `respond`, `govern`, workspace and legacy CLI alias retain behavior.
Existing private records are read only; no migration or automatic rewrite is required. Unsupported
old members are recorded as blocked with a recapture action. Adding source bytes changes existing
implementation fingerprints; old live evidence may become historical. Preserve it and document the
need for a newly authorized run when current acceptance is required. New private dossier version is 1.

No new environment settings. Normal installation includes only `src/agent/closeout`; no tests,
customer documents or generated package enters wheel/sdist. Publication guard additions must reject
both renamed and damaged recognizable private shapes without adding a publishable exception.

## Delivery phases and independent checkpoints

1. Shared models/catalog/store with complete Function 13 mapping and private integrity rules.
2. US1: inventory and zero-effect guides; usable blocked dossier is the MVP.
3. US2: typed snapshots/imports, fifteen-row proof assessment, historical/current applicability.
4. US3: baseline preparation and four-scenario measured reconciliation; fixture-tested independently.
5. US4: digest-bound review, core package, five-role signoff and final handoff.
6. Documentation, privacy/distribution checks, full CI parity, sanitized implementation ledger.

Tests explicitly required by FR-021 precede behavior implementation in each story. Model/source
constraint tests must use independently constructed expected evidence, not mirror implementation.
Live provider runs and real witnessed signoff are separate follow-up actions with named owners; the
software task list requires their guides/blocker reporting, never falsely marks them performed.
