# Implementation Plan: Observable, repeatable security validation

**Branch**: `feature/002-security-validation` | **Date**: 2026-10-09 | **Owner**: mcteer
**Spec**: [spec.md](spec.md)
**Status**: Design only; implementation is reserved for the next model/session.

## Summary

Add a packaged validation CLI to the existing slim harness. Execute a fixed scenario registry
through the same runtime/capabilities, collect typed metadata events, and produce private JSON
and Markdown reports. Correlate explicit private service exports with per-operation identifiers.
Keep observed execution, remote telemetry receipt and owner-reviewed customer acceptance separate.
Use the existing optional Logfire dependencies with a filtered OTLP pipeline for telemetry; no new service or frontend is needed.

## Technical Context

**Language/Version**: Python 3.12+ with the committed uv lockfile.
**Primary Dependencies**: Existing Pydantic AI Slim 2.55.0, Pydantic, HTTPX and PyJWT; optional
Logfire, model-provider and PostgreSQL extras. No planned new runtime dependency. Installed
Logfire/OpenTelemetry APIs are verified in research.md; any dependency change requires license,
purpose and lockfile review before implementation.
**Storage**: Owner-only local files under `.local/validation/`; immutable source copies, an
append-only bounded event journal, atomic reports and explicit review records. No external DB.
**Testing**: pytest/pytest-asyncio; deterministic FunctionModel and mock transports; optional
local OpenTelemetry capture; network-denial and privacy fixtures. CI has no live credentials.
**Target Platform**: Python CLI/library on macOS and Linux. No deployment issuer selected.
**Project Type**: Existing library/CLI, additive `validate` command family; no HTTP control API.
**Performance Goals**: Offline suite <=30 seconds per run in ten consecutive CI runs; report
assembly for 10,000 normalized events <=5 seconds on CI, excluding file I/O and external calls.
**Constraints**: At most 32 selected scenarios, sequential execution, scenario timeout 1–180 s
(default 30 offline/150 live), suite timeout 1–1800 s (default 300), separate cleanup budget 1–30 s
(default 30); existing request/tool/token/delegation limits remain enforced. 10 MiB/import,
10,000 normalized events/run, depth 16, 100 artifacts/run, 64 KiB/event, 100 MiB/run including copies and journals. Limits cannot be
raised beyond these bounds by configuration. No live retry after uncertain side effects.
**Scale/Scope**: A single operator, one active writer per run directory, four stories and fifteen
unchanged customer criteria. New runs use new directories. Existing host login supplies tokens.

## Constitution Check

| Principle | Pre-research / post-design result |
| --- | --- |
| I. Reusable slim runtime | PASS: existing optional extras; registry and suite configuration are tenant-neutral. |
| II. Trusted boundaries | PASS: normal verified ingress and capabilities; assertions exercise real policy/approval boundaries; fault injection is offline only. |
| III. Secret isolation | PASS: typed allowlisted events, no generic payload fields; private raw imports; public projection and canary tests. |
| IV. Evidence before acceptance | PASS: local/live provenance per assertion, exact correlation and explicit digest-bound review; unsupported fields stay blocked. |
| V. Bounded execution | PASS: fixed limits, terminal results, cleanup budget, correlation and cancellation tests. |
| VI. Reproducible delivery | PASS: deterministic CI, package/privacy gates, source-to-task traceability and migration notes. |

No constitutional exception is proposed. Requirements and boundary review is recorded in the
quality checklist and this threat analysis. Maintainer review and required branch protection
remain delivery gates before merge; implementation must verify them rather than bypass them.
No service provisioning or live phone action is authorized merely by loading a suite.

## Architecture and integration points

1. `validation/catalog.py` loads packaged `config/validation-suites.json` via explicit
   force-include, validates it with Pydantic and resolves scenario IDs against Python factories.
   Configuration cannot import code, supply URLs, SQL, credentials or approval decisions.
2. `validation/runner.py` runs selected scenarios sequentially, preflights dependencies and
   verified identity, creates a private run store and injects per-run event sinks. A failed
   prerequisite produces blocked results. After uncertain effects or interruption, skip pending
   work and complete cleanup; never automatically retry a write or credential issuance.
3. `validation/scenarios.py` uses existing Runtime/capabilities and deterministic test models.
   A selected live scenario can use the configured model, but assertions require observed tool
   attempts and effects; a model refusal is insufficient proof. Offline fixtures and faulting
   adapters remain explicit and cannot be chosen after a live failure. No imports from tests/.
4. `observability.py` introduces a typed, content-free lifecycle event and sink protocol shared
   by runtime, capabilities, broker and service adapters. Keep Audit.events and the broker's
   existing string observer compatible. Optional trusted operation-observer callbacks carry
   native IDs only into the private store; they cannot influence authorization or returned data.
   Inject the run/request identity when the runtime constructs the broker call, avoiding mutable
   module-global context or reusing a principal across independent callers.
5. `telemetry.py` turns allowlisted events into spans and associates native Pydantic AI
   Instrumentation with the same root trace. Capture policy, approval, lease and cleanup phases;
   instrument no HTTP bodies/headers or SQL queries. Inject public TracerProvider/Tracer/Span
   allowlist wrappers ahead of a dedicated SDK provider and its sole OTLP exporter; preserve
   native SpanContext and use fresh root Context, explicit Resource and NoOpMeterProvider.
   Use AdvancedOptions.generate_base_url for key-only region discovery without global SDK
   configuration. See research R3; no private provider access or post-export filtering. Safe span attributes include opaque run,
   scenario, request and parent identifiers, opaque stable definition references, phase, outcome, duration
   and safe error codes. Raw actor IDs, lease IDs, existing unsalted principal_ref, profile text,
   endpoints and arbitrary exceptions never enter the export projection. A private, locked definition
   map assigns stable opaque UUIDs to agent/workload definitions across runs; raw configured names
   remain private. Scenario labels come only from the packaged catalog. Native span/resource/event
   metadata also passes the export allowlist; content flags alone are insufficient.
6. `validation/importers.py` accepts explicit bounded private native exports, with separate
   Vault, Verify and Logfire normalizers. Imports never fetch arbitrary URLs. Preserve source
   bytes privately with SHA-256 digest; normalize only selected fields. A file's declared source
   is not proof of authenticity: retain provenance and require reviewer inspection of the source.
7. `validation/correlation.py` pairs exact native IDs through private run bindings. Vault pairs
   request/response by request.id and binds the operation using a unique X-Correlation-Id header
   where present or a returned request_id. Verify requires an adapter-reviewed observed mapping from transaction IDs to native event fields;
   no equivalence between event id, correlationid, JWT txn and transaction ID is assumed;
   Logfire uses trace/span IDs plus run/scenario fields. Timestamps are a bounded supporting
   check, never a substitute. Missing optional newer Vault metadata blocks that specific claim.
8. `validation/report.py` constructs a whitelist-only JSON/Markdown projection. `review.py`
   binds a named decision to canonical report/evidence digests. Existing evidence.py remains the
   authoritative fifteen-criterion validator; pass/alternative requires both its rules and the
   new review-binding validation. Reports never edit tracked acceptance.json automatically.

## Scenario catalog

| Suite | Scenarios | Evidence boundary |
| --- | --- | --- |
| offline-security (default) | delegated-read, policy-denial, injection-denial, approval-denied, approval-expired, approval-replay, approval-mutated, cleanup-failure, cleanup-cancelled | Local contract proof only; no network or ambient exporter. |
| live-database | delegated-database-read, actor-only-denial | Genuine token exchange and credential service; TLS DB; exact revoke. Fail if actor-only unexpectedly obtains credentials; clean up that lease explicitly with its scoped authority if available, otherwise mark cleanup failed and retain TTL backstop. No operator fallback. |
| live-phone (interactive) | phone-approved, phone-denied | Real selected human decision on simulated restart. Require exactly one explicit --scenario and --interactive; no unattended approval or replay of a live write. |

Only offline adapters simulate provider/cleanup failures. A live scenario requesting a service
operation must create its operation binding before issuing the request. A dropped connection
with unknown outcome is failed/uncertain, not safely retryable. Telemetry receipt and source
correlation are report checks attached to relevant scenario assertions; they do not redefine
an operational result as customer acceptance. Native export support is field-detected, not
assumed from product version or successful API calls.

## Execution and storage lifecycle

Resolve project root from the current Git worktree, or the current working directory when outside
Git. Require the output root to be beneath that project's .local/ directory; in a worktree verify
Git ignores it before creating files. Reject other roots, even if otherwise writable or ignored.
Create a new UUID run directory and owner-only lock atomically. Persist manifest before effects,
append bounded sanitized events, then atomically replace JSON/Markdown summaries. Reject symlink
components and paths outside the root; never overwrite a prior run. Copies retain permissions
0600/directories 0700. Readers verify digests and report versions. One writer owns each run;
concurrent writers fail with a safe code. A first/second interrupt stops scheduling and awaits
cleanup within its separate deadline; a forced process kill may leave a running manifest, which
report assembly marks interrupted without replaying effects. No automatic retention deletion.

Protect raw imports from repr/exception logging. Do not copy executable markup to Markdown;
render fixed labels and escaped validated values only. A typed event sink failure must not skip
cleanup: fail the affected validation/report claim, preserve a safe partial record when possible,
and still execute finally blocks. No logging handler receives raw imported evidence.

## Delivery phases and gates

- Foundation: strict contracts, private store, event sink and fixed catalog; negative boundary tests first.
- US1 MVP: offline runner/CLI and expected-effect assertions; live adapters behind explicit mode.
- US2: dedicated offline tracer, confidential-data-free lifecycle export and receipt verification.
- US3: private service normalizers, immutable provenance and exact correlation with explicit gaps.
- US4: acceptance projection, evidence-bound reviewer decisions and reproducible report assembly.
- Final: ten-run repeatability, two configurations, package contents, privacy/history and all-feature
  Spec Kit checks; live walkthrough with private proof or an honest recorded external blocker.

Implementation software completion requires deterministic checks. Feature live validation requires
at least one real database flow with remote trace receipt and source correlation for supported
fields, plus explicit dispositions for unavailable claims; customer acceptance still needs review.
Live phone validation is a separate interactive gate and must be reported blocked if not witnessed.
Missing access never justifies marking an unexecuted task complete; split completed software tasks
from live validation tasks. This planning turn performs no live calls or implementation.

## Project Structure

```text
specs/002-security-validation/
  spec.md, plan.md, research.md, data-model.md, quickstart.md, tasks.md
  contracts/runtime.md, checklists/requirements.md, acceptance.json
src/pocdantic/
  observability.py
  validation/{__init__,models,catalog,store,runner,scenarios,importers,correlation,report,review}.py
  cli.py, telemetry.py, runtime.py, capabilities.py, broker.py, vault.py, services.py, verify.py
  evidence.py, settings.py
config/validation-suites.json
tests/test_validation_{models,store,runner,scenarios,cli,importers,correlation,report,review}.py
tests/test_observability.py, tests/test_telemetry.py, tests/test_publication.py
```

Retain the current single package, inject optional adapters, and bundle only the non-secret
scenario catalog. New test fixtures live in Python files with synthetic identifiers. All private
outputs remain under ignored .local/. Existing run/batch/demo/serve behavior remains compatible.
No implementation code is generated by this plan.

## Complexity Tracking

No exception is needed. File-based evidence replaces a new database/server; manual read-only
imports avoid provider-admin dependencies. Optional authenticated collectors and cryptographic
review signatures can be added in later features if the operating model requires them.
