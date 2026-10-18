# Implementation Plan: Model Gateway and Credential Guardrails

**Feature**: `014-gateway-guardrails` | **Date**: 2026-10-18 | **Spec**: [spec.md](spec.md)
**Workspace branch at planning**: `ops/supabase-keepalive`; no branch switch or commit performed.
Spec Kit reports the feature slug as its logical branch from the ignored local pointer.

## Summary

Add explicit Gateway model routing, credential-block handling, exact-model admission, remote
spend configuration and metadata-only visibility to the existing CLI/workspace. New live setup
selects Gateway; existing operators must explicitly choose legacy direct mode or migrate.
Use the locked SDK's native providers with an owned hardened HTTP client, an attempt capability,
and a small private control-review record. Remote configuration stays an administrator runbook.

All five stories can be tested with synthetic transports. Protected private use requires their
combined controls plus reviewed live evidence. Passing local software tests is not activation.
See [research](research.md), [data model](data-model.md), [runtime contract](contracts/runtime.md),
[administrator contract](contracts/administration.md) and [quickstart](quickstart.md).

## Technical Context

**Language/Version**: Python 3.12+, existing plain JavaScript/CSS workspace.
**Primary Dependencies**: Pydantic AI Slim 2.55.0, Pydantic Settings, existing provider extras;
explicit `httpx2>=2.13.1,<3` declaration for the already locked model transport dependency.
Existing `httpx` identity/Vault adapters remain separate. No new framework or Gateway extra.
**Storage**: Existing private deployment root; owner-only `.local/gateway/` control reviews,
synthetic probe evidence and bounded metadata. No credential bodies in these records.
**Testing**: pytest/asyncio, mocked native transports, existing onboarding/install matrices,
Playwright/WebKit for browser refusal/migration behavior; no live services in ordinary CI.
**Target Platform**: Existing Python CLI and loopback workspace on supported Linux/macOS.
**Project Type**: Library/runtime, CLI and local web application.
**Performance Goals**: Per-turn local admission and metadata processing p95 ≤25 ms over 1,000
synthetic attempts after warmup; no additional synchronous remote management call per turn.
Remote model latency remains bounded by the existing run deadline, not a new service SLA.
**Constraints**: No direct fallback, no automatic network retry, no raw content telemetry,
no automatic remote administration, no new tool authority, no clearing recovery/enrollment.
**Scale/Scope**: Four native model protocols, two database profiles, existing parent/child and
workspace concurrency bounds, one approved hosted endpoint/provider per deployment initially.

## Constitution Check

| Principle | Before research | After design | Design evidence |
| --- | --- | --- | --- |
| I. Reusable slim runtime | Pass | Pass | Existing provider extras; explicit dependency already transitive; no separate proxy/DLP framework. |
| II. Trusted security boundaries | Pass | Pass | Model selection/review stay operator-controlled; Gateway never grants tool authority; exact model admission. |
| III. Secret isolation | Pass | Pass | Transport-only key, closed headers/errors, existing content-free telemetry, remote privacy activation gate. |
| IV. Evidence before acceptance | Pass | Pass | Fixed synthetic probes; dated private live evidence and review; no conversion of legacy acceptance IDs. |
| V. Bounded observable execution | Pass | Pass | One send per attempt, existing limits, per-turn context, cancellation/cleanup and unknown-cost states. |
| VI. Reproducible delivery | Pass | Pass | Dependency/license review, lockfile, negative tests, artifact installs and documented migration. |

No constitutional exception is requested. Artifact review is complete; maintainer implementation
and merge decisions are separate. No hooks are configured in `.specify/extensions.yml` (absent).

## Project Structure

```text
specs/014-gateway-guardrails/
  spec.md, plan.md, research.md, data-model.md, quickstart.md
  tasks.md, validation.md, acceptance.json, checklists/
  contracts/runtime.md, contracts/administration.md
src/agent/
  gateway/                         # new small trusted model-use boundary
    __init__.py, models.py, config.py, transport.py
    capability.py, review.py, probes.py, commands.py
  model_config.py, settings.py      # descriptors and explicit secret injection
  runtime.py, cli.py, api.py        # central selection and owned client lifecycle
  capabilities.py                  # child context and every-turn containment
  observability.py, telemetry.py    # closed per-attempt metadata
  setup/{commands,models,prerequisites,readiness,guidance,recipes}.py
  workspace/{app,runs,models}.py, workspace/static/app.js
  validation/{context,models}.py   # bind changed routing to private validation context
scripts/check_onboarding.py
scripts/publish_policy.py           # only exact private-artifact recognition if needed
config/                            # no tenant/Gateway credential material
```

Tests add `test_gateway_{configuration,transport,controls,privacy,review,probes}.py`,
`tests/browser/test_workspace_gateway.py`, and extend existing runtime/setup/telemetry/install
coverage. `docs/adr/` records this model boundary; public instructions update README, setup,
configuration, usage, CONTRIBUTING, AGENTS and `.env.example`. Existing unrelated staged work
must be preserved and not folded into this feature's commits.

## Phase 0 — Research decisions

Research R1–R8 resolves SDK choice, protocol compatibility, credential coverage, cost semantics,
privacy, retries, review binding and dependencies. Google GLA does not silently become Vertex;
an explicit Gateway model/protocol is required. Vendor block error schemas and retention details
are live proof obligations with a safe generic fallback, not invented APIs or implementation gaps.

## Phase 1 — Architecture and contracts

### Configuration, migration and model construction

Add `MODEL_MODE` (`gateway` or `direct`, absent requires live operator selection),
`GATEWAY_REGION`, `GATEWAY_ROUTE`, `GATEWAY_API_KEY`, and `GATEWAY_MODELS`. Keep `MODEL` as the
exact protocol-qualified model. Short names are canonical; the official
`LOGFIRE_GATEWAY_API_KEY` is a documented credential alias with process-environment precedence.
Reject conflicting nonempty process aliases; never consult PAIG or provider keys implicitly.
Do not export private-file keys into process environment.

New setup templates choose Gateway and require explicit supported model selection; no remote
model availability is invented. Preserve direct descriptor aliases/custom-provider behavior only
under explicit `MODEL_MODE=direct`, with visible unprotected status. A missing mode on an enrolled
installation yields migration guidance before any effect. Fresh live preparation rejects direct
mode while recovery/response enrollment is absent; direct mode cannot initialize a new deployment. Offline fixed models bypass live
configuration entirely. Caller-supplied live Model objects must pass the same central admission;
only fixed trusted synthetic entry points/test doubles have a non-live path.

Centralize construction at `Runtime`, with CLI/workspace sharing one admitted factory result.
Use native `gateway_provider` with explicit settings and owned `httpx2.AsyncClient`. OpenAI Chat
and Responses retain distinct classes; Anthropic stays native; Google uses explicit cloud/Vertex
selection. Transport and provider imports remain lazy; fail with closed missing-extra errors.
The Runtime owns closure after work/cancellation; CLI finally, API hosts and workspace lifespan
await it. Include delegated-run context in `capabilities.py` and all public construction paths.

### Wire boundary and failure behavior

A final request boundary enforces HTTPS hosted region, exact approved route/protocol path,
no redirects, no environment proxy/TLS configuration and a finite timeout within the run deadline.
Construct the destination from reviewed components; accept no arbitrary base URL. At final send,
replace auth with the dedicated Gateway bearer, strip provider keys, ambient organization/project
headers, custom-header environment effects and arbitrary trace baggage; use a closed header set.
SDK defaults can read custom headers despite explicit key injection, so this is essential.

Disable SDK/transport retries and enforce at most one model HTTP send per logical attempt to
cover library-internal compatibility retries. A new legitimate model turn after a successful
tool result is a new attempt. Denials and uncertain transport failures are terminal; never
raise `ModelRetry` or route them to a model. The trusted boundary converts error bodies to bounded
closed codes before SDK instrumentation sees them; non-reviewed signatures are generic, not
mislabelled guardrail or budget results. Streaming is not introduced; reject unsupported payloads.

### Per-turn control and observation

Use the locked `AbstractCapability.wrap_model_request` hook with `RunContext.deps` to bind
attempt/run/parent/definition IDs. Keep per-attempt state in context-local storage, never a mutable
shared provider field. Before every turn, validate model allowlist, current review, root and
existing run bounds; create the local attempt-start record before dispatch. Transport invokes
the same one-send guard. On completion, record tokens, duration and documented cost if available;
otherwise cost is unknown. Do not invent a price table or derive spend authority from estimates.

Extend the existing allowlisted telemetry path rather than enabling SDK global instrumentation.
Audit storage failure prevents a new dispatch; exporter failure records degraded visibility and
cannot prevent cleanup. Gateway Include messages stays off; verified metadata-only diagnostics may coexist with application
agent traces, without counting Gateway representations again as application attempts. Local metadata and remote
spending analytics meet visibility needs. No prompts, tool content, matched strings, headers or
raw remote IDs appear in public events. Private joins may retain bounded native request IDs.

### Control review and acceptance bootstrap

`agent gateway status` is read-only. `agent gateway probe` dispatches only named fixed synthetic
cases through the same hardened adapter without enabling arbitrary runtime work; this breaks
the otherwise circular requirement to prove controls before activating the workspace. It needs
explicit operational authorization and produces owner-only private evidence. No prompt argument,
file-input body, tool execution or normal-run review bypass is exposed.

`agent gateway review` records an explicit operator decision bound to exact private evidence and
configuration. Approval requires verified routing, blocking coverage and content-free telemetry. Explicit
`operator-owned` administration leaves spending and internal-service retention unverified and
operator-managed; it omits spend amounts. Legacy `reviewed` scope additionally requires the
spending control and SpendControl evidence. Unknown required controls still block approval. Rejection needs only safe local storage and reviewer
identity; it must disable subsequent dispatch even when evidence/configuration is missing or stale. It expires within 24 hours, binds implementation and
credential revision, and is read atomically at launch and before each attempt. It is operator
attestation, not cryptographic remote-policy proof. Admin-reported drift invalidates it immediately;
remote changes that the operator does not report may remain undetected within the review window.

Private evidence is never staged. Reuse private-file/root/digest patterns without changing the
15 legacy evidence criteria. New Gateway acceptance items live in this feature's validation
record and private review schema. Public `acceptance.json` retains all 15 legacy blockers.

### Compatibility and migration

New live configurations require Gateway. Existing live configurations without `MODEL_MODE`
fail early with instructions to explicitly retain direct mode or migrate. Preserve `.env.local`
bytes during checks; do not auto-edit an existing file. Switching model transport alone does not
change recovery credential-target identity, so do not add model fields to the recovery digest
and force unrelated re-enrollment. Add Gateway routing/review identity to validation context;
if the operator also changes identity/database targets, use the existing recovery migration.
Outstanding holds and cleanup always take precedence. Rollback to direct mode is a deliberate
operator configuration action, never a recovery fallback, and makes the lack of Gateway protection
visible before further work.

### Security boundary review

| Threat | Control | Remaining limit |
| --- | --- | --- |
| Ambient headers/keys redirect or change authentication | Explicit destination, final auth/header allowlist, no env/proxy/redirects | Trusted OS/operator still controls executable/configuration. |
| Secret in later message or tool result | Independent adapter isolation; Gateway Block; per-surface canaries | Opaque/encoded/unknown patterns outside documented coverage. |
| Budget or guardrail bypass by retry/fallback | Single send, terminal failures, one remote provider, model allowlist | Remote behavior requires evidence; billing caps can overshoot. |
| Data leaked into telemetry/errors | Allowlisted metadata and early error normalization; remote privacy review | Service retention cannot be proved by local toggles. |
| Stale/forged protection status | Private digest-bound expiring review and operator change control | No continuous remote attestation or hostile-admin resistance. |
| Denial after a tool effect or cancellation | Existing deterministic authority, cleanup finally blocks, no replay | Unknown remote billing remains unknown. |

## Phase 2 — Requirements review and tasks handoff

Review requirements/security checklists, generate dependency-ordered story tasks, then perform
read-only cross-artifact analysis. Implementation is a subsequent user-triggered phase. Live
acceptance tasks stay unchecked if accounts, authorization, vendor features or evidence are absent.

## Validation strategy

Synthetic constructor/wire matrices cover all four protocols and malicious ambient inputs;
end-to-end fake runs cover both profiles, child runs and post-tool turns. Exercise blocked,
auth/budget/access/rate-limit/generic failures, unsupported payloads, concurrent turns, cancellation,
post-send uncertainty, cleanup failure, stale review and exporter/storage failure. Capture every
public surface for private canaries. Test fresh Gateway setup, explicit direct migration, offline
rehearsal, locked wheel/sdist installs and names-only guidance. Benchmark local admission.

Run applicable gates in `.github/workflows/ci.yml`, including security regression, browser WebKit,
onboarding/install/platform matrices and distribution privacy after implementation. This planning
change requires artifact/link/publication checks only. See [validation.md](validation.md) for
truthful current status and the future software/live acceptance matrix.
