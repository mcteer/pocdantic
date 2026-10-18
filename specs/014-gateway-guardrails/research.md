# Research: Model Gateway and Credential Guardrails

**Date**: 2026-10-18. Sources are public vendor documentation and the locked local SDK;
no authenticated services, private settings, remote configuration or model calls were used.
Decisions below resolve design questions; deployment acceptance remains separate.

## R1 — Explicit controlled routing

**Decision**: Use a trusted model factory and owned transport with explicit Gateway key, hosted
region, route and native model protocol. Preserve direct mode only when explicitly selected;
new setup templates choose Gateway. No automatic provider/key/model fallback.

**Rationale**: `src/agent/model_config.py` only recognizes direct providers and passes unknown
strings to SDK inference. `Runtime.__init__` independently falls back to `settings.model`;
covering CLI construction alone would leave an alternate path. Child definitions share the
selected model today, so admission must be centralized and applied to each turn.

The pinned `pydantic-ai-slim==2.55.0` has a public `gateway_provider` factory accepting explicit
`api_key`, `base_url`, `route` and `http_client`. Its default inference/environment paths are
not admission policy. The model SDK uses `httpx2`; existing non-model project adapters use
`httpx`. Provider clients can retry by default; transport hardening alone does not disable
SDK retries. See the [Pydantic AI Gateway integration](https://pydantic.dev/docs/ai/overview/gateway/)
and installed `pydantic_ai/providers/gateway.py` under the locked environment.

**Alternatives**: Prefixing `MODEL` with `gateway/` alone is insufficient for trust, retries,
private-file key injection and unknown-provider refusal. A generic OpenAI translation for all
providers would change native tool semantics. A new proxy service adds an unnecessary boundary.

## R2 — Google is an explicit protocol migration

**Decision**: Retain native OpenAI Chat, OpenAI Responses, Anthropic Messages and Google support,
with separate reviewed descriptors. Gateway Google uses the SDK's Google cloud/Vertex route;
legacy `google-gla` continues only in direct mode. Require explicit Gateway model selection and
compatibility validation; never silently translate the enrolled GLA route or invent availability
for its current model name.

**Rationale**: The installed SDK maps `gateway/google` to Google cloud and the `google-vertex`
wire route. A matching model label does not prove equivalent transport/tool behavior.
Each protocol can be implemented and tested synthetically; only successfully reviewed protocol,
route and model combinations can be activated. Unsupported ones remain blocked.

**Alternatives**: Treating GLA and Vertex as interchangeable hides a compatibility change;
dropping Google would unnecessarily remove the project's default provider family.

## R3 — Block credentials; do not claim universal detection

**Decision**: Configure Block for a reviewed credential inventory. Use synthetic positive and
negative probes per protocol and outbound surface. No new application DLP engine, LLM judge,
Presidio service or automatic redaction/retry loop. Keep adapter secret isolation independently.

**Rationale**: [Guardrails](https://pydantic.dev/docs/logfire/manage/ai-gateway/protect-data/)
inspect requests on the way to the model. Observe/Flag forward unchanged; redaction and blocking
are distinct. Template actions vary. Public docs do not enumerate every credential recognizer
or prove every protocol field is inspected. The documented flag header proves flagging only;
it cannot establish refusal. No stable blocking response schema was found.

Freshly opened documentation says prebuilt/custom protections are Beta on every plan. Older
indexed versions still describe Growth/Enterprise Early Access. Deployment administrators must
verify actual available controls and actions; no tier purchase is assumed. Presidio is excluded.

**Alternatives**: Observe-only would not meet the goal; guessing regex coverage for arbitrary
passwords or encoded fragments creates false assurance. Gateway sees content it inspects, so it
cannot replace the application's rule against putting actual adapter credentials in requests.

## R4 — Spend is a remote, qualified control

**Decision**: Use a dedicated project-scoped deployment key, finite daily and monthly per-key
limits in whole USD, and administrator-selected organization/project limits where appropriate.
Require pricing data; use blocking, not alert-only behavior. Keep local usage and time bounds.
Do not require experimental advanced policies to use included limits.

**Rationale**: The [spending guide](https://pydantic.dev/docs/logfire/manage/ai-gateway/spending-policies/)
documents included limits, empty/unlimited and zero/block semantics. The
[SDK integration guide](https://pydantic.dev/docs/ai/overview/gateway/) explains that allowing
unpriced requests excludes them from tracking and spending limits. The
[Gateway supplemental terms](https://pydantic.dev/legal/terms-of-service-gateway) describe limits
as soft: actual costs may arrive after completion. No atomic reservation or maximum overshoot
is established. BYOK billing belongs to the upstream account; verify that selected BYOK usage
is priced and counted before accepting spend protection.

**Alternatives**: Local estimated-dollar accounting cannot enforce a shared remote budget;
prepaid balance and auto-recharge do not replace per-key limits. Advanced policy/model access
features may supplement local exact-model admission only after verified availability.

## R5 — Useful visibility without content capture

**Decision**: Retain `safe_instrumentation` and the allowlisted telemetry exporter; add bounded
attempt metadata and explicit unknown costs. Enable application agent traces with closed
`invoke_agent` semantics and fixed agent names. Allow Gateway metadata-only diagnostics with
Include messages off, subject to actual selected-service privacy verification.
Use Gateway spending analytics plus application metadata for visibility. Require administrator
review of service-side retention and pre-block logging before private-data activation.

**Rationale**: [Gateway setup](https://pydantic.dev/docs/logfire/manage/ai-gateway/)
can enable conversation traces by default. Public documentation does not establish a hosted
metadata-only configuration or logging order relative to blocking. The user-supplied inkantOS
reference (ADR 0097, inspected 2026-10-18) records a hosted Include messages setting; this is
a configuration pattern, not evidence for this deployment. Verify that setting here and keep
Gateway diagnostics separate from authoritative application attempt totals. The supplemental terms allow
prompt/output logs with a target deletion period; a telemetry toggle alone is not proof of
no service-side retention. [Logfire scrubbing](https://pydantic.dev/docs/logfire/instrument/python/scrubbing/)
is not a substitute for excluding model content. Local `include_content=False` cannot control
remote Gateway logging. This is an explicit activation dependency, not a software-test claim.

**Alternatives**: Enabling recommended setup without review could weaken existing privacy.
Exporting prompts for debugging or relying on redaction after export violates the chosen boundary.

## R6 — Safe failures and remote routing

**Decision**: Disable automatic SDK and transport retries; initial remote endpoints contain one
provider with no failover. Map only reviewed exact vendor signatures to guardrail/budget/access
categories; unknown failures remain generic safe denials or uncertain dispatch. Do not infer a
specific cause from HTTP status alone. Unknown response/error content is discarded at the trusted
transport boundary before SDK instrumentation can capture it.

**Rationale**: [Endpoint routing](https://pydantic.dev/docs/logfire/manage/ai-gateway/endpoints/)
can add provider retries/fallback remotely. Local retry suppression cannot attest to that setup.
A refusal after a tool result must not replay a database read or weaken cleanup. Cancellation and
transport loss may leave billing unknown even when application cleanup is confirmed.

**Alternatives**: Retrying on all 429/5xx, feeding failure text back to the model or parsing free
text for control reasons risks repeat spend, credential echoes or incorrect reporting.

## R7 — Review is bounded operator evidence, not remote attestation

**Decision**: Add a small private Gateway control-review record, checked at launch and before
each dispatch. It binds model/route/key revision, implementation, detector/spend/privacy evidence
and expiry. Operator review is valid for at most 24 hours and invalidated by local changes. No
remote management API or undocumented control-plane scraping is assumed.

**Rationale**: Existing validation/recovery patterns provide private storage, strict models,
canonical digests and explicit review semantics. A configuration boolean cannot prove remote
controls. Administrators must report remote changes and re-review; undetected remote drift
within the review window remains a stated limitation. Protection does not resist a hostile
operator who can edit process configuration, code or private review records.

**Alternatives**: Per-request remote policy introspection is not supported by established docs.
A permanent `guardrails_enabled=true` flag would confuse declaration with evidence. Reusing the
existing 15 external acceptance IDs for new Gateway claims would falsely close unrelated gates.

## R8 — Dependency and license decision

**Decision**: Keep Pydantic AI Slim pinned and retain provider extras. Explicit model HTTP-client
use must declare `httpx2>=2.13.1,<3` as a direct base dependency; it is already mandatory through
Pydantic AI Slim and locked to 2.13.1, so this adds no installed package or Gateway extra.
Installed metadata identifies BSD-3-Clause. Recheck license/compatibility during implementation
and update lock metadata without unrelated upgrades.
No separate Gateway SDK, Logfire CLI, full Pydantic AI package or Presidio dependency is needed.
The Logfire extra remains optional for export, not required for basic local visibility.

**Rationale**: Native model clients use a different HTTP package than existing identity/Vault
adapters; mixing them would fail at construction or bypass client controls. Existing dependency
licenses do not grant a license to this project; any new direct dependency requires the normal
license/compatibility review and reproducible artifact-install tests.

## Operational facts still requiring live evidence

These are explicit acceptance conditions with fail-closed behavior, not unresolved architecture:
actual plan entitlement; exact detector catalog/coverage and block error signatures; selected
model/protocol availability; single-provider routing/retry behavior; pricing and budget refusal
semantics including concurrency; telemetry/body-retention and pre-block logging controls; and
upstream absence of a blocked canary. Unavailable evidence keeps that acceptance item blocked.

### Trace configuration follow-up (2026-10-18)

The user explicitly requested trace data and supplied the inkantOS configuration reference.
Preserve content exclusions from this project rather than its conversation capture settings.
Export fixed service identity, closed environment labels and Pydantic semantic agent attributes;
pass the isolated provider into every host and flush after runtime drain. Real OTLP delivery
requires a valid project write token. An exporter acknowledgement does not establish queryability
or Agents dashboard presentation. A synthetic model run exported live remains synthetic model
evidence, never Gateway inference or vendor control acceptance.

### Complete inkantOS mechanism comparison

Inspected the model and skills-runner observability entry points; shared model-runtime
configuration, Gateway connection validation, tracing, middleware, accounting, usage records,
funding, content handling, scrubbing and evaluation scopes; native provider call sites; Rust
session/control-plane trace initialization and propagation; destination, agent, accounting and
egress regressions; and ADR 0097. This is reference inspection, not imported third-party code.

| Mechanism | Application here |
| --- | --- |
| Explicit credential/region and readiness bindings | Retain separately selected Gateway and Logfire authorities, native protocol/model selection and private control review; no credentials copied from the reference deployment. |
| Agent invocation identity | Preserve fixed `invoke_agent` span names, closed agent labels and generated call IDs. The served Logfire Agents reader also checks the span name; attributes alone are insufficient for the current hosted reader. |
| Parent and subagent ownership | Pydantic AI owns actual invocation scopes; runtime delegation retains parent context, independent call IDs and distinct `parent`/`ticket-reader` labels. Inactive profiles emit no invented registrations. |
| Per-attempt context and accounting | Context-local single-send admission, unique physical attempt IDs, tokens and explicit unknown cost; application attempts own accounting rather than summing ancestor/Gateway representations. |
| Native clients and external propagation | Explicit hardened owned native clients, no hidden retries/failover, no private trace owner/baggage/provider headers crossing Gateway egress. |
| Environment/service/export lifetime | Fixed service name, closed resource environment, isolated provider shared by the owning host and flush/shutdown after runtime drain. |
| Privacy and error paths | This project's stricter no-content requirement remains: no conversation capture even in dev; no raw SDK/HTTP exception, matched credential or payload export. Reference content capture and RPC-specific features are not enabled here. |
| Acceptance | Verify actual hosted agent-filter matching, separate labels and nesting, not just OTLP acknowledgement. Gateway configuration, spend and blocking still need independent live review. |

Primary hosted reader inspection corroborated the reference's `invoke_agent` naming contract.
See [Agents discovery](https://pydantic.dev/docs/logfire/observe/agents/) and
[resource/query fields](https://pydantic.dev/docs/logfire/reference/sql/).
