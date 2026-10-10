# Research: Observable, repeatable security validation

Owner: maintainer. Reviewed: 2026-10-09. Research used current installed source and primary
provider documentation. No live service calls or configuration changes were made.
The operator reports the Logfire write token is now present in private configuration;
its validity, destination and actual trace receipt remain implementation-time checks.

## R1 — Native telemetry with an explicit export boundary

**Decision:** Retain native Pydantic AI Instrumentation with injected tracer/meter providers.
Add trusted lifecycle spans around authorization and credential handling. Use
include_content=False, include_binary_content=False and include_model_request_parameters=False.
Filter exported span names, attributes, events, links and resource metadata through an allowlist.

**Rationale:** Installed Pydantic AI 2.55.0 supports provider injection and inherits active trace
context for parent/child operations. Content flags suppress messages but do not suppress all
metadata: tool definitions/descriptions, agent descriptions, workspace metadata and some settings
can still be emitted. Existing principal_ref and any customer profile content are not safe public
attributes merely because they are metadata. Raw logfire.span can record escaping exceptions;
trusted spans use record_exception=False, set_status_on_exception=False and explicit safe codes.
Canaries cover spans, metrics, events, baggage, names, schema descriptions, resources and errors.

**Alternatives:** Broad HTTP/SQL instrumentation leaks credential or data paths; disabling all
native instrumentation loses useful Pydantic AI behavior. Neither is selected.
**Sources:** [Pydantic AI monitoring](https://pydantic.dev/docs/ai/integrations/logfire/),
[Logfire API](https://pydantic.dev/docs/logfire/api/logfire/); installed instrumentation source.

## R2 — Offline mode cannot inherit telemetry configuration

**Decision:** Base offline runs use a no-op event/telemetry sink without importing Logfire.
When testing spans with the optional extra, inject a dedicated local TracerProvider,
SimpleSpanProcessor, InMemorySpanExporter and NoOpMeterProvider. Do not call the normal
Logfire initializer in offline mode. Explicitly pass providers through parent and child agents.

**Rationale:** Installed Logfire 5.1.1 can create exporters from OTEL_EXPORTER_OTLP_* environment
variables even with send_to_logfire=False. Poisoned environment plus network-denial tests are
required. A dedicated provider prevents mutation of unrelated application-global telemetry.
**Alternatives:** Temporarily deleting environment variables is process-global and fragile;
assuming the absence of a token guarantees offline behavior is false.
**Source:** [Logfire testing API](https://pydantic.dev/docs/logfire/api/testing/) and installed
logfire/_internal/config.py.

## R3 — A supported filtered export pipeline with key-only configuration

**Decision:** Inject public OpenTelemetry TracerProvider/Tracer/Span wrappers that allowlist
names, attributes, events, status and exception metadata before forwarding to a dedicated SDK
TracerProvider. Preserve SpanContext and activate wrapped spans using public trace.use_span.
Start roots with a fresh Context, explicit Resource (not Resource.create), fixed instrumentation
scope and NoOpMeterProvider. Use a single BatchSpanProcessor and the standard OTLPSpanExporter
from the existing optional Logfire dependencies. Offline substitutes a local exporter or no-op.
No global logfire.configure call or parallel ambient exporter is allowed in this pipeline.

Use the public documented logfire.AdvancedOptions(base_url=override).generate_base_url(token)
for key-only region discovery without configuring exporters. Validate the result as HTTPS with
no userinfo/query/fragment. Unknown token-region inference is blocked, never guessed. An explicit
trusted base override remains configurable. Export to /v1/traces with the write token as
Authorization, using an explicitly configured transport without environment credentials/proxies
or credential-carrying redirects. Exporter diagnostics map to safe codes, not upstream text.

**Rationale:** Content flags are defense in depth; wrappers filter before SDK storage, batching,
local capture and wire serialization. Logfire supports direct OTLP/HTTP clients. Its configure
additional_span_processors option cannot filter the built-in exporter. No public configured
provider getter exists, and the OTel docs discourage constructing ReadableSpan copies. The public
wrapper interfaces avoid those private APIs and preserve actual native parent/child provenance.

A wrapper around export() records SpanExportResult and the opaque batch span IDs. Transport
response observation checks partial rejection as well as status; count acknowledgment only for
successful trace delivery without rejected spans. force_flush returning true is separate and
not remote receipt. Bound flush to five seconds. Required 002 receipt verification uses a private
project export; automated query collectors are deferred. A write key suffices for execution and
export. Future read support would use a separate query credential, fixed projection and limits.

**Alternatives:** Mirrored synthetic spans lose native provenance; post-export redaction is too
late; private SDK mutation is unstable; treating HTTP success as project receipt overstates proof.
**Sources:** [Logfire alternative clients](https://pydantic.dev/docs/logfire/guides/alternative-clients/),
[Logfire API](https://pydantic.dev/docs/logfire/api/logfire/),
[OpenTelemetry trace API](https://opentelemetry-python.readthedocs.io/en/latest/api/trace.html),
[OTLP exporter API](https://opentelemetry-python.readthedocs.io/en/latest/exporter/otlp/otlp.html),
[Query client](https://pydantic.dev/docs/logfire/api/query_client/),
[Query limits](https://pydantic.dev/docs/logfire/reference/query-limits/).

## R4 — Exact correlation with native exports

**Decision:** Support plain Vault JSONL, Verify Events JSON and Logfire JSON rows through
versioned adapters. Require private source-instance/project aliases and explicit export-window
completeness metadata. Copy raw bytes privately; normalize a fixed set of fields. Never fetch
URLs from imported material, extract archives or disable source hashing.

Vault pairs request and response using request.id scoped to source instance. A generated opaque
per-operation X-Correlation-Id links an empty-response revoke to the run when the audit header is
present; otherwise missing linkage remains blocked. Lease values can be HMAC protected. Compare
only within a documented audit-device context or an observed verified mapping; never equate an
ordinary SHA-256 of a local lease with a Vault HMAC. Actor/JWT/RAR audit fields are documented for
Vault 2.1.0+ and must be detected from actual exports, not assumed on all supported installations.

Verify events use response.events.events[], with id, correlationid, time, indexed_at, event_type,
service and keyed data. Event id identifies a record; correlationid identifies a provider flow.
Neither is documented as identical to the push transaction ID or a local run ID. The existing
push response does bind id and transactionData.additionalData.approval_id/action_digest: label
that transaction evidence, not proof of a linked Events audit export. Token-exchange audit
linkage stays blocked until an observed supported native mapping establishes exact identifiers.
No arbitrary operator-provided field mapping can manufacture a verified correlation.

**Rationale:** Similar times and successful application calls cannot establish vendor audit
lineage. Incomplete delayed event windows cannot prove absence. Missing HCP export availability
is a prerequisite blocker, never a reason to mutate the cluster tier or assume source evidence.
**Alternatives:** Online collectors and source admin configuration are deferred. Timestamp-only
matching and caller-asserted labels as proof are rejected.
**Sources:** [Vault audit schema](https://developer.hashicorp.com/vault/docs/audit/schema),
[Vault audit devices](https://developer.hashicorp.com/vault/docs/audit),
[HCP audit export](https://developer.hashicorp.com/vault/tutorials/get-started-hcp-vault-dedicated/manage-clusters),
[Verify event export](https://docs.verify.ibm.com/verify/docs/pulling-event-data),
[Verify event fields](https://www.ibm.com/docs/en/security-verify?topic=reports-service-events-payload).

## R5 — Preserve the existing acceptance contract

**Decision:** Keep evidence.py and the fifteen criterion IDs compatible. Add immutable artifact
and review models in validation/. A customer pass/alternative requires the existing live source,
reference, reviewer and observation-time conditions plus a valid review digest over the relevant
run, suite/scenario versions, configuration fingerprint, assertions, mappings and artifact digests.
Recompute this binding whenever assembling a report. Review remains an explicit local operator
command and does not write tracked acceptance files. Same operator/reviewer is allowed but
recorded; the system does not claim cryptographic verification of reviewer identity.

**Rationale:** Existing Evidence accepts nonempty reference strings but does not resolve their
existence or bind them to a revision. Feature 002 closes that gap without breaking 001 artifacts.
An evidence digest detects edits relative to the record; it is not a signed provenance guarantee.
**Alternatives:** Replacing all criterion IDs breaks existing evidence. Automatically promoting
observations or using alternative to bypass absent live proof violates the constitution.
**Sources:** src/agent/evidence.py, specs/001-secure-agent-runtime/acceptance.json and constitution.

## R6 — Fixed scenarios and bounded private storage

**Decision:** Package a declarative catalog that selects audited Python scenario factories.
Use deterministic models for offline effect attempts and explicit live adapters for real services.
Keep approval decision injection and provider failure injection offline. Store bounded JSON/JSONL
and fixed Markdown projections under an owner-only ignored directory, with atomic writes and
exclusive run ownership. Reject duplicate JSON keys, invalid UTF-8, nested/oversized input,
unsupported versions, symlinks and path escapes. No new dependency or database is planned.

**Rationale:** The existing runtime's typed capabilities and policy boundaries are reusable;
model wording is not an enforcement assertion. Fixed adapters minimize the trusted surface.
Partial journals survive ordinary failures; hard process termination cannot guarantee cleanup,
so residual work stays explicitly interrupted/unknown and TTL remains the existing backstop.
**Alternatives:** Arbitrary Python/SQL in suite JSON, a new orchestration service and a production
fault injector are unnecessary for the agreed scope.
