# ADR 0004: Bounded validation with private, explicitly reviewed evidence

Status: Implemented software; live and delivery gates remain separate. Owner: maintainer.

Repeated manual demonstrations did not provide uniform operational assertions, safe native
telemetry, source correlation or evidence-bound customer reviews. A fixed packaged scenario
catalog now drives sequential deterministic offline factories and separately selected live
adapters through existing runtime/capabilities. Catalog data cannot execute code or supply
customer credentials. No new dependency, frontend, service or database is introduced.

Strict typed metadata is separate from private operation bindings and source bytes. Owner-only
ignored storage rejects traversal, symlinks, overwrites, concurrent writers and bounded-input
violations. Atomic report revisions preserve earlier views; unfinished runs recover interrupted
results without repeating effects. Negative tests require attempted forbidden boundaries and zero
forbidden effects. Expected cleanup-failure assertions preserve the failed underlying operation.
Repeated cancellation shields lease cleanup under its own bounded deadline.

Injected public OpenTelemetry wrappers filter native spans before SDK storage and export.
A single explicitly configured OTLP pipeline uses a fixed resource/scope and no-op metrics;
o global Logfire configuration or ambient exporter is used. Content flags remain defense in
depth. Export acknowledgment is distinct from remote receipt. A private expected project alias
and exact exported trace/span/run lineage bind receipt imports. The transport refuses redirects,
ambient proxies/credentials and partial rejection, and emits no upstream diagnostic content.

Versioned native parsers copy original bytes privately and normalize fixed fields. Vault uses
request/response IDs and audited opaque correlation headers. Lease HMAC comparisons without a
supported shared audit-device context remain blocked. Verify event and correlation IDs are not
assumed to equal phone transaction IDs. Verified transaction responses remain separate from
Events audit exports. Native exports and manifest aliases are operator provenance, not signed
proof of source authenticity; reviewers inspect them independently.

All fifteen existing evidence criteria remain compatible. Local proof cannot become customer
pass/alternative. Supported live references and explicit private reviews bind canonical revisions;
changed evidence invalidates decisions. Unsupported UC3, VIP, workload and OAuth actor-audit
claims remain blocked. No command mutates tracked acceptance snapshots or publishes artifacts.

Existing CLI commands, Runtime.run, Audit.events and broker string observers remain usable.
Hosts that previously relied on configure_telemetry mutating global Logfire must inject its
returned telemetry object into Runtime and flush/shutdown it. Additional native source mappings
require a separately reviewed versioned adapter, negative tests and live observations.
