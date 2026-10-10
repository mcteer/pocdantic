# Data model: Observable, repeatable security validation

Owner: maintainer. All models are strict (unknown fields rejected), versioned and immutable after
validation. Runtime objects may hold secrets privately; none of these public/event models may.
Explicit private model fields use repr=False and are never serialized by the public projection.
JSON digests use UTF-8, sorted keys and compact separators; raw-file digests hash original bytes.

## Shared constraints (normative)

| ID | Constraint |
| --- | --- |
| C01 | `schema_version` is exactly `1`; unknown fields and unsupported versions are rejected. |
| C02 | Generated identifiers are UUIDs; labels match `^[a-z][a-z0-9-]{1,63}$`; revisions/digests are 64 lowercase hexadecimal characters; all timestamps are timezone-aware UTC. |
| C03 | Select 1–32 distinct registered scenarios; mode is `offline` or `live`; scenarios execute sequentially; live interactive scenarios require `interactive=true`; `live-phone` requires exactly one explicit scenario. |
| C04 | Scenario timeout is 1–180 seconds, suite timeout 1–1800 seconds, cleanup timeout 1–30 seconds; defaults are 30 offline/150 live, 300 suite and 30 cleanup. |
| C05 | A terminal outcome is `pass`, `fail`, `blocked` or `interrupted`; safe reason codes match `^[a-z][a-z0-9_]{1,63}$` and belong to the closed contract registry; arbitrary error strings are forbidden. |
| C06 | At most 100 artifacts, 10 MiB per artifact, 64 KiB per event, depth 16, 10,000 normalized events and 100 MiB total bytes per run; reject duplicate JSON keys and invalid UTF-8. |
| C07 | Private directories use 0700 and files use 0600; reject symlinks/path escapes, existing run overwrite and concurrent writers; copies and reports use atomic finalization; output must be beneath the project .local/ root and verified Git-ignored when in a worktree. |
| C08 | Public metadata contains only opaque generated IDs, registered labels, enums, nonnegative counts/durations, safe reason codes and digests; native IDs, paths, payloads, secrets and free-form text are private. |
| C09 | Native operation IDs are private nonempty strings of at most 512 characters, scoped by source instance; imported observation windows have start <= end; identical duplicates deduplicate and conflicting duplicates fail. |
| C10 | Correlation is `matched`, `missing`, `unsupported`, `ambiguous`, `outside_window`, `incomplete_export` or `contradicted`; timestamps alone never establish a match. |
| C11 | Review decisions are `pass`, `fail`, `blocked` or `alternative`; reviewer is 1–128 characters and rationale is 1–2000 characters, both private; every review includes criterion, UTC review time and an exact evidence revision digest. |
| C12 | A report includes each of the 15 existing criteria exactly once; customer pass/alternative requires live evidence, resolved references, observation time, reviewer and an unchanged review digest. |

## Entities and relationships

### DefinitionReferenceMap

An owner-only, locked mapping assigns a generated stable UUID to each configured agent/workload
definition within this private root. Raw definition names are private keys; exports use UUIDs.
Persist it across runs without changing previously assigned IDs. C01, C02, C07 and C08 apply.


### SuiteDefinition / ScenarioDefinition

Stable suite/scenario labels, revision digests, registered factory label, allowed mode,
interactive flag, required capability labels, expected assertion labels, required evidence
source kinds and relevant criterion IDs. Descriptions are static repository text; they never
become arbitrary telemetry attributes. Catalog revision includes all scenario definitions.
Definition fields cannot contain credentials, endpoints, command strings or arbitrary imports.
C01–C04 and C08 apply. A suite contains ordered distinct scenario references.

### ValidationRun

Generated validation_id, suite label/revision, mode, selected scenario labels, private non-secret
configuration fingerprint, created_at/completed_at (completed_at nullable while running), bounds,
manifest state (`created`, `running`, `finalized`, `interrupted`) and private artifact references.
Run-to-runtime request/run IDs are distinct and linked explicitly; a validation can invoke more
than one agent request. The configuration fingerprint includes relevant non-secret definitions,
policy and adapter settings, never credential values. C01–C04, C06–C08 apply.

### ScenarioObservation / AssertionResult

Generated observation_id, validation_id, scenario label/revision, request/run references,
started_at/finished_at, expected and observed assertion labels, per-assertion outcome, safe
reason, effect-attempt count, forbidden-effect count, cleanup disposition and evidence references.
Evidence strength is `local`, `live` or `mixed` per assertion, never inferred from suite mode.
Cleanup disposition is `not_acquired`, `revoked`, `failed` or `unknown`. Negative cases require
both an attempted boundary violation and zero forbidden effects. An offline cleanup-failure
scenario may pass its expected assertion while recording cleanup=`failed` and the underlying
agent result as failed; it must never imply a successfully completed operational read.
C01–C05 and C08 apply. No model output/task/credential field exists.

### LifecycleEvent / PrivateOperationBinding

LifecycleEvent has event_id, validation/observation IDs when applicable, request_id, run_id,
nullable parent_run_id, stable opaque agent/workload definition UUIDs, phase, outcome, duration, safe reason,
nullable trace_id/span_id, opaque operation_ref and nullable opaque lease_ref/approval_ref.
Trace/span IDs use their standard 32/16 lowercase hexadecimal forms. Phase is one of
`run`, `delegation`, `policy`, `approval`, `identity`, `credential`, `database`, `cleanup`,
`telemetry` or `report`; phase detail is a registered enum, not arbitrary text. C01, C02,
C05, C06 and C08 apply. Missing parentage or a missing expected terminal event blocks lineage.

PrivateOperationBinding links operation_ref to validation/observation/run/stage, source-instance
alias and native request/transaction/lease IDs. A unique binding is recorded before each external
operation. Private bindings cannot set policy, impersonate a principal or change tool arguments.
New native fields cannot enter telemetry merely by being included in this object. C07–C09 apply.

### SourceArtifact / NormalizedSourceEvent

Generated artifact_id, source kind (`vault`, `verify`, `logfire`), private source-instance alias,
format label/version, raw digest, byte/event counts, imported_at, observation-window start/end,
completeness (`complete`, `partial`, `unknown`), provenance (`operator_export`, `transaction_response`),
private root-relative copied path and normalized events. Provider response evidence does not
become an audit export. C01, C02, C06–C09 apply. Do not persist acquisition credentials with exports.

Normalized events retain only the adapter's fixed schema: native source event/request/transaction
IDs, supported outcome, service operation, observation time and validated binding fields. Additional
native fields remain in the private raw copy and are ignored in normalization. A native unknown
format/schema is blocked, while malformed input or conflicting duplicate records fails import.

### CorrelationResult

Generated correlation_id, assertion/operation references, opaque artifact references, binding
method (registered adapter rule/version), status, safe reason and linked observed source times.
C01, C02 and C08–C10 apply. `matched` requires an exact run/operation and source-instance binding
plus consistent outcome. Unrelated records do not count as contradictions unless claimed as a
match. Missing/unsupported/ambiguous/outside-window/incomplete => blocked; contradicted or tampered
artifact => fail. Absence claims require a complete relevant export window.

### ReviewDecision / AcceptanceProjection

ReviewDecision includes generated review_id, validation_id, criterion, decision, reviewer,
rationale, reviewed_at, source observed_at, opaque evidence references and evidence_revision.
C01, C02, C07, C11 and C12 apply. The canonical revision binds suite/scenario versions, relevant
configuration fingerprint, criterion, assertions, correlation rules/results, source artifact
digests and run ID. Review text itself is excluded from that revision to avoid recursive hashing.

AcceptanceProjection preserves the existing Evidence contract and all fifteen criterion IDs.
It resolves the private review and references before constructing pass/alternative. Missing or
changed artifacts/rules/configuration invalidate an old review and return blocked (`review_stale`);
a detected digest mismatch also fails the integrity check. Explicit fail does not need a review
to block acceptance. An alternative requires reviewed live proof for the named alternative and
cannot waive a criterion's evidence requirements. Unsupported UC3/VIP/workload claims stay blocked.

### ValidationReport

Schema version, validation ID, suite revision, mode, selected/completed/terminal counts, ordered
scenario projections, correlation/delivery checks, fifteen acceptance dispositions, total duration,
limits and safe blocker codes. Public owner fields use fixed role labels (`operator`, `reviewer`),
not names from imported events. Missing-evidence instructions use fixed text from reason codes.
JSON and Markdown are two views of the same validated projection. C01–C05, C08 and C12 apply.
Private reports/reviews can resolve opaque references; public summaries never include local paths,
source instance names, raw native IDs, customer names, arbitrary rationale or hyperlinks from input.

## State transitions

Run: created -> running -> finalized; interrupted is terminal when scheduling stops abnormally.
Scenario: pending -> running -> terminal; blocked can follow preflight without a runtime call.
Forbid terminal mutation: a later report with new evidence creates a new report revision.
Delivery: disabled (offline) or attempted -> acknowledged -> received; failed/unknown outcomes
remain explicit and do not bypass database cleanup. Evidence attached later can establish receipt.
Review: recorded -> applicable or stale on each report assembly; never silently update its digest.
