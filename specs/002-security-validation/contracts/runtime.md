# Public contracts: validation CLI and evidence

Owner: mcteer. Proposed interfaces for implementation; these commands do not yet exist.
Version 1 is additive to existing run/batch/demo/probe/push-demo/serve behavior.

## Commands

```text
pocdantic validate list [--mode offline|live]
pocdantic validate run [--suite offline-security] [--scenario ID ...]
  [--mode offline|live] [--interactive]
  [--root .local/validation] [--scenario-timeout SECONDS]
  [--suite-timeout SECONDS] [--cleanup-timeout SECONDS]
pocdantic validate import --run UUID --source vault|verify|logfire
  --input PATH --manifest PATH [--root .local/validation]
pocdantic validate report --run UUID [--root .local/validation]
pocdantic validate review --run UUID --criterion ID --decision pass|fail|blocked|alternative
  --review-file PATH [--root .local/validation]
```

Selection defaults to all scenarios in the selected suite except live-phone, which requires
exactly one explicit --scenario. Missing or multiple phone selections fail before any push. Repeated --scenario selects an ordered
subset; unknown, duplicate or mode-incompatible IDs fail before any effect. --interactive is
required for live-phone and does not supply an approval decision. Live mode requires a live
suite; offline mode cannot silently convert it. `list` makes no service calls. `report`, `import`
and `review` do not run agent scenarios, mint tokens, query providers or request phone decisions.

Resolve project root from the current Git worktree, or the current working directory outside
Git. --root must resolve beneath that project's .local/ directory, with no symlink components.
In a Git worktree, verify the destination is ignored before any write; otherwise reject it.
This applies to run/import/report/review and cannot be bypassed by an absolute path. A wheel run
outside Git uses the current directory's private .local/ root with the same ownership permissions.

`run` writes run.json, events.jsonl, report.json and report.md in a new private UUID directory.
It prints the sanitized JSON projection, not file contents from input or raw runtime output.
`report` rebuilds both report views from existing immutable observations plus currently valid
imports/reviews. Each revision has a new digest and immutable report-<digest>.json/.md files; report.json/.md
are atomically refreshed convenience copies. Prior evidence/reviews remain immutable.
`import` prints opaque artifact IDs and safe import dispositions. `review` prints a review ID
and applicable/stale status. All command exceptions use registered safe codes.

Exit precedence: 130 for interruption, 1 for observed failure/contradiction/integrity failure,
2 for invalid invocation/configuration or blocked required scenario/check, otherwise 0.
`run` success is based on selected operational assertions and enabled required telemetry checks,
not the fifteen wider customer criteria. `report` success additionally requires the explicitly
requested correlation/receipt checks declared by the selected suite. Blocked out-of-scope customer
criteria remain visible and do not turn a completed offline suite into an error. `review` returning
0 means the record was validly stored, not that all customer criteria passed.

A first or repeated interrupt stops pending scenarios, shields cleanup for at most cleanup-timeout,
marks remaining scenarios interrupted and attempts atomic report finalization. Hard process kill
or storage failure cannot guarantee finalization; later report assembly marks an unfinished
manifest interrupted without repeating effects. Each selected scenario still receives a terminal
projection. Cleanup-failure scenarios distinguish an expected test assertion from failed operation.

## Configuration and credentials

Use existing Settings and existing environment variables for live identity, model, Vault, Verify
and database. POCDANTIC_BEARER_TOKEN supplies an externally acquired user access token; no CLI
argument or report carries the token. The operator supplies a fresh token for a later run if it
expires. No dependency on chat/ or its diagnostic socket is permitted.

LOGFIRE_TOKEN enables live export with the existing optional extra. Add POCDANTIC_LOGFIRE_BASE_URL
as an optional validated HTTPS service endpoint; token-inferred region is the default. An explicit
endpoint override is an operator trust decision and must reject userinfo, query and fragment.
Do not follow redirects carrying credentials. No read token is needed for this feature's manual
receipt import. Automated Logfire/Verify/Vault collectors and arbitrary query input are deferred.

Offline construction ignores ambient .env.local, provider variables, Logfire tokens, OTEL endpoints,
OTEL_RESOURCE_ATTRIBUTES and baggage. It uses deterministic models and explicit local/no-op sinks.
Live preflight validates installed extras, required nonempty settings, human JWT and target
capability availability. Preflight issues no database lease and initiates no phone push. It does
not list or print credential values, subject IDs, endpoints or tenant/project names.

## Suite manifest (packaged, non-secret)

config/validation-suites.json contains schema_version=1 and suites with registered labels,
revision inputs, ordered scenario factory labels, modes, interactive flags, required capability
labels, expected assertions, relevant criterion IDs and required report checks. Digest is computed
from canonical manifest bytes excluding the digest field. At most 32 selections per invocation.
Unknown factory/capability names fail; no Python expressions, arbitrary paths or credential fields.

Default offline required checks are execution and local integrity. A live-database run requires
execution and cleanup; export health is required when a Logfire token is configured. Its assembled
report additionally requires remote receipt and supported Vault operation correlation. Verify
OAuth actor-audit linkage is reported separately as blocked until an observed supported mapping
exists. A live-phone report requires genuine transaction evidence and reports separate Events
audit correlation as blocked if its linkage is unavailable. No missing claim is silently omitted.

## Source import manifest (private)

schema_version=1; source_kind and supported format label/version; private source_instance alias;
window_start/window_end UTC; completeness complete|partial|unknown; provenance operator_export;
optional private audit-device context. The input file supplies native records and is copied
atomically under the run root. Caller-asserted metadata is provenance, not verified native proof.
Reject supplied claims that conflict with inspected records; reject artifacts beyond data-model
limits, symlink escapes, duplicate JSON keys, invalid UTF-8 and unsupported archive formats.

Supported native v1 inputs:

- Vault JSONL: request/response entries paired by request.id within source instance. Use an audited
  opaque X-Correlation-Id or returned request_id to link the exact private operation binding.
  Raw/HMAC lease comparisons require known compatible device context; missing metadata is blocked.
- Verify Events JSON: response.events.events[] envelope with native id, correlationid, time,
  indexed_at, event_type, service and adapter-reviewed data fields. Require an observed native
  linkage before connecting it to a push transaction or token exchange. Unknown linkage is blocked.
- Logfire JSON rows: rows exported with trace_id, span_id, parent_span_id, start_timestamp and
  attributes containing the allowlisted validation/run/scenario IDs. Private manifest identifies
  expected project. Receipt requires exact trace/run/project binding and required parent/child
  relationships; a private source alias is operator-attested until reviewer inspection.

Unknown native fields remain only in raw copies. Absence checks require complete relevant windows;
matching records can establish positive facts from partial exports if all required records exist.
The supporting time check permits at most 300 seconds of skew outside recorded operation bounds;
otherwise classify outside_window even when an identifier matches. Adapter versions define native
timestamp units before UTC normalization. Normalizers must not evaluate templates, fetch embedded URLs or echo arbitrary provider errors.

## Review-file contract (private)

schema_version=1, reviewer (1–128 characters), rationale (1–2000 characters), expected_revision
(64 lowercase hex), source observed_at UTC and selected opaque evidence references. CLI arguments
supply run/criterion/decision. reviewed_at is generated locally, never supplied as authority.
The reviewer obtains expected_revision from private report assembly. Recheck all artifact digests,
relevant observations and mappings immediately before recording; reject changes as review_stale.
A review file contains no tokens or credentials. Arbitrary text is private and escaped if rendered
for local review; the public projection uses fixed reason/role labels.

## Safe reason registry

Reason codes are a closed enum, not arbitrary strings that merely match a regex. Initial codes:
invalid_selection, prerequisite_missing, identity_expired, policy_denied, approval_invalid,
agent_run_failed, cleanup_failed, interrupted, limits_exceeded, storage_error, source_unsupported,
evidence_missing, evidence_ambiguous, evidence_outside_window, export_incomplete,
evidence_contradicted, digest_mismatch, review_stale, review_required, telemetry_export_failed,
telemetry_receipt_missing, schema_invalid, operation_uncertain, effect_not_attempted,
forbidden_effect, provider_unavailable, provider_denied, scenario_timeout, suite_timeout,
live_mode_required, interactive_required. Unknown exception/provider codes map to one of these;
raw messages do not become enum values. A passing check may omit its reason.

## Library compatibility

Existing Runtime.run, AgentResponse, Audit.events and DatabaseBroker string observer continue to
work. Optional typed sinks and private operation bindings are injected by trusted callers. Sink
errors are sanitized, never change policy decisions, and never skip cleanup. Evidence/criterion
IDs remain unchanged; extended review validation composes with evidence.py rather than weakening it.
Source namespace/lease/request identifiers never become model-visible tool arguments.
