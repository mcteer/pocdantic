# Data Model: Monty Database Sandbox

All boundary records are strict, reject unknown fields/coercion and use immutable values unless
explicitly identified as host-owned lifecycle state. Runtime code cannot trust a record merely
because a worker returned it. Bounds below are normative and shared by contracts and tests.

## AnalysisRun (host-owned, private memory)

- `run_id`, `request_id`, `job_id`: host-generated UUIDs; `job_id` is optional for CLI.
- `owner`: existing verified principal/session binding; never accepted from generated code.
- `profile`: literal `database-analyst`; `source`: `synthetic` or `live` from the host.
- `state`: `admitted`, `generating`, `executing`, `draining`, `completed`, `denied`, `failed`,
  `cancelled`, or `unresolved`; transitions are host-controlled and terminal states cannot resume.
- `code`: UTF-8 text, 1–16384 bytes, private; exactly one program submission per run.
- `schema_revision`: host-derived digest of curated schema and query-policy version.
- `query_attempts`: ordered QueryObservation records, at most 3 admitted host calls; rejected
  excess/concurrent calls latch failure without adding unbounded observations.
- `deadline`: monotonic active deadline; min(30 seconds, remaining runtime/credential bound).
- `result`: JSON-compatible finite data, at most 16384 encoded bytes; optional on failure.
- `inspection`: private code/query explanation plus bounded output; at most 131072 encoded bytes
  per run, at most 10 run inspections per session; evict oldest terminal inspection only.
- Raw inspection is removed on sign-out, expiry or process exit. Ordinary metadata/history
  remains governed by existing session/recovery contracts. No sandbox snapshot serialization.

Lifecycle: admitted → generating → executing → draining → terminal. Generation may decline or
fail without execution. Every terminal path first closes admission and drains owned work.
`completed` requires real sandbox success, at least one completed query and confirmed cleanup.
Any unresolved credential takes precedence as `unresolved`; earlier reads remain counted.

## QueryRequest (untrusted)

- `sql`: UTF-8 text, 1–8192 bytes; grammar in contracts/runtime.md.
- `parameters`: ordered list, 0–32 elements; each is a strict signed 64-bit integer or UTF-8
  string of at most 1024 bytes; booleans, nulls, floats, containers and extra fields rejected.
- Encoded request: at most 16384 bytes. No identity, connection, credential, provider target,
  approval, deadline or executor field is accepted.

## ReadPlan (private, immutable)

- `relation`: literal `public.poc_records`; `kind`: `rows`, `count`, or `grouped_count`.
- `columns`: for rows, unique ordered subset of `id`, `status`, length 1–2; for count empty;
  for grouped_count literal status grouping with output columns `status`, `count`.
- `predicates`: 0–8 comparisons joined only by AND. Each comparison has `column` in id/status,
  `operator` in eq/ne/lt/le/gt/ge for id, eq/ne for status, and `parameter_index` 1–32.
  Parameter type must match the column; all provided indices must be referenced contiguously.
- `order`: 0–2 unique terms; term is an output column plus asc/desc. Count-only has no order.
- `limit`: strict integer 1–100, default 100; count-only output remains one row.
- `parameters`: validated QueryRequest values, held privately; no interpolation into SQL text.
- Trusted parent attaches run identity/admission revision outside the worker's proposed plan.
  The parent validates the plan again and compiles approved fragments; model SQL is not executable.

## QueryResult (sandbox-visible)

- `rows`: 0–100 mappings with only the selected output keys. `id` is a signed 64-bit integer;
  `status` is text up to 4096 UTF-8 bytes; `count` is an integer 0–9223372036854775807.
- Whole serialized result: at most 65536 bytes; overlarge cells or byte totals fail rather than
  returning partial misleading data. Rows beyond the requested limit set `truncated=true`.
- `truncated`: strict boolean; `row_count`: exact returned count. The program is instructed not
  to present a truncated result as the complete population.
- Rows return only after connection close and confirmed applicable credential cleanup.

## BoundaryObservation / QueryObservation (public metadata)

- `schema_version`: literal integer 1; correlation IDs supplied by host only.
- `boundary`: `model`, `sandbox`, `query_policy`, `identity`, `vault`, `database`, `cleanup`.
- `outcome`: `passed`, `denied`, `failed`, `not_attempted`, `unresolved`, `cancelled`.
- `reason`: closed reason code; no free-form upstream exception message.
- `origin`: `synthetic` or `live`; `engine`: `monty` or `not_exercised`.
- `query_attempted`, `query_admitted`, `sql_executed`, `rows_returned`, `credentials_acquired`,
  `credentials_revoked`: host-derived nonnegative counters, bounded by the run contract.
- `limit`: optional closed category `source`, `input`, `memory`, `compute`, `wall`, `output`,
  `calls`, `recursion`, `suspensions`, `sleep`, `parser`, `rows`.
- Observations: at most 32 per run. No code/SQL hashes derived from potentially secret input,
  source text, parameter values, records, stdout, identities or native credential handles.

## Existing credential custody

Reuse recovery v3 token/lease attempts, immutable configuration context and independent receipts.
One query's custody completes before the next begins. No new journal format is planned. Snapshot
loss, timeout, worker death and 403 are not proof of revocation. Do not expose custody to Monty.
