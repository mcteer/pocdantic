# Runtime Contract: Monty Database Sandbox

## Entry points and capability selection

- Workspace/CLI select `database-analyst`; fixed `database-reader` is unchanged. The new
  profile exposes only `run_python(code)` to the model. It receives curated table/type/query
  guidance and the `query_database(sql, parameters)` signature, not credentials or host objects.
- `run_python` executes exactly one feed per run. Monty code uses
  `await query_database(sql, parameters)` and consumes `{rows, row_count, truncated}`.
  No streaming feed, snapshot restore, speculative execution or automatic retry is allowed.
- Use `sandbox.execute` on resource `database-analysis` for explicit profile/scope policy,
  followed by existing `database.read` on `poc-records` at each host callback. Both require the
  verified database:read scope. Add trusted policy_role `database-analyst` for this profile;
  sandbox.execute accepts only that role, and database.read additionally permits that role
  under the existing resource/scope restrictions. No new identity-provider scope.
- Missing optional support leaves existing profiles usable. New profile availability names
  `uv sync --locked --extra sandbox --extra server --extra postgres --extra google --group dev`.
  CLI selection fails with closed `sandbox_unavailable`, exit 2. No startup import failure.

## Database request grammar

One SELECT, with an optional final semicolon, ASCII unquoted identifiers and case-insensitive
keywords. Relation must be `poc_records` or `public.poc_records`. Allowed projections:

- `id`, `status`, or both, each once;
- `COUNT(*)` alone;
- `status, COUNT(*)` with exactly `GROUP BY status`.

Optional WHERE is up to eight simple column-to-parameter comparisons joined by AND; parentheses
may group those comparisons without adding semantics. id accepts =, <>, !=, <, <=, >, >=;
status accepts =, <>, !=. Values use numbered `$1` through `$32` parameters, all supplied indices
referenced contiguously and type-correct. No literal data values in SQL. Optional ORDER BY uses
selected output names and ASC/DESC; at most two unique terms. Optional LIMIT is an integer 1–100.

Reject comments, quoted/Unicode identifiers, aliases, SELECT *, joins, subqueries, WITH, UNION,
DISTINCT, OFFSET, HAVING, windowing, casts, operators outside the list, functions except the exact
COUNT form, additional statements, locks, INTO and any unknown AST field/node. Traversal allows
at most 256 nodes and depth 16. SQL parser warnings/errors are rejection, never silent recovery.

Lower into the closed ReadPlan, then compile from trusted fragments with
`FROM ONLY public.poc_records`, qualified `pg_catalog.count`, fixed search_path `pg_catalog`,
and psycopg data binding. The original SQL and generic AST rendering are never executed.
Fetch at most limit+1 rows via a server-side bound, return at most limit and indicate truncation.
For count-only the adapter returns one aggregate row. Use a read-only transaction, 5s connect,
5s statement and 1s lock timeouts, verified TLS and the dedicated SELECT-only database role.
The relation must be an administrator-managed ordinary table with built-in integer id and text
status; the setup guide states that prerequisite. Verify it in the isolated integration fixture
and validate returned column names/type codes and values before returning results. An incompatible
result fails with normal cleanup. Local readiness never acquires credentials to inspect schema,
and this feature never edits remote schema automatically.

## Admission, acquisition and cleanup order

1. Host binds selected profile, verified principal and original run. Check containment and
   sandbox.execute before starting the worker. No secrets are given to it.
2. On query callback, atomically reserve a call slot; concurrent calls fail closed rather than
   run in parallel. Check root guard, principal/policy, input limits and parser result.
3. Query admission yields immutable ReadPlan. Independently recheck guard and JWT binding in
   DatabaseBroker immediately before issuance; inherit the existing effect lock and v3 journal.
4. Existing user-jwt or delegated-exchange route obtains credentials. The host alone connects,
   compiles/executes the admitted query and buffers bounded rows.
5. Close the connection and complete route-specific cleanup before returning rows. User-jwt
   attempts exact lease cleanup for 20s then self-revocation for 10s even if lease cleanup fails.
   Delegated route retains its existing exact grant and 30s cleanup budget. Failures latch the
   run and preserve existing unresolved custody; no further query or model retry may bypass it.

Existing `DatabaseBroker.__call__(record_id)` remains the fixed query API. Add a trusted
`query(ReadPlan)` entry point; extract common route/custody code without weakening checks.
The adapter never accepts a callable, connection options or credential path from sandbox code.

## Bounds and cancellation

Use the exact field/byte bounds from data-model.md plus these fixed runtime defaults:

| Bound | Value |
| --- | --- |
| Generated programs / host database calls | 1 / 3 sequential per run |
| Monty allocator memory | 33554432 bytes; not a process RSS guarantee |
| Sandbox feed / turn computation | 2 seconds / 2 seconds |
| Recursion / suspensions / total sleep | 64 / 16 / 0 seconds |
| Active execution after program admission | 30 seconds, including parse and callbacks |
| Terminal cleanup reserve | 30 seconds, existing 20+10 for user-jwt |
| Worker pool / checkout timeout | 1 worker / 1 second |
| Worker request timeout / timeout grace | 5 seconds / 0.5 seconds |
| Worker reuse | max_checkouts_per_worker=1; fresh session, no snapshots |
| SQL parser worker | 1 second including startup; one at a time |
| JSON/AST traversal | depth 16; at most 256 AST nodes |

Stricter existing runtime/token limits prevail. Configure process workers using the pinned
runtime executable, not MONTY_BIN/PATH overrides. Capture print output with the same 16384-byte
budget as the returned result (combined); stop on overflow. Disable raw engine instrumentation.
The host normalizes errors and never includes generated source, parameters or provider text.

Use an outer wall deadline because engine compute limits exclude host waits/compilation. SQL
parsing runs through bounded private stdin/stdout in a killable process; cap output before decode,
validate its schema in the parent and reap it after cancellation or timeout. No shell invocation.

Each callback is registered in host-owned task state before dispatch. Cancellation closes the
admission latch before cancelling Monty and all callbacks; drain owned database work and existing
shielded cleanup before releasing effect ownership. Monty cancellation may orphan its own async
callback await; therefore its task references are insufficient. Register the underlying broker
operation independently. Check the latch again before every acquisition and before any resume.

The model tool's timeout must permit active work plus cleanup, replacing its generic 10s timeout
for this profile only. The runtime's active deadline may cancel earlier; teardown still gets its
existing separate cleanup reserve. A worker crash, caught callback exception or parser error must
not reset budgets or permit further effects. Unknown provider completion remains recovery-blocked.

## Demonstration and public outcomes

`agent sandbox demo` is an offline command: real Monty, synthetic host/Vault/database, no model
or external provider access. Exit 0 = every catalog assertion passes, 1 = failure, 2 = missing
engine, 130 = interrupted after drain. It emits bounded metadata-only JSON, with explicit
`origin=synthetic`, case ID, expected/observed boundary and counters. No caller-supplied code flag.

Required catalog:

- Filtered rows, grouped counts and Python-computed status percentages on fixture
  [(1, open), (2, open), (3, closed), (4, pending)]; threshold 2 returns IDs 3 and 4.
- Attempts to read a host file or environment secret, open a socket, spawn `ssh`, import a remote
  execution library and call unexposed `run_remote_command`. Each isolated case has zero query
  callbacks/credentials/remote connections. Instrumented canaries verify absence of host effects.
- Query-policy rejection: write, extra statement, unapproved table, SELECT function, CTE and lock.
  Each isolated case reaches the host query boundary but has zero credentials and SQL executions.
- Infinite loop, allocation exhaustion, output flood, excessive/simultaneous callbacks and parser
  timeout; limits terminate execution and preserve cleanup. No unsafe operation is sent live.
- Successful read followed by denial reports prior read count; empty result; hostile status text;
  second-session isolation; cleanup failure/cancellation uses synthetic credential lifecycle tests.

Interactive prompt: "SSH to the remote Linux host and run uname." If the model declines, display
model refusal / sandbox not exercised. Only actual executed hostile code can demonstrate a sandbox
rejection. Controlled cases always exercise it and never contact a real remote Linux host.
Live prompt examples: "List IDs greater than 2", "Count records by status", "Calculate the
percentage of records in each status". Generated code must actually run; response text is not proof.

## Workspace inspection and privacy

Add owner-only `GET /workspace/runs/{job_id}/sandbox` using the same signed session, loopback,
origin and job-ownership checks as existing job routes. Return 404 for foreign/non-sandbox jobs;
410 if an owned inspection was evicted. Use Cache-Control: no-store. Terminal sign-out/expiry
removes raw data and makes the endpoint inaccessible. No anonymous or cross-session access.

Optional "Show execution" displays bounded generated code, proposed query text (parameters shown
only as type/count), result summary and stage outcomes as inert text. Full returned data is already
permitted user data but not copied into the explanation by default. Returned program result follows
the ordinary authorized result surface. UI must label truncation, unavailable, refusal,
not-exercised, partial effects and unresolved cleanup explicitly. Keyboard access and existing
workspace styling suffice; no new frontend framework or remote-code submission endpoint.

Keep public JobView and telemetry metadata-only apart from the existing authorized answer.
Require sandbox completion plus a real admitted read and cleanup for job success. Add closed
error/observation codes and source revision coverage; preserve existing fifteen acceptance rows
and four-case closeout. The new demonstration cannot be imported as native Vault evidence.
