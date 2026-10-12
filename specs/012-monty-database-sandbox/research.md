# Research: Monty Database Sandbox

**Date**: 2026-10-12. Research only; no dependency installation or provider operation.

## 1. Local engine and integration

**Decision**: Add optional `sandbox` extra with `pydantic-monty==1.1.0` and `sqlglot==30.22.0`. Retain `pydantic-ai-slim==2.55.0`. Use a direct
Monty adapter behind one normal model tool, rather than the separate AI harness package.

**Rationale**: Monty's metapackage pins matching client/runtime 1.1.0 packages and supports
Python >=3.10. Published wheels include macOS Intel/Apple Silicon and Linux x86_64/arm64.
The project targets Python >=3.12; feature acceptance will initially cover macOS arm64 and
Linux x86_64, Python 3.12. Other wheel availability does not imply project certification.
Monty is MIT licensed; preserve required notices and review transitive licenses. The
repository's own licensing decision remains separate.

**Alternatives**: Full Monty adds commercial service deployment beyond this PoC. The current
`pydantic-ai-harness` CodeMode integration brings broader tools and dependencies; this feature
needs only one host callback and no persistent REPL. Containerized CPython grants capabilities
outside the selected Python subset and adds deployment work.

Sources: [release](https://github.com/pydantic/monty/releases/tag/v1.1.0),
[package metadata](https://pypi.org/pypi/pydantic-monty/json),
[runtime wheels](https://pypi.org/pypi/pydantic-monty-runtime/json),
[MIT license](https://github.com/pydantic/monty/blob/v1.1.0/LICENSE),
[AI Code Mode](https://pydantic.dev/docs/ai/harness/code-mode/).

## 2. Explicit worker and host boundaries

**Decision**: Use `AsyncMonty`, a fresh checkout per run and no restored snapshots. Pin worker
resolution to the executable delivered by the locked runtime rather than trusting `MONTY_BIN`
or PATH. Expose only `query_database(sql, parameters)`; no modules, mounts, host objects,
environment or generic network callbacks. Use one pool worker and one checkout per worker.
The initial compatibility test verifies startup, async callback, denial and cancellation on
both target platforms before changing the broker.

**Rationale**: Monty confines interpreter operations. A host callback runs with host authority
and must validate its inputs independently. A generated call to an unexposed SSH/remote-command
function is denied; a model that simply refuses never exercises Monty. Controlled probes
make that distinction repeatable without contacting a remote machine.

**Alternatives**: Passing a database connection or Vault client to generated code defeats the
credential boundary. Exposing general HTTP/SSH callbacks creates precisely the authority this
demonstration is intended to exclude.

Sources: [pool API](https://pydantic.dev/docs/monty/api/python/pools/),
[security model](https://pydantic.dev/docs/monty/concepts/security/).

## 3. Bounds, cancellation and confidentiality

**Decision**: Set finite worker/checkout/request, computation, recursion, suspension, sleep,
source/input and output limits. Treat memory accounting as allocator bytes, not an RSS promise.
Use a separately owned callback registry, an outer monotonic deadline and existing credential
cleanup. Cancelling the Monty await closes the worker; the host still cancels/drains its owned
query tasks and prevents callback resumption. Do not retry a failed feed or reuse its session.

**Rationale**: Interpreter duration excludes host waits and compilation. Upstream cancellation
can leave a coroutine answering a suspension running. A worker death is not evidence that
PostgreSQL stopped or Vault cleanup completed. Configure a bounded print sink because default
printing goes to stdout/stderr. Disable raw Monty tracing; normalize errors without source lines.

**Alternatives**: Relying only on the interpreter timeout or worker termination would abandon
host work. Passing raw exceptions or enabling automatic instrumentation risks exposing code,
parameters or records. See the exact bound table and drain contract in contracts/runtime.md.

Sources: [resource limits](https://pydantic.dev/docs/monty/concepts/resource-limits/),
[pinned cancellation code](https://github.com/pydantic/monty/blob/v1.1.0/crates/monty-python/src/pool.rs),
[package telemetry documentation](https://pypi.org/project/pydantic-monty/).

## 4. Generated SQL admission

**Decision**: Parse a narrow PostgreSQL SELECT subset with optional pure-Python SQLGlot, lower
to a closed `ReadPlan`, then compile fresh SQL using trusted identifiers and psycopg parameter
binding. Never execute the original model SQL or generic AST serialization. Reject unrecognized
nodes and non-default fields, comments, aliases and all syntax outside the contract. Parsing
runs in an isolated bounded subprocess with source through private stdin, not command arguments.
Its output is untrusted until the parent validates the closed plan and rechecks policy.

**Rationale**: SQLGlot is MIT and portable, but its parser is intentionally lenient and is not
an authorization validator. A closed plan limits semantics to projections, filters and counts;
the database sees only the adapter's compiler output. Reject ambiguous syntax rather than repair
it. `FROM ONLY public.poc_records`, explicit `pg_catalog.count`, built-in column types and a
fixed search path avoid inheritance, function and operator surprises. The administrator owns
the table/grants; untrusted users cannot modify its schema, policies or functions.

**Alternatives**: Regex-only SQL screening and accepting anything starting with SELECT fail on
nested effects. pglast has closer PostgreSQL grammar but GPLv3+ requires a separate licensing
decision. Arbitrary SQL, joins and user-configurable schemas are deferred.

Sources: [SQLGlot parser caveat and API](https://sqlglot.com/sqlglot.html),
[SQLGlot license](https://github.com/tobymao/sqlglot/blob/main/LICENSE),
[release metadata](https://pypi.org/pypi/sqlglot/30.22.0/json),
[psycopg parameters](https://www.psycopg.org/psycopg3/docs/basic/params.html),
[read-only transactions](https://www.postgresql.org/docs/current/sql-set-transaction.html).

## 5. Existing integration and evidence

**Decision**: Preserve `DatabaseBroker.__call__(record_id)` and add a separate admitted-query
entry point beneath shared auth/custody helpers. Reuse both route verifiers, root guard, durable
effect ownership, lease cleanup and user-JWT native-token cleanup. Each query completes cleanup
before returning data to Monty. Unresolved cleanup halts further queries.

The model gets `run_python(code)` plus the curated schema/tool description. The analysis profile
is unavailable when dependencies are absent, while eager construction of existing profiles
must keep working. Use the existing database.read policy and an explicit sandbox.execute policy
restricted to the analysis profile. SQL validation remains mandatory because existing policy
does not inspect arbitrary query arguments.

Workspace success requires actual sandbox completion and a completed admitted database read,
not a model claim. Keep full source/results only in bounded session-owned memory for optional
inspection, purged with the session; public audit/evidence uses closed metadata. Add sandbox
modules to implementation revision hashing. Existing fifteen criteria and four-case closeout
remain unchanged. A new standalone offline demonstration reports real sandbox execution with
synthetic host/Vault behavior; an isolated PostgreSQL integration test supplies actual engine
semantics without a live identity provider.

**Alternatives**: Modifying every existing profile or repurposing native closeout evidence would
obscure what this feature proves and make the optional dependency mandatory.

Repository references: src/agent/{runtime,capabilities,security,broker,vault}.py,
src/agent/workspace/{app,runs}.py, src/agent/validation/models.py.
