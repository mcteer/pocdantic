# Validation Record: Monty Database Sandbox

## Implementation and review status (2026-10-12)

The optional database-analyst profile is implemented. The requirements checklist (16/16)
and boundary/design checklist (13/13) remain planning reviews, not owner acceptance.
Generated Python runs in the actual Monty worker. Generated SQL is admitted to an immutable
plan and compiled by the trusted adapter; source SQL never reaches the driver. Credentials
remain in the existing broker and results return only after applicable confirmed cleanup.
The fixed database-reader and original native acceptance/closeout catalogs remain independent.

README, setup/configuration/usage guides, AGENTS.md and CONTRIBUTING.md describe installation,
query grammar, model refusal versus sandbox/query-policy denial, privacy and recovery.
The quickstart now describes implemented commands rather than future planning commands.

## Software verification

- macOS arm64, Python 3.12.14: pydantic-monty/client/runtime 1.1.0, SQLGlot 30.22.0,
  psycopg 3.3.6. MIT dependency notices reviewed; no project license inferred.
- Final full suite, including Playwright/WebKit: 1250 passed, 1 skipped in 191.69 seconds.
- Focused real-worker generation/runtime/WebKit tests after clarifying dictionary results:
  7 passed. Additional hostile-parser/callback-containment suite: 19 passed; resource/worker
  ownership suite: 7 passed.
- Final real Linux x86_64 worker suite in a Python 3.12 Docker image, network disabled:
  32 passed in 20.97 seconds. This is local emulation
  on an arm64 Mac; native Linux/macOS CI results are not claimed before CI executes.
- Actual isolated PostgreSQL 18 with verified TLS, four synthetic rows and a restricted
  SELECT-only role: 1 passed in 2.63 seconds. Checks include grouped/filtered semantics,
  driver built-in types, limit+1 truncation, denied DELETE and a held-lock timeout.
  The normal-suite PostgreSQL skip is intentional; no application database is discovered.
- Final separate base-install Linux test after removing the optional engine/parser:
  17 passed in 1.27 seconds.
- Offline Monty demo: all 21 real-engine assertions passed; provider rows are synthetic.
  Includes file/env/socket/SSH/process/import/reflection denial, SQL denial, resource limits
  and partial-effect/caught-denial cases. No remote command or provider credentials used.
- Both-profile security regression: all 20 cases passed. An initial concurrent formatting
  edit correctly produced content_changed; that historical failure was retained and a new
  unchanged-content run completed successfully.
- Offline validation: all 9 scenarios passed; synthetic agent demo completed.
  Targeted repeatability, normalized-event budget, readiness and closeout: 29 passed.
- All-feature and runtime configuration gates passed. Ruff lint/format and Git whitespace
  checks passed. Build produced wheel and source distribution; distribution privacy gate
  passed. Prospective indexed publication and reachable-history privacy scan passed.
  No before/after implementation extension hooks were registered.

No raw generated source, SQL parameters, database rows, browser state or native handles are
committed. Private test/evidence summaries and logs are retained under .local/self-checks/.
The source revision includes all sandbox modules and existing configuration/dependency pins.

## Authorized live model-generated execution

The owner completed IBMid sign-in in the existing local Playwright/WebKit workspace and
provided the signed-in inspection results for two explicit database-analyst submissions.
The configured route was delegated-exchange. The existing dataset was used without remote
provisioning or permission changes.

1. Initial run: model program received, actual Monty exercised, query policy passed,
   one completed database read, credential cleanup revoked, acquisition/revocation 1/1.
   The program then failed because it treated dictionary rows as positional tuples.
   This was reported as sandbox_execution_failed, not successful analysis.
2. Corrected run: program received, Monty exercised, query policy/database/sandbox all
   passed, one completed read, cleanup revoked, acquisition/revocation 1/1. The generated
   program computed status percentages using dictionary fields. Result values and their
   numeric correctness were not independently copied/reviewed; do not infer a four-row
   fixture count for this existing deployment.

The model-facing tool now explicitly documents dictionary row access and a grouped-count
example. The second live prompt included that same guidance because the current signed-in
server retained the previous tool description; no restart or second sign-in was required.
A post-run `agent recover status` independently reported clear, unblocked custody.
The private summary records outcomes only, with the owner-copied browser inspection identified
as its source. It is not a provider-native audit export.

Adding the profile changed the local environment fingerprint. Before live testing, the two
resolved legacy recovery attempts were inspected and migrated with agent recover migrate;
no unresolved attempt was discarded. The new response policy was reviewed and enrolled
with automatic incident cleanup disabled and zero sources. Normal per-query cleanup stayed
mandatory. No provider grants/policies were changed.

## Independent limits and next review

The parser and engine terminate under their declared bounds; callback cleanup reuses the
broker's bounded cleanup reserve. A cancellation-resistant host adapter remains quarantined
and retains custody until it exits rather than releasing the effect lock on a timer.
The 32 MiB limit describes Monty allocation, not worker RSS. Controlled probes do not prove
protection against every future engine vulnerability. Full Monty and remote-host execution
are outside scope.

Original fifteen native criteria remain blocked in acceptance.json. The unavailable native
audit tier and existing independent provider-evidence/reviewer prerequisites are unchanged.
A sandbox pass does not promote any of those claims.

T032 owner review completed on 2026-10-12: after the implementation results and live
limitations were presented, the owner explicitly instructed “merge it.” This records approval
of the concrete changes for publication and merge, conditional on green CI. It does not
change any independent blocked native acceptance criterion.
