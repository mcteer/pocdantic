# Data model: Security Regression Validation

These are development-tool records, separate from production validation/native journals.
All JSON models reject unknown fields, duplicate object keys, nonfinite values and coercion
where strictness is stated. Public summaries use a deliberate projection of private records.
The normative constraint sentences below are quoted in implementation tasks.

## Normative constraints

- **C01**: Schema version is the integer 1; run IDs are canonical UUIDs, content/selection/node/artifact digests are 64 lowercase hexadecimal characters, and timestamps are timezone-aware UTC.
- **C02**: Case IDs match `[a-z][a-z0-9-]{0,47}`; test groups are exactly F12-T1 through F12-T10; build items are exactly F12.01 through F12.14; profiles are exactly baseline or restricted.
- **C03**: The catalog contains 1–256 unique cases and at most 512 unique selectors; each case has 1–32 selectors, 1–10 distinct groups and 1–14 distinct build items; selectors are repository-relative test file/function names of at most 256 characters with no parameter expressions or command options.
- **C04**: Boundary is one of model, tool, identity, approval, vault, database, incident, governance, publication or reporting; severity is critical, high, medium or low; owner is agent, identity, vault, database, security or integration; configuration applicability is fixed or profile-sensitive.
- **C05**: Case expectations are 1–16 compiled assertion codes of at most 48 lowercase alphanumeric/hyphen characters; optional effect counters are strict integers from 0 to 10,000 and accept only attempted, issued, completed and forbidden keys.
- **C06**: Run state is running, completed, failed, interrupted or incomplete; item/case/group outcome is pass, fail, blocked or incomplete; freshness is current, historical or unknown; all native dispositions are blocked.
- **C07**: A run selects 1–256 distinct cases and 1–2 distinct profiles; at most 10,000 expanded item results exist across the run, and shared selectors execute once per profile.
- **C08**: Execution has a fixed 600-second total deadline including collection and both profiles, followed by at most 10 seconds to terminate, kill and drain the owned process group; no user option increases either bound.
- **C09**: Metadata frames are at most 16 KiB and carry a strict positive sequence number; manifests and final reports are each at most 8 MiB, artifacts at most 10 MiB each, and the run at most 100 MiB with at most 100 artifacts.
- **C10**: Private directories are owned mode 0700; files are owned mode 0600 regular single-link entries; symlinks, path traversal, unsafe existing modes, inode replacement and overwrite of immutable records are rejected.
- **C11**: A passing expanded item has exactly one setup, call and teardown phase in order, all passing without skip, xfail or xpass; passing also requires unchanged selection/content, zero process exit and a matching terminal seal.
- **C12**: Failure reasons are selected from the closed contract list; public results contain only run/case/group/profile identifiers, digests, UTC times, bounded counts, outcomes, freshness, severity, owner and compiled next actions, never raw test text or parameter values.
- **C13**: Native prerequisite/action/recheck text is compiled, each 1–512 characters; software/version labels are 1–128 ASCII alphanumeric or .+!_- characters from an allowlisted package-name set, with at most 32 version entries and no filesystem paths.
- **C14**: Records are immutable after writing; an active run is exclusively locked, an unlocked run lacking a valid terminal seal is incomplete, and report inspection never resumes execution, prunes prior runs or changes acceptance.

- **C15**: Item ordinals are strict integers from 1 to 10,000; result counts are strict integers from 0 to 10,000; exit code is absent or a strict integer from 0 to 255; cleanup outcome is drained or unknown; full-selection flags are strict booleans.
- **C16**: JSON nesting is at most 8 levels; protocol event kinds are collection, item, terminal or error; phase states are pass, fail, skip, xfail, xpass or missing; unsupported fields and duplicate JSON keys are rejected.

## SecurityCase (compiled, maintained)

Fields: case_id(C02); groups/build_items/selectors(C03); boundary, severity, owner,
configuration_applicability(C04); expectations(C05). Selectors use exactly
`tests/test_*.py::test_*` or explicitly named test-class functions; no arbitrary module,
callable, absolute path, parent component, glob, expression or test parameter selector.
Catalog validation requires every one of the ten groups and fourteen build items covered.
A maintained rationale describes how each selector demonstrates the expectation, and any
excluded subprocess/browser selector names its retained full-CI coverage and safe substitute.
Missing new selectors remain a failing catalog gate until implementation supplies them.

## PolicyProfile (compiled, synthetic)

Exactly the two profiles in C02. `baseline`: `Policy(ticket_projects={POC, ALT})`;
`restricted`: `Policy(ticket_projects={POC})`. Other policy fields keep existing defaults.
A canonical representation and digest bind the actual policy, not instructions or its label.
Profile-sensitive cases must consume this representation; fixed-policy reused cases explicitly
report fixed applicability. The changed ALT-1 request and unchanged POC-1 control are required.

Allowed version keys are python, pytest, pytest-asyncio, pydantic, pydantic-ai-slim,
pydantic-settings, httpx, pyjwt, cryptography, psycopg, fastapi, uvicorn, logfire,
opentelemetry-api and opentelemetry-sdk. An uninstalled optional package records absent;
a package required by the selected cases fails dependency readiness. Platform is recorded
as the compiled macOS/Linux target label. Dependency lock bytes remain in content identity.

## RunManifest (private immutable)

Fields: schema_version/run_id(C01), state=running, started_at, selected case IDs/profiles(C07),
complete_catalog boolean, content_digest, selection_digest, catalog_digest, profile digests,
versions(C13), expected deadline, implementation base reference as digest only. Manifest
binds exact source snapshot and selection before collection; no absolute source path stored.
Selection digest covers sorted selected descriptors plus profiles; content digest covers
sorted eligible relative paths and exact bytes. Parent generation is fixed to this run.

## Collection and ItemResult (private normalized)

Collection: run/profile/content/selection identities, selector ID and all expanded item
node digests; each digest hashes the complete collected node ID held only in child memory.
Parent assigns a stable ordinal within each selector; no parameter string is exported.
An item may serve multiple cases. Pre-deselection and final sets must match exactly.

ItemResult: identities above, selector ID, node_digest, ordinal (strict1..10,000),
phase states(C11), outcome(C06), safe reason(C12), optional counters(C05), start/finish UTC.
Collector errors may produce a collection-level failure with no item; they cannot manufacture
an item pass. Terminal failures compact available phases and explicitly mark absent phases.
Only passed setup/call/teardown can yield pass; assertions must themselves check effects.

## TerminalSeal and persisted integrity

Seal: schema_version/run_id, content/selection/profile identities, result artifact digests,
strict result count0..10,000, final run state, finished_at, exit code strict integer0..255
(or absent for a lost child), and cleanup outcome `drained|unknown`. Completion requires
all expected children drained. Integrity binds manifests and normalized result bytes.
Digest verification detects accidental modification; these local files are not signed
provider attestations and do not protect against a malicious same-user author.

## Report and failure ownership

Report: run identity, content/selection identity, full/partial selection, state/freshness,
versions, result counts, per-case and ten per-group outcomes, and ten native prerequisites.
An omitted group is incomplete with not_selected; a selected case passes only if every mapped
item passes for all selected profiles. A full result requires all cases and both profiles.
Group precedence is fail > incomplete > blocked > pass. Run operational errors remain
nonpassing even when earlier cases passed. Historical pass may be displayed with historical
freshness but never as a current full pass or an exit0 report.

FailedCase: inherited case severity/owner, safe reason, and compiled reproduction command
using only case/profile IDs. No waiver, exception, arbitrary finding text or native pass field.
An independent rerun creates a new run UUID; it does not supersede/delete a prior failure.

## Lifecycle and bounds

run: validate → snapshot → locked running manifest → collect/execute profile1/profile2 →
verified terminal artifacts → completed or failed. Timeout/interrupt → drain → interrupted;
missing child/invalid metadata/storage failure → incomplete. Failure to drain prevents pass.
Read-only inspection of active locked state returns busy; abandoned state is incomplete.

Report storage and temporary synthetic state are separate. Clean temporary state only after
owned child drain; an uncertain drain leaves only bounded private remnants and a safe failure.
Do not modify provider/private application state or delete earlier result directories.
