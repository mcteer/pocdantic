# Data model: Readiness and closeout

All additions use the existing frozen extra-forbid contract base, canonical serialization and
UUID/digest validation. Public projections never serialize private objects by default. The
following numbered constraints are normative and repeated in implementation tasks.

## C01 — Shared contracts

"New records use schema_version exactly 1, reject unknown fields, use generated UUIDs and
64-character lowercase SHA-256 digests, and require timezone-aware UTC timestamps."

New record types: ReadinessReport, ReadinessCheck, DeploymentContext, CloseoutSnapshot,
CloseoutCase, CloseoutCriterion and CloseoutMember. Context has schema_version 1 plus a private
digest; it is not a public report. Existing run/source/review schema support is preserved.

## C02 — Readiness

"Readiness selects 1–2 distinct registered live scenarios from one suite; live-phone requires
exactly one named scenario. Check states are configured, missing, invalid, unverified or
not_applicable; sections are execution or evidence; owners are operator, integration_owner
or reviewer. No check result contains configuration values or arbitrary exception text."

ReadinessReport: schema_version, suite label, selected scenario labels, ordered checks,
execution_ready boolean, evidence_ready boolean, external_verified=false, generated_at.
A check has a registered check_id, scenario, section, state, owner and optional safe Reason.
Duplicate (scenario, section, check_id) is invalid. Execution_ready means no applicable local
execution check missing/invalid; evidence_ready analogously covers only local evidence setup.
Unverified remote checks do not make a configured local check pass remotely.

New Reason members: external_unverified, context_missing, context_mismatch, selection_incomplete,
input_changed, snapshot_stale, decision_unverified. Reuse existing safe reasons elsewhere.
All check IDs and owners are code-defined; static setting names are documentation, not values.

## C03 — Readiness bounds and dependency separation

"Readiness performs zero network/model/credential/phone/export calls, creates no validation
artifacts, reads at most 10 MiB per local configuration file, and has a two-second total deadline."

Local checks cover required packages; bearer presence (never validity); OAuth client/audience
and discovery/issuer endpoint arrangement; profile/capability selection; Vault target, path,
audiences and database target/TLS trust; phone enabled flag/API client/user/device mapping;
and optional telemetry SDK/write key/project configuration. The execution subset excludes
missing export-read access and native audit coverage. A configured exporter without its SDK
is an execution configuration error; absence of telemetry entirely is an evidence blocker for
this walkthrough. No model-provider key is required for the deterministic live factories.
Profile/CA failures are reduced to safe IDs/reasons. Readiness never invokes probe().

## C04 — Private deployment context

"A deployment context is sealed before live effects, contains no credential values, excludes
suite and timeout choices, and compares by a private digest; missing or unequal contexts block
combined closeout without preventing legacy per-run reports."

Persist context.json within the run and include it in integrity.json. Its digest covers a
canonical allowlisted configuration snapshot: effective OAuth provider/issuer/discovery/token
endpoint/audience/auth method/token type; agent client ID; Verify tenant/API client ID/user/device
and push-enabled flag; Vault address/namespace/path/audiences; database host/name/port/username
suffix/TLS CA content digest; workload definition and auth mount/role; effective profile content
digest; Logfire project alias and configured base URL or the stable marker token-routed.
Never include bearer/client/API/Logfire/Vault tokens, secrets or workload JWTs. A token-rotation
changes no context by itself; a project/identity/target/profile/trust change does. Source-manifest
identity and native receipt checks still establish whether a token actually reached that source.
Use existing trusted endpoint-resolution rules without making discovery calls; equivalent
spelling canonicalization is limited to existing settings normalization. This context groups
operator configuration; it is not proof of the human subject or authenticated source identity.

## C05 — Native import compatibility

"Import format version 1 remains readable; version 2 permits documented native envelopes and
an optional private native project ID of 1–128 characters. Contradictory simultaneously supplied
aliases fail with evidence_contradicted; unsupported shapes fail with source_unsupported."

Keep source_kind and format_label as today. Version 2 of vault-jsonl recognizes
response.secret.lease_id and the legacy top-level value; either absent is allowed for non-lease
responses, but both supplied must be equal. Version 2 of logfire-rows accepts row arrays,
rows envelopes and the documented schema/data JSON form. Data rows must be objects with the
required native fields; never guess column order or coerce arrays into rows. Validate schema
metadata as an object with fields: a list of objects containing name (nonempty string),
data_type (nonempty string) and nullable (boolean); it supplies no trusted row values.
Reject duplicate field names and row/schema field-name disagreement. Existing columns/rows
metadata keeps its documented datatype spelling and must not be confused with data_type. If rows and data both appear, reject
as ambiguous instead of choosing one. Existing duplicate-key, encoding, depth and event limits apply.

ImportManifest.native_project_id is optional/private and permitted only for Logfire format v2.
project/project_name values, if present, must equal source_instance and each other. project_id,
if present, must equal native_project_id; without that binding the record is unsupported.
Missing native project fields are accepted as operator-scoped provenance only, as in v1.
Version-1 canonical digests and normalization must remain stable on read; new matching rules
apply to version 2. Corrected interpretation of old ambiguous project IDs must not silently
promote receipt: a fresh v2 import and new review are required.

## C06 — Exact transaction and operation ownership

"Each binding and transaction must match its containing validation ID, selected observation ID,
run ID, expected source and approval/action binding. One native transaction cannot satisfy
multiple observations; only DENIED, VERIFY_DENIED or USER_DENIED proves intentional phone denial."

Reconstruct the expected joins from sealed run/observation/binding records. Required phases and
source instance must agree; native action digest and approval reference must match the stored
exact-action binding and response. SUCCESS/VERIFY_SUCCESS is approval. TIMEOUT, EXPIRED,
CANCELED, FAILED and VERIFY_FAILED remain non-approval evidence but never witnessed denial.
Preserve raw native state privately; derive public decision approved/denied/unverified. Legacy
transactions can derive state from their immutable raw response; never rewrite their bytes.
If a vendor's real denial uses another documented state, add a separately reviewed mapping
with primary evidence and tests before acceptance; do not guess during a live run.

## C07 — Closeout members and fixed slots

"Closeout accepts 1–4 distinct explicit live run UUIDs and contains exactly four case slots:
delegated-database-read, actor-only-denial, phone-approved and phone-denied. More than one
observation for a slot blocks selection; no latest-run selection or effect replay is allowed."

Each CloseoutMember has validation_id, report_revision, evidence/input-inventory digest and
private context digest. All selected observations must belong to these four cases; reject
foreign suites/offline runs before assembly. Missing slots are blocked/selection_incomplete.
All contexts and implementation/mapping revisions must be compatible with current code. Each
scenario revision must equal that scenario's current definition (different scenarios naturally
have different revision hashes). CloseoutCase includes scenario, references to supplied
validation/observation IDs, operation outcome, evidence outcome, cleanup and safe reasons.
Duplicate observations are retained as references for diagnosis but cannot choose a winner.

## C08 — Closeout outcomes and reviews

"Operational and evidence closure each use pass, fail, blocked or interrupted with precedence
interrupted > fail > blocked > pass. Exactly 15 criterion rows contain per-run dispositions;
closeout creates neither an aggregate customer disposition nor a new review decision."

CloseoutCriterion has criterion ID and one member projection per selected run: validation_id,
current status/reason/evidence_revision and applicable review_id or null. Use existing per-run
review reconstruction, including stale decisions, unsupported criteria and current eligibility.
Private reviewer/rationale strings never appear. Conflicting member decisions remain visible.
Operational closure evaluates all four expected case assertions; a successful negative assertion
may have an underlying denied operation. Evidence closure additionally applies the fixed matrix
in contracts/runtime.md. Unsupported Verify Events linkage is visible as a separate unsupported
customer-evidence item and does not imply receipt failure for unrelated sources.

## C09 — Snapshot revisions and immutability

"Snapshot content revisions bind sorted run IDs, exact input inventories and report/review
revisions, context and implementation/mapping revisions, all four cases and all 15 rows.
Snapshot UUID and generation time are excluded from the content digest."

CloseoutSnapshot has snapshot_id, created_at, content_revision, sorted members, case slots,
criterion rows, operational/evidence outcomes and blockers. Private manifest records selected
IDs and the digest of every consumed file; public JSON/Markdown use only safe projections.
A repeated build from unchanged inputs produces the same content_revision but can have a new
snapshot_id. Inspection by snapshot_id compares current reconstructed inputs to the saved ones;
changes produce snapshot_stale, missing files evidence_missing, tampering digest_mismatch.
Old snapshots remain historical records and are never rewritten as current success.

## C10 — Atomicity, privacy and quotas

"Run locks are acquired in sorted UUID order without blocking; inputs are rechecked immediately
before atomic closeout finalization. Private directories are 0700 and files 0600; symlinks,
path escapes and overwrites are rejected. Each snapshot allows at most 100 files, 10 MiB per
file and 100 MiB total; inherited per-run limits remain unchanged."

Use .local/validation/closeouts/<snapshot_uuid>/ with a private manifest and immutable JSON/Markdown
projections. A failed or interrupted write produces no finalized snapshot; abandoned temporary
files are ignored during inspection, never treated as proof. Do not copy raw evidence into the
snapshot. A changed file between read and final check produces input_changed and no successful
finalization. Locks protect cooperating writers; hostile local filesystem control remains outside
the source-authenticity guarantee and digest provenance is explicitly limited.

## C11 — Local work and exit codes

"Closeout has a 30-second wall deadline and a ten-second assembly budget excluding file I/O
for four maximum-supported runs; exit precedence is 130 interrupted, 1 failed, 2 blocked or
invalid, then 0 successful selected work. No command retries effects or deletes evidence."

Ready exits 0 only when both local execution/evidence setup are ready, 2 when a local check is
missing/invalid, 1 on local processing failure, 130 interrupted. Its execution_ready field stays
independent when only evidence setup is missing. Unverified external checks alone do not turn
readiness into failure. Closeout exits on operational plus evidence closure, not on all 15
customer criteria; unsupported broader acceptance remains visible even when selected proof is
complete. Existing run/report/review exit meanings remain documented and unchanged.

## C12 — Review eligibility remains narrow

"Only existing UC1-01, UC1-05 and UC2-02 eligibility may be retained; exact referenced evidence
must cover their relevant successful operation phases, and unrelated source-kind matches never
qualify. Unsupported criteria and changed revisions remain blocked."

UC1-01/UC1-05 require the delegated-database-read observation, successful exact lease acquisition
and cleanup evidence and complete matching telemetry for the selected run. If actor-only-denial
is also selected, its expected denial and Vault evidence must hold; failures cannot be discarded.
UC2-02 requires phone-approved with its exact successful transaction, verified action binding and
simulated effect assertion. Neither path constitutes a blanket vendor enforcement claim; named
reviewer and current evidence revision remain mandatory. Phone-denied evidence contributes to the
closeout slot but grants no new criterion eligibility. The existing reviewer must still assess
whether full criterion meaning is supported; no automatic pass or alternative is introduced.
