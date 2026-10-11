# Runtime Contract: End-to-End PoC Closeout

Installed local interfaces. Successful record creation is separate from native proof or acceptance.
Normative field and bound rules are in [data-model.md](../data-model.md). All new commands run locally;
no provider Settings, network client, subprocess, phone prompt or provider mutation is permitted.

## Commands

Prefix with `uv run agent closeout`. IDs/digests/revisions are returned safe values. PATH is an
explicit operator-selected owned regular file; file paths never appear in public output. Default
storage is the fixed project-private `.local/closeout/`; no arbitrary output-root or live flag.

| Command | Result and mutation |
| --- | --- |
| `prepare --inventory PATH` | Create new dossier UUID and revision 1 after strict inventory validation |
| `amend --dossier UUID --revision N --inventory PATH` | Append environment revision; old evidence remains historical |
| `guide --dossier UUID [--use-case UC1\|UC2\|UC3\|UC4] [--experiment SCENARIO]` | Read-only compiled prerequisites, steps, capture/recheck and expected results; selectors mutually exclusive |
| `capture --dossier UUID --revision N --kind validation\|response\|governance\|regression --member UUID` | Snapshot selected member's complete relevant reference closure/history, evaluate actual capture time, append evidence member |
| `import --dossier UUID --revision N --manifest PATH --input PATH` | Validate one bounded declared raw source and manifest, append typed artifact; import never grants acceptance |
| `experiment --dossier UUID --revision N --input PATH` | Prepare one of four scenarios from imported pre-operation baseline, mapping and cohort artifacts |
| `measure --dossier UUID --revision N --experiment UUID --input PATH` | Bind final exports, 100-execution roster/mappings and delta explanations; compute measured result |
| `assess --dossier UUID --revision N` | Append complete immutable four-UC/fifteen-row/six-test/five-gate snapshot using all relevant current-scope members |
| `review --dossier UUID --revision N --input PATH` | Record source-profile/source/attachment attestation, criterion decision, exception agreement or package role decision according to discriminated input schema |
| `package --dossier UUID --revision N --assessment UUID` | Assemble/seal immutable private core from selected assessment, applicable criterion reviews, measurements and explicitly reviewed attachments |
| `handoff --dossier UUID --revision N --package UUID` | Seal new private final bundle from unchanged core and applicable role reviews; may legitimately contain blocked/failed final result |
| `inspect --dossier UUID` | Read-only state/current revision, partial operations, safe blockers and next actions |
| `report --dossier UUID --assessment UUID` or `report --dossier UUID --package UUID` | Mutually exclusive selectors; verify fixed snapshot, dependencies and current applicability without rewriting |

Successful local mutation returns 0 with UUID/revision and actual content status, even if proof is
blocked. Guide/inspect return 0 for a valid readable dossier and report its blocked items explicitly.
`report` returns 0 only for applicable fully accepted content, 1 for failed proof/integrity/rejection,
2 for incomplete, historical, unknown or unreviewed proof. Input/storage/revision/quota failures return
2 with a safe reason; integrity contradictions return 1. Interruption returns 130 after bounded cleanup.
Callers must inspect explicit proof/decision fields, never interpret import or package exit 0 as acceptance.

Common output: schema_version, operation, dossier_id, revision, local object_id if produced, status,
proof_status, applicability where relevant, compiled reason/owner/action entries and safe measurements.
Errors use closed codes including schema_invalid, source_unsupported, evidence_missing, evidence_conflict,
context_mismatch, input_changed, review_stale, review_conflict, source_expired, revision_conflict,
capacity_exceeded, integrity_failed, storage_invalid, deadline_exceeded and interrupted. No exception text.
No input value may become a shell command, Markdown link, HTML fragment or executable expression.

## Existing execution guides

New guide output never invokes the following commands. Actual sign-in remains in the local workspace,
using Sign in → Sign in with IBMid and scanning inside IBM Verify where configured. No extra credentials
are requested merely for packaging. Existing phone failures retain their recorded blocker.

| Use case | Existing entry commands | Required collection and expected outcome |
| --- | --- | --- |
| UC1 | `agent validate ready --suite live-database`; separately authorized `agent validate run --suite live-database --mode live` | Match signed human/actor and request scope to actual issuance, SQL grants/SELECT, Vault denial and exact lease revoke; capture native audit if entitled |
| UC2 | `agent validate ready --suite live-phone --scenario phone-approved` and `phone-denied`; separate `agent validate run --suite live-phone --scenario phone-approved --mode live --interactive` (or `phone-denied`) | Capture exact phone decision and gated parent operation; use workspace delegated task for Jira lineage; phone-only checks do not prove full parent write or audit |
| UC3 | `agent respond providers readiness`; `agent respond providers status --incident UUID`; `agent respond status --incident UUID` | Capture actual provider-originated incident, controls and evidence; current provider probe forms are linked from 007, never auto-dispatched by guide |
| UC4 | `agent govern readiness --candidate UUID`; `agent govern closeout --candidate UUID` | Follow 008 prepare/observe/review/enroll/prove flow; preserve exact pre-enrollment discovery, identity, native SVID verifier and ceiling outcomes |

Existing source import/review commands remain documented in the
[003](../../003-live-evidence-closure/quickstart.md),
[007](../../007-provider-remediation/quickstart.md) and
[008](../../008-shadow-agent-governance/quickstart.md) quickstarts.
`agent validate closeout --run DB_UUID --run APPROVED_UUID --run DENIED_UUID` remains the older
four-case aggregate. Its successful rows may be evidence members, never automatic four-UC acceptance.
`python scripts/run_security_regression.py report --run UUID` contributes software coverage only.

Guide catalogs must name whether each suggested existing command performs local inspection, live reads,
credential issuance or mutation. A customer test must explicitly follow the existing tool's preconditions;
guide text is never itself authorization or automatic execution. Fixture/reset guidance uses exact
existing recovery commands and never deletes state, clears holds or replays uncertain effects.

## Source adapters and native fact formats

Kinds resolve only in established project-private stores: validation run/closeout IDs from
`.local/validation/`, response incidents from `.local/response/`, candidates from `.local/governance/`,
and software run IDs from `.local/security-regression/`. Validation runs resolve under the default root, older closeout IDs under its `closeouts/` child;
exactly one matching typed object is required and ambiguous IDs are rejected. Use the maintained default
resolver without constructors or side effects; no fallback scans arbitrary directories. Copy only required source evidence and related scope history,
within C04–C08. Strict identity/mode/link validation precedes any legacy helper call.

Validation uses read-only reconstruction; response/governance use pure reducers on captured schema-valid
state and exact referenced source inventories. Regression capture validates its compiled source format,
file inventory and terminal seal and always labels it software; runtime code does not import `scripts/`.
A missing root, legacy format or unsealed member yields a precise blocker. No chmod or source lock creation.

Import manifests explicitly discriminate `vault-audit-v1|vault-audit-v2|verify-events-v1|logfire-v1|logfire-v2|
native-facts-v1|vault-activity-v1|execution-roster-v1|entity-mapping-v1|attachment-v1`.
Existing supported importers can be reused only with their original validation semantics. New external
facts require reviewed fixed source profile, original source bytes and exact record/field extraction as
specified in the data model; no string saying "native" is evidence. Unknown formats cannot receive pass.
Review schema has distinct source-profile, source-extraction, attachment, criterion, exception and
package variants; each forbids fields belonging to another variant. Source/extraction review binds raw,
schema and selected-fact digests. Attachments require exact byte digest and explicit sanitized-for-handoff
attestation. Neither type is a criterion decision or substitute for enforcement proof.

## Criterion proof matrix

All rows require same environment/scope, exact source correlation, original artifacts and explicit
criterion review. Positive and negative controls are both required where listed. A reviewed claim
without extractable source facts stays blocked. Original criteria IDs/meaning never change.

| Criterion | Minimum independently verifiable obligations | Accountable review roles |
| --- | --- | --- |
| UC1-01 | Reviewed deployed code/config inventory plus credential-flow/trace inspection; no embedded secrets, source-backed trusted-adapter isolation; software scan alone insufficient for target deployment | agent_engineering |
| UC1-02 | Verified human/actor and exact OBO/RAR request, Vault validation and request-limited issuance, measured TTL, successful permitted SELECT and exact lease revoke/after-check | verify_owner, vault_owner (DB evidence) |
| UC1-03 | Actual issued read role/grants, permitted SELECT and denied write with same credential scope | vault_owner (DB evidence) |
| UC1-04 | Out-of-policy request denied at Vault with zero issued credential; policy/config proof no pre-created permission group required; actor-only application denial alone insufficient | vault_owner, verify_owner |
| UC1-05 | Actual Vault audit issuance event linked directly or by verified correlation to human subject and agent actor | vault_owner (observability evidence) |
| UC2-01 | Jira child read, parent/child lineage and actual parent write under its own allowed policy with correlated audit | agent_engineering, verify_owner, vault_owner |
| UC2-02 | Exact-action native approval precedes privileged issuance/effect; denied and timeout paths independently prove zero privileged issuance; phone transaction alone insufficient for full gated effect | verify_owner, agent_engineering |
| UC2-03 | Complete correlated audit artifact index and reviewer-confirmed receipt for the witnessed UC2 flow | customer_security, agent_engineering |
| UC3-01 | Agent lease revoke and after-check; still-unexpired original external JWT is retried and fails JWT validation at the specified provider; policy denial/token revoke/local hold separately labeled | vip_owner, vault_owner, verify_owner |
| UC3-02 | Native user-compromise event, automatic session revoke, user suspension, existing/new session outcomes and actual Teams notice receipt, without intervening human action | vip_owner, verify_owner |
| UC3-03 | Actual VIP detection of the selected misused secret and automatic exact Vault rotation/revoke with generation-correct independent after-check | vip_owner, vault_owner |
| UC3-04 | Same-event trigger and actual revocation source intervals, clock bounds and conservative upper latency <1,800 seconds; receipt/worker time alone insufficient | vip_owner, agent_engineering |
| UC4-01 | Independent workload bootstrap, actual native Vault SVID issuance, independent relying verification and exact entity/owner registry/ceiling binding | vault_owner, verify_owner |
| UC4-02 | Actual inside-ceiling success and outside-ceiling denial at Vault with matched context/healthy controls and policy snapshots | vault_owner |
| UC4-03 | Actual VIP unknown-agent finding and notification strictly before registry enrollment, correlated absent-before state and observed activity | vip_owner |

When a compiled member evaluator covers only part of a row, leave remaining obligations blocked.
Native-facts-v1 allows supported source-backed facts for the rest; no blanket sufficiency override.
A source format lacking the needed relation requires an owner-provided supported artifact or a separately
agreed exception. Demo-tier Vault audit remains unavailable unless an actual new entitled source is proven.
Existing Verify transaction/event linkage limitations are retained.

Timing is an interval: if trigger is [t0-u0,t0+u0] and revoke is [t1-u1,t1+u1], latency is
[(t1-u1)-(t0+u0), (t1+u1)-(t0-u0)]. Negative/overlapping chronology cannot prove the required order;
show unknown rather than clamp to zero. Use the conservative upper bound for UC3-04 eligibility.

## Client-count evidence protocol

1. Operator obtains source-owner-reviewed export/mapping access, the actual 100-subject cohort and
   an approved test scope. No bulk user creation or token import endpoint is introduced.
2. Import pre-operation native entity/alias inventory and activity export plus source manifest. Prepare
   the experiment before its first operation. Record other consumers and intended cohort independently.
3. Execute the approved existing application/provider flow externally for all 100 operations and retain
   successful operation, independently resolved entity, issuance and trace references. Agent-only users
   must be verified upstream while native operation evidence proves no human OBO use. If an existing
   execution surface cannot perform the required mode, report `execution_surface_unavailable` with
   agent/Vault owner and request the explicit provider test harness/operation evidence; do not fake a CLI.
4. Acquire complete final export after the declared reporting delay and record effective calendar period,
   collection time, scope and source version. Use the official
   [activity-export API](https://developer.hashicorp.com/vault/api-docs/system/internal-counters#export-client-activity)
   through an authorized provider operator; authentication stays outside command text and this workflow.
5. Import final activity, post-mapping inventory and the exact execution roster; `measure` verifies every
   join and reports scenario-associated, reused, incremental, unrelated, missing and extra sets separately.
   Missing source, unknown export completeness/delay or unsupported mode is blocked; verified wrong
   cardinality/remapping/conflicting evidence is failed. Exact controlled sets, not approximate totals,
   govern pass. Any unexplained client prevents pass.

| Scenario | Required identities/actions | Controlled expected set |
| --- | --- | --- |
| agent-repeat | 100 distinct successful executions/issuances/traces; one durable native agent entity | 1 agent client, no growth with executions |
| agent-only-users | 100 distinct upstream verified humans; all Vault operations autonomous agent | 1 agent client; none of these calls maps a human OBO client |
| agent-obo-users | 100 distinct verified humans with exact delegated native mapping; one distinct agent | 101 distinct entity clients for the controlled roster |
| direct-users | 100 distinct successful direct native human clients | 100 distinct entity clients |

Counts do not predict an invoice. Reused cohort identities affect incremental counts independently;
non-entity categories and other consumers are explained separately. A 100-record roster cannot be
made from one subject with altered labels. Exports from unlike clusters/periods cannot be summed into
one measurement. More than allowed input volume requires narrower authorized collection, never truncation.

## Function 13 and phase-gate mapping

| Design item | Required result | Implementation story |
| --- | --- | --- |
| F13.01 | Frozen complete inventory/context | US1 |
| F13.02 | UC1 guide, captured native obligations and disposition | US1, US2 |
| F13.03 | UC2 guide, approve/deny/timeout plus parent lineage/effect disposition | US1, US2 |
| F13.04 | UC3 guide, independent native controls, timing and disposition | US1, US2 |
| F13.05 | UC4 guide, discovery/identity/enrollment/ceiling disposition | US1, US2 |
| F13.06 | Exactly fifteen original criterion rows with source/measurement/owner/decision | US2 |
| F13.07 | Gaps, product limitations and explicitly agreed exception records | US2, US4 |
| F13.08 | Private reproducible package, reviewed sanitized logs/images, fixture/reset/config summaries | US4 |
| F13.09 | Short readout of function/proof/timing/gaps/counting assumptions | US4 |
| F13.10 | Actual witness and all owner decisions, or concrete missing-review blockers | US4 |
| F13.11 | Pre-operation baseline/inventory and scoped cohort | US3 |
| F13.12 | Four external experiment guides and measured 100-execution evidence | US1, US3 |
| F13.13 | Native identity/activity set reconciliation and explained differences | US3 |
| F13-T1 | Witnessed UC1/UC2 positives/negatives with eligible independent artifacts | US2, US4 |
| F13-T2 | Witnessed native automatic UC3 and measured end-to-end timing | US2, US4 |
| F13-T3 | Witnessed native pre-enrollment UC4 and ceiling rejection | US2, US4 |
| F13-T4 | All fifteen original rows have explicit pass/fail/blocked, owner and evidence or gap | US2 |
| F13-T5 | agent-repeat native identity/trace/activity measured outcome | US3 |
| F13-T6 | All three 100-user native scenario outcomes and delta explanations | US3 |
| P4-G1 | Full software suite reference plus actual witnessed native demonstrations | US2, US4 |
| P4-G2 | Evidence index and sealed private proof/readout package | US4 |
| P4-G3 | Original criteria preserved; separately approved deviations and gaps | US4 |
| P4-G4 | Five role signoffs for exact core, or named missing role | US4 |
| P4-G5 | Four measured client experiments and reviewed counting assumptions | US3, US4 |

Software tests establish that these dispositions are computed correctly; missing native performance
is recorded as blocked, never an unchecked software task secretly called complete.

## Review and final decision

Review payload variants carry exact subject UUID/digest. Criterion approval needs eligible source proof
and required criterion-owner roles; witness-required F13 outcomes additionally need actual meeting
attestation with time, participants and source reference. Package approval needs one explicit approval
per required role. Reviewer names/prose stay private. A label is not authenticated identity; no system
claim of cryptographic witness authentication is made.

An exception retains the original fail/blocked row and proposed changed criterion. Customer and all
relevant vendor roles must explicitly agree; missing approver keeps it unaccepted. Accepted exceptions
qualify the final decision without overriding evidence integrity, contradictory claims or unresolved
cleanup. Unsafe outstanding cleanup/integrity conflicts cannot be waived through an exception.

Core packaging may occur with blocked proof so the operator can review gaps. Full acceptance needs:
all original criteria pass, all F13-T1–T6 and P4-G1–G5 fulfilled, current applicability and all role approvals.
Missing witness/role approvals with otherwise complete eligible proof yields ready_for_review; incomplete
proof/prerequisites yields blocked; contradictory evidence or explicit rejection yields failed. An approved
exception can qualify an unmet original requirement but never hide it: final result is accepted_with_exceptions.
Historical reviews remain valid records of their historical scope while current status reports drift.
`handoff` copies an immutable core and applicable attestations; it never uploads or updates acceptance.json.

## Privacy, retention and compatibility

Safe console/report projections follow C17. Native paths, mappings, event IDs, users, source content and
attestations stay under private storage; public locators are generated UUIDs. Render Markdown from compiled
text/validated primitives. Private optional attachments are never rendered into stdout or executed.
Known secrets fail ingestion; reviewer-controlled manual image sanitization is explicitly required.
Raw originals stay outside the core/handoff but their digest-bound index remains for authorized review.

Source stores, prior evidence and unsupported formats are preserved. Quota rejects further writes before
partial effects on a sealed revision; capacity repair explains private archive/retention ownership without
automatic deletion. New revisions consume capacity and never silently overwrite failures or decisions.
New package version 1 is additive. Legacy `validate closeout` and its evidence/review schemas retain semantics.

## Implemented extraction representation

The inventory uses `implementation_digest`, `dependency_digest`, fingerprint lists
`definitions|policies|datasets`, exact `owners` and typed `sources`. Source profiles use
`reporting_delay`, optional `member_environment_digest`, `records_pointer`, `fact_kind`,
`proof_labels` and `selectors`. Review pins the entire profile digest. A selector may extract
`values` as its strictly typed object, individual `values_FIELD` fields, or the closed
`fact_kind`/`obligation` from original records. No predicate expression is accepted.
The eleven fact kinds retain their required values; discovery classification additionally
distinguishes `user_compromise|secret_misuse|agent_compromise` from `unknown_agent`, so an
unknown-agent discovery cannot stand in for user compromise.

`inspect` returns safe profile content digests and source seal/extraction hashes needed for
review. Complete JSON/JSONL schemas and workflow input fields are documented in
[usage](../../../docs/usage.md#poc-closeout); Python fixtures demonstrate synthetic values.
Profiles/extraction reviews are dependencies of assessments; criterion/role signoffs do not
change environment revisions. Core-bound meeting receipts are not new demonstration proof.
