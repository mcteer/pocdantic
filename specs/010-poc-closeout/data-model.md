# Data Model: End-to-End PoC Closeout

Strict frozen Pydantic boundary models reject unknown fields, duplicate JSON keys, non-finite
numbers and coercion. Private fields use suppressed repr and safe closed error codes. All references
are typed; a UUID from another family is not interchangeable.

## Normative constraints

- **C01**: IDs are canonical UUIDs; revisions are strict positive integers; SHA-256 digests are 64 lowercase hex characters; timestamps are timezone-aware UTC.
- **C02**: Public labels are compiled enums or generated aliases; private identifiers are 1–256 characters; reviewer names are 1–128 characters; private rationale is 1–2,000 characters.
- **C03**: Catalog sets are exact: 4 use cases, 15 criterion IDs from CRITERIA, 13 build items, 6 Function 13 tests, 5 exit gates, 4 experiment scenarios and 5 review roles.
- **C04**: Each source file is at most 10 MiB; each JSONL record at most 64 KiB; JSON depth at most 8; each dossier has at most 100 source artifacts and 10,000 normalized activity records.
- **C05**: Each dossier retains at most 100 revisions, 100 assessments, 100 reviews and 20 packages; total stored bytes including partial writes are at most 100 MiB; no automatic pruning or overwrite occurs.
- **C06**: Each local operation has a 30-second deadline including cleanup; pure assessment of 15 criteria and 10,000 normalized activity records takes at most 5 seconds excluding I/O.
- **C07**: Private directories are owned mode 0700; regular files are owned mode 0600 with one hard link; symlinks, traversal, inode replacement and special files are rejected before reading or writing.
- **C08**: Mutation requires the expected current revision under one per-dossier exclusive lock; seal publication is atomic and last; inspection never writes or creates source locks.
- **C09**: Evidence provenance is synthetic|operator|native; outcome is pass|fail|blocked; applicability is current|historical|missing|invalid; unknown provenance or status is rejected.
- **C10**: Each evidence member binds one environment digest, source kind/instance, format version, artifact digest, observation and capture times, exact object identity and complete selected reference closure.
- **C11**: Each experiment requires exactly 100 successful distinct execution references; agent scenarios require 100 distinct token-issuance references and trace references; user scenarios require exactly 100 distinct verified subject references.
- **C12**: Each experiment fixes one cluster, one namespace subtree, 1–16 auth mounts, one effective reporting period and one durable agent where applicable; cross-cluster totals are never deduplicated or combined into a single proof.
- **C13**: A baseline precedes all scenario operations; final acquisition follows all operations and the declared reporting delay; expected entities come from independently resolved native mappings, never token-count arithmetic.
- **C14**: Each criterion or package review binds exactly one assessment or core digest, reviewer role/name, observed/reviewed times, decision, rationale and 1–32 private attestation references.
- **C15**: Full acceptance requires all 15 original criteria passed and all 5 role approvals for the same current core; exceptions require customer plus relevant vendor agreement and never change an original criterion to pass.
- **C16**: Each package has at most 100 files and 50 MiB; attachments are text/plain, image/png or image/jpeg, at most 5 MiB each, with explicit sanitization review bound to exact bytes.
- **C17**: Public projections contain only schema versions, local UUIDs, compiled labels/reasons/actions, counts, UTC times, durations and content digests; native identifiers, paths, source prose and reviewer names are private.
- **C18**: No closeout operation initializes provider settings, reads credentials, calls network, launches subprocesses or executes guide text; existing source stores remain read-only.
- **C19**: Native eligibility is evaluated at actual capture time under the member's original freshness rules; neither import timestamps nor user-supplied evaluation times may renew expired proof.
- **C20**: Timing uses correlated source intervals with finite nonnegative clock uncertainty; a UC3-04 pass requires an upper latency bound below 1,800 seconds; unknown or inconsistent bounds block proof.

## Dossier and InventoryRevision

`Dossier`: UUID, schema_version=1, created_at, immutable inventory revisions and a current positive
revision head. The dossier mutation revision advances for every mutation, while the environment
inventory revision/digest changes only on amend. Assessments record their capture mutation revision for
provenance but invalidate only when a referenced dependency or relevant scoped evidence changes; adding
an unrelated artifact or recording a review must not stale its own assessment/core. `InventoryRevision`: revision, parent digest, implementation/lock/catalog digest,
prepared_at, fixed owner roles and capabilities, 1–16 named source profiles, 1–100 definition/identity
mapping references, 1–100 policy/dataset/configuration digests. References are private, no secrets.
Clock uncertainty is absent or a finite number from 0 through 5 seconds; absent bounds block chronological
proof. Native event times beyond actual capture time plus the reviewed uncertainty are invalid.
Declared activity reporting delay is a strict integer from 0 through 86,400 seconds and requires source-owner
confirmation for the pinned edition/version; absent or unverified delay/completeness blocks measurement.
All lists are unique by typed identity; no missing owner means implicit approval. Explicit inventory
amendment creates a new revision and invalidates current dependent assessments/reviews.

Source profiles record product/version/edition, instance/cluster identity, namespace, supported
format/schema digest, observation clock bound and evidence capabilities as supported|unavailable|unknown.
A declared capability is a prerequisite claim, not native proof. Import native profiles only after
explicit source-owner review referencing an attestation. Profiles select compiled formats, not code.

The head indexes existing immutable records. Changes append successor records; a mutation has a UUID
reserved before writes, and an interrupted operation retains a partial marker consuming quota. Recovery
can inspect the last sealed head; no retry resumes an effect because there are no effects. New attempts
use new IDs and cannot silently replace partial files. No global quota eviction or removal of sources.

## EvidenceMember and ExternalEvidence

`EvidenceMember`: UUID, kind `validation|response|governance|regression|external|activity|roster|mapping|attachment`,
context digest, native object reference privately, source/revision digest, input inventory, capture time,
recorded assessment time if independently available, own evaluation time, provenance, supported format,
original bytes locator beneath dossier, normalized facts and links. A member retains full relevant scope
history and source file digests; the capture cannot choose individual pass rows from a member object.

Validation/response/governance member parsers verify current maintained model schemas and correlations.
Regression records use a closed software-summary format, never a native proof path and never an import
from uninstalled contributor code. Unsupported versions remain blocked with recapture instructions.
Any included raw original is private; known credentials/token fields are rejected at the input boundary.
No tokens are needed for measurements: references/digests to independent issuance records suffice.

External evidence supports a versioned normalized native fact envelope with:
`source_profile_id`, `source_event_id`, `occurred_at`, `source_artifact_id`, `source_artifact_digest`,
`record_pointer`, `fact_kind`, `correlation`, `values`, `review_ref`. Facts select compiled types:
identity_mapping, operation_result, cleanup_result, approval_result, lineage, session_result,
discovery_result, registration_result, jwt_validation, timing or witness. Values and correlations
are discriminated closed models, never arbitrary nested dictionaries. Extract only fields listed by the
profile's reviewed schema. A pointer without a matching raw record is invalid; manual normalization
without independently checkable original content is operator provenance and cannot grant native proof.

At most 16 fact selectors per profile, each a JSON Pointer of at most 256 characters with no wildcard;
fields have compiled expected types and equality predicates only. Scalar comparison never executes
expressions. Known secret fields/tokens in unselected source content reject the artifact; safe errors
never include source input. Unknown format/predicate yields blocked source_unsupported.

Compiled fact values require the following fields (references are typed UUIDs to private mappings/artifacts;
counts are strict integers 0–10,000; durations are finite nonnegative milliseconds at most 86,400,000;
boolean fields are strict booleans). Denial mechanisms are exactly jwt_invalid|policy_denied|token_revoked|lease_revoked|db_privilege|session_revoked|local_containment|unknown. Optional references are null only when the discriminated kind explicitly allows absence; absence blocks any obligation requiring the field. Each fact's source profile pins the exact extraction; unknown fields
are forbidden. Shared correlations include environment/source instance, request/operation reference,
run/incident/candidate scope and actor/subject/resource-generation references where applicable.

| Fact kind | Required typed values |
| --- | --- |
| identity_mapping | verified issuer/subject reference, native entity reference, alias/mount reference, definition reference or human category, mapping observation |
| operation_result | operation enum (read/write/issue/deny/login), target reference, request/policy/scope digests, result enum (success/denied/unknown), denial mechanism enum, issued credential count; optional native lease reference/finite TTL seconds, permission-group and embedded-secret counts, adapter-isolation boolean and deployment digest |
| cleanup_result | exact lease/secret-generation reference, action enum (revoke/rotate), completion event reference, independent after-check result, outstanding-cleanup count |
| approval_result | exact action/resource/parameter/requester digest, native transaction reference, decision enum (approve/deny/timeout), decision/issuance ordering references, privileged issuance/effect counts |
| lineage | parent and child execution references, distinct policy/authority digests, child read and parent write event references |
| session_result | session/user reference, action enum (revoke/suspend/login/notify), existing/new-session outcomes, automatic-event correlation and notification receipt reference |
| discovery_result | candidate/source-object reference, compiled unknown-agent/user-compromise/secret-misuse/agent-compromise classification, observed activity, absent-before registry observation, finding/notification/registration event references |
| registration_result | entity/owner/ceiling references, registration reference, actual readback/policy digests, independent bootstrap/issuance/relying proof references |
| jwt_validation | original signed-token digest and still-valid expiry, issuer/audience/subject mapping refs, verifier result and exact failure mechanism; no token bytes |
| timing | exact source trigger/end event references and UTC intervals with source clock bounds |
| witness | meeting UTC time, participant role references, exact witnessed case/evidence digests, attestation reference |

Values for a row's inapplicable optional field are explicitly null and cannot satisfy an obligation
requiring that value. A verification reference must resolve to source-backed verification evidence;
setting a boolean does not make a forged identity native. Timing facts reuse required event records,
not operator-provided duration arithmetic.

Correlations bind the exact source instance/environment, criterion scope, run/incident/candidate,
actor/subject, resource generation, request and operation/lease/transaction references as applicable.
Bindings to owner-approved inventory are required; a raw source ID alone cannot join unlike namespaces.
Native confirmation requires a source review of the raw digest and extraction/profile digest; a new
review cannot turn an operator-created fact into original provider evidence.

## Assessment and CriterionRow

`Assessment`: UUID, created_at (actual), dossier revision, inventory/catalog/implementation digest,
member IDs+digests, four use-case results, fifteen rows, six F13 tests, five gate outcomes, blockers,
measurements and content digest. Empty evidence still produces every row as blocked.
`CriterionRow`: exact criterion, owner-role set, operation outcome, proof outcome, native proof
obligations with evidence refs, safe measurement values, scope, latest relevant contradictions,
optional eligible criterion review references and separate exception refs. No raw-source data in public view.

A review request cannot set computed proof outcome. Pass predicates are in the contract. Failure wins
within a scope; missing required source or unknown control yields blocked. Superseding a failure requires
an explicit new environment/test scope and linked remediation/retest, not an old passing member.
Applicability is derived at inspection: altered sealed bytes invalid; absent original live source missing;
changed implementation/context/evidence or expired current control historical; otherwise current.
Retained copied bytes can verify historical capture even when original location is gone.

## ClientExperiment and Measurement

Scenario is exactly `agent-repeat|agent-only-users|agent-obo-users|direct-users`.
`ClientExperiment`: UUID, prepared_at, environment revision/digest, scenario, baseline artifact refs,
pre-operation entity/alias inventory, exact cohort/mapping refs, source profile/schema, cluster/namespace/
mount scope, effective start/end month, billing period description, declared reporting delay, known
other consumers and expected set. Baseline original observation/acquisition times and prepared_at must
precede every execution. No post-hoc preparation can claim a controlled baseline.

`ExecutionRoster`: exactly 100 records with execution, operation and trace refs, successful source event,
scenario mode, UTC time, private verified subject (where required), actor/durable definition (where
applicable), issuance reference and actual resolved native entities. Direct scenario also requires
unique token and trace references per execution. The subject key is `(issuer, subject)`; display name,
email or token string never defines distinctness. Repeated `sub` with new token IDs is one subject.

`ActivityArtifact`: versioned JSONL and capture manifest. Fields include `client_id`, `client_type`,
namespace identity, mount accessor and first-use time using an explicitly chosen documented spelling.
Optional names/aliases/metadata remain in original private bytes and cannot enter summaries. Conflicting
first-use spellings, malformed required fields or unsupported categories cannot be silently dropped.
Manifest records requested and effective period, scope, collection completion/delay, format version,
source owner/review, byte/count digest and any provider filtering. Partial exports stay blocked.

Client identity key is `(cluster_id, namespace_id, client_type, client_id)`; mount membership is checked
separately and never used to artificially split a client key. Overlapping identical entries deduplicate;
conflicting mappings/times in the same acquisition fail. Keep separate sets: baseline active, scenario
expected/observed, newly active, reused, unrelated, missing, extra and non-entity. Category totals are
reported separately. Verify scoped membership and operation evidence; first-use time is not operation
causality. Baseline and observed exports must have identical effective reporting scope/period for deltas.

`Measurement`: UUID, experiment ref, final export/mapping/roster refs+digests, observed count sets,
per-delta evidence-backed classifications, failure/blocker reasons, provenance and source review.
At most 100 delta explanations, each with 1–32 artifact references; unresolved extra/missing clients
block incomplete attribution or fail a verified incorrect cardinality. No ± tolerance. Comparison state
is independent of final witness/customer decision. Unsupported source type never disappears from totals.

## Review, Exception and package lifecycle

Roles: `agent_engineering|verify_owner|vault_owner|vip_owner|customer_security`. Criterion owners use
these roles plus compiled supporting DB/observability/PoC-lead roles, but package signoff needs exactly
the five required roles. One person may hold several roles with separate attestation records.
Review scopes: criterion assessment or core package. Decisions: `approve|reject|blocked|agree_exception`.
Each review lists superseded review IDs explicitly; two unsuperseded conflicting decisions block.
No latest-timestamp-wins rule silently overwrites a rejection. Exception records include original
criterion ID, proposed alternative, unmet original obligations, rationale, related vendor roles and
separate customer/vendor agreement review IDs, all privately bounded by C02/C14.

`CorePackage`: UUID, assessment+criterion review/measurement digests, compiled guides, safe inventory
summary, evidence index, approved attachments, gap/readout files, file inventory and terminal seal.
It excludes original raw source files, arbitrary operator prose and credentials. File names are generated
UUIDs/compiled basenames, never source-supplied names. An attachment review is distinct from evidence
acceptance; text is bounded UTF-8, images must match PNG/JPEG signature/type, no SVG/HTML/archive ingestion.

`PackageReview`: role attestation stored in the dossier outside the immutable core, bound to core digest.
`FinalHandoff`: new UUID with exact copied core, applicable role reviews (private), final decision and
separate file inventory/seal. The seal omits its own bytes; a deterministic digest of sorted path/byte
hashes covers everything else. Inspect compares file sets, so extra files are an integrity failure.

Final state precedence: `failed` for unresolved rejection/contradiction; `blocked` for incomplete proof,
missing required measurement or unavailable prerequisite; `ready_for_review` when eligible proof/core
exists but required approvals are missing; `accepted_with_exceptions` when every original unmet item has
applicable customer/vendor agreement and all roles approve the qualified package; `accepted` only for
complete original proof and approvals. Final current acceptance additionally requires current applicability.
A historical recorded final decision remains displayed under historical scope, never as current acceptance.

Measurements also freeze implementation, complete source seals and review digests. Reports recheck current source eligibility; a later rejection cannot reuse a recorded passing count. Native deployment claims require the inventory implementation digest; lease lifetime and permission-group predicates use the actual native values, not a success label.
