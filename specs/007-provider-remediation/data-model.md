# Data model: Provider detection and remediation

Private boundary models remain strict, immutable Pydantic contracts with extra fields
forbidden. Public projections are separate allowlists. Existing 006 models remain valid
inside explicit legacy variants; existing recovery models are not repurposed as provider proof.
The constraints below are normative and quoted in their owning implementation tasks.

## Entities and relationships

**ResponseJournalV2** preserves anchor linkage, roots, definition generations, holds,
incidents, releases and old action records. Adds an embedded provider enrollment, resource
bindings, provider actions, observations and notification records. Migrated incidents
have `provider_mode=legacy_local_only`; new incidents snapshot the active enrollment
revision. Empty provider enrollment means local-only behavior, never missing-state repair.

**ProviderEnrollmentV1** contains revision, installation/environment/source-policy digests,
source profiles, resource bindings, rules, action permissions and capability records.
Only the local OS operator can enroll; a draft is not authority. Secret references point
to a fixed private secret store, not to event-supplied files or environment-variable names.

**SourceProfileV1** binds a distinct authenticated source alias, pinned issuer/subject and audience to one native schema
revision, constrained extraction pointers, equality predicates, target lookup entries (at most 64), optional host request-ID correlation pointer,
collector evidence reference and provenance disposition. The wire payload is processed
in memory; only normalized fields and a canonical digest enter state. Enrolled native
provenance is reviewed separately from sender authentication.

**SubjectHoldV1** binds a verified issuer/subject, definition, originating incident and
generation in the same transaction as containment. It has no remote release operation;
all matching admission checks and workspace sessions observe it. Retention follows the
incident hold, never browser-session lifetime.

**ResourceBindingV1** identifies an exact Vault actor registration/entity, native service
accessor, Verify tenant user, isolated static database role or Teams workflow destination.
It includes definition, optional trusted root owner, verified subject mapping, provider
origin/namespace, resource generation, capability disposition and immutable private native
handles. Actor identity comes from verified actor claims, not the root's human subject.
Root attribution is added only by trusted runtime registration/capture, not policy edits
while a root is active. Dynamic lease ownership remains in recovery v2. Static DB mappings name an isolated role;
no direct termination is inferred from legacy lease records.

**NativeTokenAcquisitionV1** records an acquisition UUID, complete trusted root/request/
actor ownership, pinned login mount/role, enrollment/resource generation and intent time
before native login. States are intent, submitted, bound, denied and uncertain; successful
binding links an exact service accessor. Missing reply or persistence failure retains an
uncertain acquisition without guessing the accessor. It participates in inventory, retention
and release gates separately from recovery lease attempts.

**ProbeAcquisitionV1** is a separate private response record, with acquisition UUID,
trusted ownership, original intent/dispatch times, fixed requested path, scenario, enrollment
and source digests, state and optional private lease handle. It closes definitive denial
without altering 005 production acquisition rules or claiming native audit evidence. A
successful response stores its handle durably before adoption into exact recovery; neither
a model nor browser can use it. States are intent, submitted, denied_no_issuance, issued,
cleanup_pending, cleaned and uncertain. The probe record remains pinned until its linked
recovery record/receipt is confirmed.

**ProviderActionV1** links incident(s), binding generation, enrollment digest, effect kind,
required/advisory classification, dependencies, prior-action reference, timestamps and
state. Cross-incident references join one resource operation; they do not copy dispatch
permission. Mutation state and effect proof are separate fields.

**ProviderObservationV1** binds installation/environment/implementation/enrollment digests,
incident/action/resource IDs, path kind, time, source digest and result. It labels source
as synthetic, live behavioral probe, provider readback or native source evidence. Native
source evidence may be imported privately with explicit reviewer/time; it does not
rewrite acceptance.json or authenticate the reviewer's identity.

**NotificationV1** has incident/revision, generated notice UUID, bounded card digest,
submission state and optional independently reviewed delivery receipt. Endpoint secrets
and provider text never appear in projections. **RecoveryDecisionV1** records the local
operator, expected revision/complete hold set, exact action predecessor and selected
retry or recovery disposition. It is an audit record, not a remote authorization token.

## Exact validation constraints

- **C01**: `ResponseJournalV2.schema_version = 2; response anchor and source policy stay at 1; recovery journal/attempt stay at 2 and recovery anchor/receipt stay at 1.`
- **C02**: `UUIDs identify incidents, actions, observations and bindings; revisions and resource generations are strict positive integers; digests are 64 lowercase hexadecimal characters; timestamps are timezone-aware UTC.`
- **C03**: `Enrollment allows at most 16 source profiles, 32 rules and 64 resource bindings; aliases match ^[a-z][a-z0-9-]{1,31}$; native identifiers are nonempty strings of at most 256 characters.`
- **C04**: `Native bodies are at most 65536 bytes, depth 8 and 128 scalar fields; profiles allow at most 8 scalar JSON pointers of at most 256 characters and 8 equality predicates; no scripts, recursive selectors or URL fetching.`
- **C05**: `Event IDs match ^[A-Za-z0-9_-]{1,128}$; events may be at most 300 seconds old or 30 seconds in the future; duplicate identity is source alias plus event ID; changed canonical security content conflicts.`
- **C06**: `Target scope is root_run or definition; root_run permits cancel_local, revoke_exact and revoke_native_token with exclusive trusted ownership plus advisory notify_teams; shared security controls never widen scope.`
- **C07**: `Provider action kind is block_registration, revoke_native_token, suspend_user, revoke_user_sessions, rotate_static, terminate_static_sessions or notify_teams; each action pins one binding generation and enrollment digest.`
- **C08**: `Action state is planned, submitted, acknowledged, denied, failed, uncertain or reconciled; a submitted action is never automatically resubmitted; restart converts unfinished submitted actions to uncertain.`
- **C09**: `Proof state is not_run, proven, disproven, inconclusive, unsupported or not_applicable; HTTP acceptance, timeout, disappearance and token expiry alone never prove enforcement.`
- **C10**: `Security-action deduplication uses canonical provider resource, resource generation and action kind; notices use incident UUID, notice revision and destination generation; unresolved predecessors and bindings cannot be pruned or superseded.`
- **C11**: `The snapshot limit is 16 MiB; retain at most 1000 roots, 1000 incidents and 16 non-settled incidents; allow 101 legacy/local actions plus 16 provider-action references per incident and 16 observations per provider action.`
- **C12**: `Provider workers have a 120-second total attempt budget including owner drain; each network call has a 10-second deadline and 256-KiB response cap; read-only reconciliation makes at most 3 calls per action per invocation; mutation attempts never auto-retry.`
- **C13**: `Database session selection requires an enrolled isolated role, database, PID and backend_start; at most 32 sessions may be selected and each termination uses a positive timeout of at most 5000 milliseconds.`
- **C14**: `Teams cards are at most 8192 bytes and contain only notice UUID, incident UUID, coarse scope, closed outcome codes and valid durations; links, mentions, images, actions and source text are forbidden.`
- **C15**: `Private drafts, secrets and state use owner-only files beneath .local/response; secrets never enter command arguments, journal observations, browser output, logs or telemetry; URLs must be fixed enrolled HTTPS origins with redirects disabled.`
- **C16**: `Local durations use monotonic time within one process; cross-system intervals require recorded UTC clock bounds of at most 5 seconds per source; negative, expired-proof or cross-restart unbounded intervals are unavailable.`
- **C17**: `Release requires the current enrollment and journal revisions, complete hold set, drained owners, resolved required actions, no unresolved attributable recovery and reviewed old-credential safety; old roots remain terminal.`
- **C18**: `Retain resolved provider records for 30 days; pin unresolved actions, holds, observation references and resource generations without age-based deletion; capacity exhaustion rejects new intake before effects.`

- **C19**: `Each native profile has at most 64 object mappings, a distinct audience/source namespace and an exact pinned issuer/subject; root correlation must match one host-registered request and its verified binding.`
- **C20**: `Observation imports are at most 1 MiB; identical observation IDs require identical digests; release observations are at most 300 seconds old unless an immutable event and finite credential-lifetime bound establish safety.`

- **C21**: `Native token acquisition intent is durable before login; states are intent, submitted, bound, denied or uncertain; at most 64 unresolved acquisitions are retained; unknown accessors prevent complete inventory and release.`

- **C22**: `Enrollment rejects duplicate canonical resources keyed by pinned origin, namespace, resource type and native ID, even when binding UUIDs or aliases differ.`
- **C23**: `Probe acquisition intent precedes dispatch; at most 16 active probes exist; authenticated definitive 401/403 without credential material closes as denied_no_issuance, while timeout, malformed reply or missing handle remains uncertain and blocks release.`

## State transitions and ownership

Enrollment: prepared draft → validated/read-only capabilities → explicit local enrollment.
Capability observations distinguish supported, missing_authority, unsupported and unverified;
permission discovery is not successful enforcement. Native source activation requires
reviewed route/schema/collector evidence and exact mappings. Synthetic fixtures cannot
supply that native disposition. Enrollment with no source adapter still supports explicit
local operator scenarios; these remain operator-originated, never VIP-originated.

Actions: planned → submitted (durably before network) → acknowledged/denied/failed/uncertain.
Reconciliation adds a read-only observation and may set reconciled when the exact desired
state is independently known; causation remains unavailable when no evidence establishes it.
A provably undispatched planned action can resume automatically. An acknowledged control
has its own proof state; overall required enforcement remains partial until applicable
proof is proven. Blocked capability is represented by unsubmitted action plus closed
reason/proof unsupported or not_run, not a fictitious successful provider call.

After uncertainty, explicit retry creates a new linked action, never resets the predecessor.
The operator must inspect current state, exact target generation and possible effects on
new sessions first. The predecessor remains retained and is resolved only by a separate
observation or reviewed uncertainty disposition. Such a disposition permits safe recovery
only when the required access-denial/old-credential proof also exists; it cannot create a
native acceptance pass. Advancing a resource generation is an explicit recovery/enrollment
operation after prior required actions resolve; duplicate incidents cannot rotate it again.

Native service-token acquisition intent precedes HTTP dispatch; trusted ownership is
required on enabled live native-login paths. Binding is prospective, before returning a successful workload login
to a caller, and records accessor/type plus complete descendant ownership. Shared parents,
batch tokens and external OAuth JWTs cannot be represented as exactly revocable service
tokens. An acquisition lost before binding is uncertain and prevents complete inventory.

Existing dynamic leases use their recorded recovery owner. Direct SQL termination is only
for an explicitly enrolled isolated static role; dynamic session closure uses existing
Vault role revocation SQL and separate observation. No migration guesses a DB username.
Live proof credentials and open connections stay in a bounded trusted probe process; a
restart loses them and leaves proof inconclusive. The probe is not the application root
whose cancellation would otherwise masquerade as provider-enforced session closure.

## Atomicity and compatibility

An explicit offline migration replaces only response state.json after taking maintenance
ownership and verifying root/worker drain. It preserves source policy/anchor/recovery bytes.
Old binaries reject schema 2 rather than admit roots without provider guards. New binaries
allow v1 read-only status and existing exact cleanup, but require migration before new
response admission. No provider work is backfilled into pre-migration incidents.

Enrollment copies a validated draft into the v2 snapshot in one atomic replacement. It
never requires coordinated policy.json/state.json updates. Binding/enrollment changes are
forbidden while roots, workers or unresolved provider actions exist. Provider enablement cannot change the enrolled 006 source policy. Native profiles use
a distinct audience/source namespace and the configured pinned issuer; normalized 006
source permissions are unchanged even when the existing mode is local_only. Store reserves worst-case result space before
intake acknowledgment and checks the actual serialized byte budget on every commit.

## Implemented contract refinements

The response schema remains 2. `SourceProfile.object_bindings` supplies exact binding UUIDs
for root object/request correlation. `ResourceBinding.session_id_field` and
`session_schema_digest` record an independently reviewed tenant session-list shape;
`destination_digest` fences Teams host/path independently of signature rotation.
`ProbeAcquisition.credential_class` distinguishes `vault_lease` from `oauth_jwt`; the latter
stores only credential digest and verified finite expiry, never a token or lease. Issued
JWTs stay pinned until expiry plus skew; this is lifetime safety, not enforcement proof.
Dynamic observations join the existing exact cleanup action through prospective probe
ownership. Safe summaries add `database_checks` with closed dynamic-fresh/session outcomes.
`ProviderAction.scope` preserves the original scope in every successor notice/control;
`attempt_ms` is one-process monotonic elapsed time, distinct from bounded source intervals.
