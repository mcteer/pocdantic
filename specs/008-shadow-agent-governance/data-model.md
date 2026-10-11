# Data model: Shadow Agent Governance

All models are strict, frozen Pydantic boundaries with unknown fields forbidden. Private
models suppress native values in repr/errors. Public projections use explicit allowlists.
The numbered constraints below are normative; tasks quote them to avoid implementation
choices changing the security contract.

## Shared constraints

- **C01**: UUIDs are canonical; revisions/generations are strict positive integers; digests are 64 lowercase hex characters; timestamps are timezone-aware UTC.
- **C02**: Aliases match `[a-z][a-z0-9-]{0,30}`; private identifiers are 1–256 characters; owner/purpose text is 1–256 characters; public labels are generated aliases only.
- **C03**: HTTPS origins are exact and reviewed; paths contain no traversal, query, fragment or embedded credentials; namespace is exact; redirects and token-selected URLs are forbidden.
- **C04**: There are at most 16 sources, 1,000 candidates and 10,000 observations; the journal is at most 32 MiB; unresolved records are pinned and resolved cases retain all linked evidence for 30 days after closure.
- **C05**: Input is at most 64 KiB, JSON depth 8 and 128 scalars; projection has at most 12 scalar JSON Pointers of at most 256 characters and 8 fixed predicates; compressed bodies are rejected.
- **C06**: Relay tokens have exact enrolled issuer/subject/audience and `governance:observe` scope; age and lifetime are at most 300 seconds with at most 30 seconds future skew; event age is at most 300 seconds for automatic intake.
- **C07**: Network calls are at most 10 seconds and 256 KiB; effect workers are at most 120 seconds including drain; one local effect worker is active; at most 16 unresolved credential intents exist.
- **C08**: Private directories are mode 0700 and regular files 0600 owned by the current user with one hard link; symlinks, inode replacement and non-atomic state replacement are rejected.
- **C09**: Reviews/readiness expire after 300 seconds; imports are at most 1 MiB; at most 32 evidence references attach to one candidate; changed evidence/configuration invalidates dependent reviews.
- **C10**: State enums are closed: candidate `prepared|observed|reviewed|enrolling|registered|blocked|closed`; attempt `prepared|submitted|confirmed|denied|uncertain|conflict`; proof `pass|fail|blocked|inconclusive`; provenance `synthetic|operator|native`.
- **C11**: Registration has one exact entity, operation-reserved name, owner, description, 1–8 ceiling policies and explicit default/RAR flags; create never includes an existing registration ID.
- **C12**: Trust uses one pinned algorithm from `RS256|RS384|RS512|ES256|ES384|ES512`, one audience of at most 256 characters, one exact SPIFFE ID of at most 255 characters and one exact entity; maximum SVID lifetime is 300 seconds and clock leeway is 30 seconds.
- **C13**: JWT compact input is at most 16 KiB; headers allow only `alg`, `kid`, `typ`; `typ` is absent, `JWT` or `JOSE`; `kid` is required and at most 128 characters; `iss`, `sub`, `aud`, `iat`, `exp` and `vault.entity.id` are required.
- **C14**: JWKS has at most 16 usable public keys, a 60-second freshness ceiling and a 10-second unknown-key refresh throttle; duplicate key IDs, private key material, wrong key usage and ambiguous matches are rejected.
- **C15**: A relying challenge is 32 random bytes, expires after 60 seconds and is consumed once; only its digest is persisted; requests/results are bound to candidate, profile generation, attempt and implementation digest.
- **C16**: Each effect reserves 256 KiB of journal capacity before dispatch; recorded results consume that reservation; pruning never removes unresolved work or breaks reference closure.
- **C17**: Five authorization probe paths are fixed: preregistration, OBO allowed, OBO beyond ceiling, direct allowed and direct denied; targets are exact dedicated KV-v2 data reads, never credential-issuing or arbitrary write endpoints.
- **C18**: Native chronological proof requires clock bounds of at most 5 seconds per source, correlated registry absence, captured activity, received collector evidence and detection's latest possible time before registration's earliest possible time.

- **C19**: RS keys are at least 2048 bits; EC curves match ES256/P-256, ES384/P-384 or ES512/P-521; only signature-verification key operations are accepted.
- **C20**: `aud` is one string or a singleton list matching the configured audience; time claims are strict finite integers with `exp>iat`, `exp-iat<=300`, `iat<=now+30` and `exp>now`; optional `nbf` is validated.
- **C21**: Credential intent kinds are `actor_oauth|obo_oauth|svid`; tokens are memory-only; unknown lifetime bounds remain unresolved rather than expiring automatically.
- **C22**: Candidate direct OAuth requests carry exact `vault:path_access` authorization details; verified JWTs require the exact candidate issuer/subject/audience and requested details, with no `act` claim; no RAR downgrade is allowed.
- **C23**: The relying socket is mode 0600 under the private directory; its JSON envelope is at most 64 KiB; access/body logging and browser listeners are disabled.

- **C24**: Confidence is a finite numeric source value, a label of 1–64 characters or absent; it is never compared across sources; native classification/event kinds must match the enrolled fixed predicates.
- **C25**: Registration fixes `no_default_ceiling_policy=true` and `optional_authorization_details=false`; ceiling policies exclude `root`; exact SPIFFE IDs reject userinfo, port, query, fragment and dot segments.

- **C26**: A lost issuance needs provider evidence or an independently reviewed server-completion bound to establish its last possible issuance time; client timeout and worker exit alone do not establish that bound.

## Private entities and relationships

### GovernanceAnchor / GovernanceJournalV1

Fixed `.local/governance/anchor.json` identifies the installation and original deployment
digest; `state.json` contains schema version 1, monotonic revision, immutable activated
source/trust profiles, candidates, attempts, proofs, nonce digests and bounded reviews.
Separate `control.lock`, `effect.lock` and `service.lock` coordinate short transactions,
effect lifetime and the relying service. No change to recovery/response journal versions.
A damaged, missing or incompatible established anchor fails closed. Prepare uses exclusive
creation; it never resets state. Sources can be revised only without active effects,
unexpired credential intents or unclosed candidates using that source generation.

### DiscoverySourceProfile / Observation

Profile pins product/version, source-instance identifier, schema reference/digest,
fixture digest, collector receipt digest, relay issuer/subject/audience, fixed selectors,
classification predicates and source clock bound. The separate audience must differ from
workspace, actor, Vault, response and remediation-native audiences.

Observation key is `(source-generation, source-event-id)`; private source-object key joins
findings only within that source instance. Selected-content digest includes object key,
classification, confidence, event type, times and test correlation. Free transport/display
fields cannot affect identity or authority. First source observation and receive time are
immutable. Lifecycle updates are new events with their own provenance. Schema supports
unknown/discovered, managed, triaged and notification receipts only when the reviewed
native profile defines them. Secret-bearing fields are rejected, including ignored ones.

### Candidate / ControlledCase

Local UUID, generated alias, immutable originating observation IDs (empty only while prepared), source object mapping,
case correlation UUID, lifecycle state and local revision. An approved private binding
contains owner viewer `(issuer, subject)`, accountable owner reference/purpose, workload
logical ID, OAuth issuer/subject/client reference, exact Vault origin/namespace/entity/alias,
OAuth profile digest, reserved registry name and policy digests. Raw owner names and native
IDs never enter public labels. Discovery claims cannot populate the approved binding.

A controlled case is created before any safe activity; it records exact registry absence
for both entity and reserved name, activity request digest/times, healthy result and source
receipt. Imported older findings may exist without a controlled case but cannot establish
native pre-registration discovery. Distinct claimed objects require explicit reviewed
identity binding; no display-name/email/hostname merge is allowed.

### EnrollmentReview / RegistrationAttempt

Review binds candidate revision, source evidence, owner decision, settings/environment,
readiness metadata, exact request payload and policy/role/trust digests to operator and
review time. Decision is consumed once. Attempt adds UUID, submitted/finished times,
private registration ID when returned, provider request reference, acknowledgement and
readback digests. Current matching presence after a lost response is retained separately
from proven creation ownership. An uncertain/conflicting registration pins the candidate;
404 readback alone never permits replay. Explicit resolution imports correlated provider
records and a new review; confirmed presence can then be adopted without another POST.
No deletion, update or automatic rollback API belongs to this model.

### TrustProfile / CredentialIntent / RelyingProof

Trust profile binds candidate entity, direct OAuth bootstrap, metadata/policy/role digests,
SPIFFE config/trust domain, exact expected issuer/subject/audience/algorithm, fixed discovery
and OIDC JWKS URLs, role maximum TTL and independently reviewed issuer maximum OAuth TTL.
OIDC JWKS uses public signature keys (`use=sig`); SPIFFE bundle `use=jwt-svid` is not accepted.
RS keys are at least 2048 bits; EC curves match ES256/P-256, ES384/P-384 or ES512/P-521.
Only signature-verification key operations are accepted. `aud` is one string or a singleton
list matching the configured audience; time claims are strict finite integers, `exp>iat`,
`exp-iat<=300`, `iat<=now+30`, `exp>now`; optional `nbf` must be valid. The exact URI is
validated as a SPIFFE ID with no userinfo/port/query/fragment or dot-segment tricks.

Credential intent kinds are `actor_oauth|obo_oauth|svid`; raw tokens remain memory-only.
Intent records possible dispatch interval, current profile digest, maximum issuer TTL,
received token digest/verified expiry when available and resolution. Submitted uncertainty
expires only after last possible dispatch completion plus independently reviewed maximum
TTL plus 30 seconds, or the later observed expiry plus 30 seconds. Unknown bound or drift
stays pinned; elapsed time is never proof of denial. Worker drain must be established,
but cannot prove when a timed-out server finished. Apply C26 before calculating any
unobserved-token lifetime bound; otherwise require correlated provider evidence.

Relying proof stores nonce digest, candidate/generation, token digest, trust snapshot
fingerprint, safe verification result and server observation time. The separate service
checks current enrollment and consumes the challenge atomically before returning the
result. A failed request consumes its challenge too. No SVID or claims object is returned.

### PermissionProof / NativeReview / PublicSummary

Proof includes case/attempt UUIDs, exact candidate and generation, profile/policy/request
fingerprints, before/after readbacks, provider result category, healthy control, mechanism
attribution and source evidence digests. HTTP 403 alone does not identify the policy layer.
Each F11 test has independent predicates. Latest contradictory qualifying evidence wins;
old generations and stale implementations cannot certify current state.

Public summary contains schema version, local UUID/alias, state, safe reason/action code,
counts, times and separate discovery/registration/identity/permission/native-triage results.
Only host-reviewed owner mappings authorize browser access. Operator summary may enumerate
local aliases but uses the same safe projection. Raw imports are retained through existing
private validation artifact storage; their data is never embedded in summary output.

## Transitions and retention

`prepared → observed → reviewed → enrolling → registered → closed` is the successful path. `blocked`
is entered on drift, containment, conflict or unresolved effects; a new revision-bound
review can return to the last proven state, never skip a missing proof. An unrelated
finding can be locally triaged/closed without becoming registered or native-managed.
Effect states are append-only attempts; submitted-after-restart becomes uncertain.
No automatic retry. Complete reference closures are pruned after retention, only if no
open case, unexpired credential or unresolved reference pins them. If capacity cannot be
reserved, reject new work before dispatch; never sacrifice unresolved records.
