# Runtime contract: Provider detection and remediation

Planned interfaces, not commands already implemented. Model constraints C01–C18 in
[data-model.md](../data-model.md) are normative. All new authority is local operator or
explicitly enrolled automation; model/browser input never selects a provider action.

## Private files and migration

- `.local/response/state.json`: ResponseJournalV2, with embedded enrollment and action ledger.
- `.local/response/anchor.json` and `policy.json`: existing v1 authority, unchanged by migration.
- `.local/response/providers.draft.json`: strict operator draft, not active authority.
- `.local/response/provider-secrets.json`: fixed alias-to-secret map for Teams capability URL
  and optional dedicated DB control/proof DSNs. Reject symlinks, broad permissions and
  unexpected keys; parse as secret values. Never expose file content or paths in browser.
- `.local/response/evidence/`: private, size-limited evidence/receipt files. Imports are
  explicit local operations, never URLs. Raw source evidence stays outside the journal.

`respond migrate` requires stopped workspace/response workers, nonblocking ownership checks,
existing valid enrollment/anchor and quiescent roots. Acquire locks in the plan's order,
validate old bytes, reserve output, fsync temporary owner-only file then atomic replace
of state.json and directory fsync. Failure before replace leaves v1 intact; failure after
replace is detected by reading version/digest. Rerun is idempotent, never wipes state.
No migrated incident acquires native actions. New admission rejects v1 with a migrate
instruction; v1 status/known-handle cleanup remain available.

## CLI

All commands extend `uv run agent respond` and use the existing Settings loading of
`.env.local` where provider configuration is needed. Never pass secrets in flags.
UUID/revision placeholders below mean exact IDs printed in private local status.

| Command | Effect and result |
| --- | --- |
| `migrate` | Offline response v1→v2 only; no provider request |
| `providers prepare` | Create a mode-0600 draft template if absent; never overwrite active policy or secrets |
| `providers readiness` | Local validation plus bounded read-only provider metadata/capability queries; never credential issuance, rotation, termination, send or suspension |
| `providers enroll --revision N` | Quiescent, explicit local activation of validated draft in one snapshot transaction |
| `providers status [--incident UUID]` | Disk-only safe per-control report and exact next actions |
| `providers reconcile --incident UUID --revision N` | Bounded read-only state/readback evidence; no mutation, credential read, issuance probe or resend |
| `providers retry --action UUID --revision N --operator LABEL` | Explicit retry decision; recheck exact target/predecessor/holds and current state, create new linked action if safe; never reset history |
| `providers import --file PATH --incident UUID --revision N --operator LABEL` | Validate private bounded observation envelope, source digest and exact correlation; record review separately from assertion |
| `providers probe --incident UUID --revision N --scenario NAME --operator LABEL` | Explicit authorized live proof with fixed scenario/targets and bounded subprocess ownership; secrets through private stdin/in-memory context only |
| `release --definition NAME --incident UUID --revision N --operator LABEL` | Existing local release extended to provider/subject holds and proof; no external re-enable |

Exit codes: 0 completed requested local/read-only operation; 2 invalid input; 3 blocked
prerequisite or unsafe/stale revision; 4 provider/proof partial or uncertain. JSON reports
use their declared schema version and closed `reason_code`, `owner_role`, `next_action`
and `rerun_command`; never arbitrary provider error strings. Status may exit 0 while
reporting blocked actions because it successfully read state. Enrollment cannot silently
activate a missing-authority control: disabled optional bindings remain explicitly disabled;
requested required actions must pass readiness before enrollment. Readiness success is
configuration/permission readiness, never a claim of native enforcement.

Probe scenarios: `same_jwt`, `fresh_issuance`, `native_token`, `user_sessions`,
`dynamic_database`, `static_database`, `notification_delivery`. Unknown scenario fails
before network. A `--scenario` does not take arbitrary URLs, SQL or command strings.
Proof preparation that needs before-state must start before incident submission: the
probe command for a not-yet-contained registered root accepts `--root UUID` instead of
`--incident`, registers a one-use private probe session and waits up to 120s for the
matching incident. It prints only that probe is ready. A live operator can then use the
existing submit command; native acceptance requires the actual enrolled native event.
After an incident, missing prior observations produce inconclusive rather than invented
pre-state. No proof connection or credential is persisted for restart.

## Provider enrollment fields and capability rules

Common fields: schema version, expected installation/environment, revision, pinned issuer,
source profiles, rule predicates, target bindings, action dependency set, resource generations,
recovery policy and private secret aliases. `providers.example.json` contains only synthetic
IDs and no credential-shaped sample values. A source profile owns a distinct native source
namespace/audience, exact issuer/subject, allowed target scopes, native schema/fixture digest,
collector review reference and scalar pointers. Reuse 006 verifier rules: required signed
access-token type, signature/JWKS, issuer/audience, iat/exp <=300s, 30s allowed clock skew and
`response:submit` scope. Neither workspace nor task audience is accepted.

Source aliases cannot collide with 006 source aliases. Rules use exact equality, fixed
reason/scope, at most 64 source-object mapping entries per profile, and at most one mapped
Verify user per rule. They select binding IDs already in enrollment. Root mapping first resolves the enrolled definition/resource and then matches a native
correlation field against the host-registered request ID and verified binding. There must
be exactly one matching root; enrollment does not hard-code root UUIDs before they exist.
Definition mapping resolves to the stable configured workload. Identity aliases/usernames/IP addresses are not authority. Unmapped/ambiguous
identity rejects before hold/effect. Enrolling a rule that would widen a root's scope fails.
Sources cannot request provider release, change policy or append token/session handles.

Readiness validates fixed destinations, feature availability, exact registration/entity/actor,
user type and permissions, role isolation, required evidence and recovery route. Query
Vault self-capabilities only for selected fixed paths; permission flags are a hint and
parameter restrictions still apply. Verify exact user readback/entitlements; DB version,
role ownership/visibility and fixed termination privileges. Teams URL-only readiness can
validate local configuration/owner evidence but cannot prove delivery without a send.
Never read `static-creds` or dynamic creds during readiness. Missing checks give bounded
closed dispositions: `not_enrolled`, `mapping_missing`, `missing_authority`, `unsupported`,
`source_evidence_missing`, `destination_invalid`, `provider_unreachable`, `proof_required`.

## Native intake

`POST /response/native/{profile_alias}` on existing loopback response service/port.
Authorization is bearer JWT, not a browser cookie; no CORS or administrative GET surface.
Strict bounded JSON object is projected using the enrolled schema into event ID/time,
reason, rule and source-object key. Allowed transport-only fields may be ignored, but
unknown security fields and unmapped/secret fields are never copied to state. Limit all
input bytes/depth/scalars before projection, disable compressed bodies and reject non-JSON.

Response after durable hold/immutable plan: 202 new incident, 200 unchanged duplicate;
body `{schema_version:1, incident_id:UUID, disposition:accepted|duplicate}`. Errors: 400
malformed/invalid projection, 403 source/rule invalid, 404 unknown enrolled target/profile,
409 event/policy conflict, 413 oversized, 422 stale event, 429 capacity, 503 storage/worker
unavailable. Return only fixed reason/next-action fields. Missing authentication never
reveals profile/target existence. Deduplication survives restart/30-day retention; older
replays are rejected by freshness after pruning. Canonical security content excludes retry
metadata but includes profile revision, source event/rule/target/time and mapped reason.
No accepted response is returned if durable containment/reservation failed.

## Provider adapters

All adapters receive immutable action/binding plus injected secret authority, return closed
outcomes and bounded private observations. They do not choose targets, repeat mutations,
follow redirects, fall back to ambient proxy settings or treat upstream messages as output.
No model tool exposes these adapters. Endpoints are pinned to enrollment/settings; path
segments use existing strict Vault path validation or percent-encoded opaque Verify IDs.

| Action | Request | Readback and limits |
| --- | --- | --- |
| block_registration | Vault DELETE `/v1/agent-registry/registration/id/{id}` | Exact registration metadata GET/absence; Enterprise 2.1+ capability required; same-JWT/fresh issuance remain separate probes |
| revoke_native_token | Vault POST `/v1/auth/token/revoke-accessor` with exact accessor | Exact lookup-accessor observations; exclusive prospective service-token tree only; absence alone not causal proof; batch/external OAuth not eligible |
| revoke_exact (006) | Existing synchronous exact lease revoke | Join original recovery receipt/proof; no prefix-wide revoke, no fabricated cascade completion |
| suspend_user | Verify PATCH `/v2.0/Users/{id}` replacing `active=false` | GET exact user and observe supported inactive value; do not claim upstream identity suspension |
| revoke_user_sessions | Verify DELETE `/v1.0/auth/sessions/{userId}` | GET exact user's session list; permissions `manageLoginSessions`/`revokeAllSessions`, read requires `listSessions`; no automatic retry that could kill newer sessions |
| rotate_static | Vault POST `/v1/{mount}/rotate-role/{role}` | Role metadata plus independent credential probes; never rotate-root, re-create role or restore old password |
| terminate_static_sessions | Fixed parameterized PostgreSQL termination | Exact isolated role/database and rechecked PID/backend_start, positive bounded timeout, independent connection observation; no shared/pool/admin target |
| notify_teams | POST enrolled private Workflows URL, URL-only mode | No Authorization header; allowlisted Adaptive Card; 2xx accepted, imported correlated receipt for delivered |

For DB termination, the privileged function is PID-addressed: rechecking backend_start
reduces mistaken reuse but is not an atomic native identity fence. Require an isolated test
role, reject any ownership change, and label this limit in live evidence; never claim a
shared production-safe kill mechanism. Permission to execute a function does not prove
permission to signal every backend. Exceeding the session bound sends no termination and
reports capacity; enumeration is bounded and nontruncating.

## Plans, retries and recovery

Local containment is unconditional once an authorized signal is accepted. Provider plans
snapshot required actions; missing authority later leaves a partial incident with local
holds. Root-only plans cannot contain user, registry or static actions; advisory notices are allowed.
Notices deduplicate per incident/revision/destination generation, never across all incidents
using one workflow. Security actions use the canonical native resource identity; enrollment
rejects duplicate aliases for that resource. Definition plans
block registration/suspend mapped user first, then existing-access operations. Dynamic
cleanup joins ordinary cleanup after owner drain; one shared lease receipt is reused.
Notification is advisory and cannot delay cancellation or make partial enforcement green.

Native login has its own pre-dispatch acquisition intent with trusted ownership. An
unknown accessor after reply loss remains an unresolved acquisition, never an empty
inventory. Binding succeeds durably before the native token is returned.

Before network, commit submitted intent and resource fence under short control ownership.
One worker owns the effect lock for provider mutations and secrets; release control before
network. Persist response/readback afterward. Lost persistence means uncertain. A known
HTTP rejection is denied/failed with a closed code; absence of a reply is uncertain.
Only unsubmitted work may run automatically after restart. Read-only reconcile can show
current desired state without claiming the original request caused it.

Retry requires current enrollment/journal revision and exact predecessor; read back first,
review possible newer sessions/rotations, and create a linked action only on explicit local
request. Never clear uncertainty by changing a status flag. Policy/binding generation
advancement is rejected until required old effects/proofs are resolved. Release checks all
holds and fresh provider/old-token safety observations under maintenance ownership; proofs
used for release are no older than 300s unless they establish an immutable past event plus
a recorded still-valid lifetime bound. No bearer/API/browser release route is added.

The supported restoration route is to prove minting ceased and the complete maximum
old-token lifetime plus skew elapsed before restoring the same actor binding.
The finite bound must cover every enrolled old token class, not just one observed JWT.
If it is unknown, remain blocked. New actor/client configuration is sealed into existing
response/recovery environment digests; 007 does not supply that multi-store configuration
migration. Never offer reinitialization or state deletion as a new-identity recovery path. Same-identity registration
must not be restored merely because local cleanup completed. User suspension/session
recovery receives the same explicit review; ordinary sign-in cannot clear subject holds.

## Evidence, timing and presentation

`ProviderObservationV1` imports bind exact installation, environment, implementation revision,
enrollment, action, resource generation, source digest and reviewer/time. Maximum import
size is 1 MiB; metadata strings follow C02/C03 limits. Replayed identical evidence joins;
changed digest under the same observation ID conflicts. Reads cannot import files implicitly.
Keep raw evidence private; journal stores typed observations/digests, never credentials.

Same-JWT proof must show pre-success, verified actor/user/audience/expiry, unexpired post-
request, provider authorization denial and a healthy control. Each negative request has a durable ProbeAcquisition intent, separate from 005 production
recovery. Only a definitive authenticated 401/403 from the pinned endpoint, with no returned
credential material, closes denied_no_issuance. TLS/transport failure, parse failure or a
success without a valid handle remains uncertain. Unexpected acquisition first persists
its exact handle in the probe journal, then adopts it into existing recovery and exact cleanup.
The adoption API accepts only a validated local probe record, copies original operation ID,
intent/dispatch times and trusted ownership, and is idempotent by probe operation ID. Under
effect ownership, write recovery first, then link it in response; on restart rediscover the
existing recovery operation. Pin the probe until a confirmed receipt is linked. Missing or
conflicting copies block recovery; never synthesize a native receipt. This narrow trusted
adoption does not change 005 live acquisition-denial rules or prove native audit linkage. Network bans,
timeouts, expiry, local guard failure and missing subject mapping are inconclusive.
Existing DB session proof must use an independent probe process; application cancellation
or probe process exit is not native closure proof. Static proof separately records rotation
acknowledgment, old-login denial, replacement login and old-session behavior.

Record source event/detection, local receipt, decision, each dispatch/ack and each observed
access loss separately. Cross-source clocks need recorded error bounds; publish an interval
with uncertainty and claim below-baseline only if its upper bound is below 30 minutes.
Across restart or missing clock evidence, report unavailable. No average hides an unblocked path.

Workspace summary: incident UUID, coarse scope, closed control/proof/reason codes and valid
durations for its verified owner. Anonymous view is aggregate only. Private CLI may list
safe binding aliases; no native IDs, URLs, usernames or raw messages in shared projections.
Telemetry uses fixed action/result categories and opaque incident/action IDs only. All new
private shapes must be rejected by staged-tree and distribution privacy tests even if renamed.

### Final additive fields and retry execution

Native intake acknowledgment contains only `schema_version`, `incident_id` and
`disposition` (`accepted` or `duplicate`). Root projection requires exact
`object_bindings` attribution and fences the captured enrollment digest during commit.
Public session-owned summaries may contain `database_checks` with `dynamic_fresh` and
`dynamic_session` closed proof results; no username, backend ID, lease or source text.

Explicit retry performs bounded exact metadata readback first where safe. It reconciles
already-applied state or creates a reviewed linked successor and runs the ordinary bounded
worker once. It never resets/replays the predecessor. Teams and static rotation omit unsafe
readback assumptions; uncertain rotation remains blocked. Private proof stdin is a strict
`ProofInput` object; no URLs, SQL, modules or executable selectors can be supplied. Verify
session proof requires the enrolled reviewed `session_id_field`/`session_schema_digest`.
