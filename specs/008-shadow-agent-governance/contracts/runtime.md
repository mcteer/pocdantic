# Runtime contracts: Shadow Agent Governance

These are planned 008 interfaces. Existing response and recovery interfaces keep their
contracts. All bounds and private fields in [data-model.md](../data-model.md) are normative.
No governance entry point is a model tool or accepts a model-selected provider target.

## Operator CLI

Prefix each command with `uv run agent govern`. UUID/revision values come from safe status;
secrets never appear in flags, shell arguments or output. `--operator` is a safe local label,
not remote proof of the person's identity. Live effects require an explicitly selected
candidate and current revision; no implicit default target exists.

| Command | Effect and result |
| --- | --- |
| `prepare` | Create owner-only installation and `config.draft.json`/`secrets.json` templates exclusively; no provider call |
| `configure --revision N --operator LABEL` | Validate reviewed source/schema/collector files, fixed endpoints and common profiles; activate local configuration only; reject source generation changes used by open cases |
| `case prepare --source ALIAS` | Allocate local case/candidate UUID and `candidate-UUID.draft.json`; no registration, finding claim, authority or credentials |
| `readiness --candidate UUID` | Bounded metadata checks for that private draft; record fixed per-prerequisite results and repair codes, no mint or registry mutation |
| `observe --candidate UUID --revision N` | Capture exact registry absence; run one compiled synthetic-fixture read using verified candidate token plus healthy control; wait at most the worker budget for correlated source receipt |
| `review --candidate UUID --revision N --operator LABEL` | Preview exact candidate/owner/entity/ceiling/role/evidence digests in private review file; return safe review UUID and summary; consume no remote authority |
| `enroll --review UUID --revision N` | Explicitly consume current review, recheck readiness/absence/holds, persist intent and create exactly one registration; no update/delete |
| `reconcile --candidate UUID --revision N` | Read exact entity/name/ID metadata; record presence/conflict while preserving unproven creation uncertainty |
| `resolve --attempt UUID --revision N --operator LABEL` | Consume already imported/reviewed correlated provider evidence and record explicit uncertainty resolution; no provider mutation and no automatic retry |
| `relying serve` | Start private Unix-socket verifier service with no minting/registration authority |
| `prove --candidate UUID --revision N --scenario identity\|permissions\|negatives` | Run the compiled scenario with current registered binding; credential material from fixed private file/non-TTY stdin, never flags |
| `import --input PATH --candidate UUID --revision N --operator LABEL` | Read one bounded owner-only evidence envelope, verify digests/references and record explicit local review; no provider calls |
| `status [--candidate UUID]` | Safe current state, outcomes, local UUIDs/revisions and concrete next-command codes |
| `closeout --candidate UUID` | Independently assess F11-T1…T7; never write public acceptance files |
| `close --candidate UUID --revision N --operator LABEL` | Local archival only when effects are drained and credentials are expired/resolved; does not delete provider registration or change authority |
| `serve [--port 8002]` | Observation-only HTTP server bound to numeric loopback; no registration or minting routes |

Credentials in `.local/governance/secrets.json` are only references/values for the exact
operator metadata/create token, candidate client and distinct healthy client. They are
Pydantic secret values, no repr, no raw exception text. Optional human OBO token arrives
through a closed non-TTY stdin object for the permission proof and is verified independently.
No interactive password collection, raw token export or arbitrary script/plugin is supported.

Exit codes: 0 completed command (a status/closeout may report blocked claims), 2 invalid
input/configuration, 3 missing prerequisite/hold/busy/stale review, 4 failed or uncertain
effect/proof. Output is bounded JSON with closed reason/action codes and safe fields.
Useful reasons include `source_not_ready`, `registry_conflict`, `review_stale`, `contained`,
`workspace_busy`, `creation_uncertain`, `bootstrap_mismatch`, `trust_unavailable`,
`identity_rejected`, `proof_inconclusive`, `native_evidence_missing`, `audit_unavailable`,
`issuance_unresolved`, `capacity_exhausted` and `storage_error`. Map each to exact setup or
rerun instructions; never return a raw provider exception.

## Observation ingress

`POST /governance/native/{source_alias}` at the loopback server accepts the configured
native JSON shape and an Authorization bearer token solely for the enrolled relay.
Audience/scope are distinct from response and task credentials. Use the existing verified
issuer/JWKS primitives without widening `response:submit` to authorize this route.

Stream/check size before parsing; reject compressed content, duplicate JSON keys, unsafe
depth/scalars, secret-bearing fields and unconfigured selectors. Authenticate and capture
source generation, project selected content, then recheck the generation in the short
commit transaction. Event identity joins only within source generation. A duplicate with
identical selected content returns the original record. Conflicting content is rejected.

The body cannot supply a trusted owner, entity, policy, trust domain, destination or action.
Source object identity remains an observation until host-reviewed binding. A new finding
may create an unbound candidate; a controlled case joins it only through its reviewed
source-object/correlation mapping. No fuzzy alias merge.

Success: 202 `{schema_version:1, candidate_id:UUID, observation_id:UUID, disposition:accepted|duplicate}`.
Failure: 400 malformed, 401 unauthorized, 409 conflicting replay/stale generation,
413 too large, 422 unrecognized projection, 503 durability/capacity unavailable.
Responses contain no echoed native fields. Native-managed/triaged and notification events
use separately reviewed selectors and never mutate registry authority. Managed/triaged
evidence received first cannot create a historical unknown-discovery claim. A validated native
projection is not by itself reviewed native discovery evidence.

## Provider calls

All paths below are relative to the pinned Vault `/v1` origin and exact namespace.
Path components are validated and encoded once; no event supplies them. Metadata-only
calls use the private least-privilege operator identity. Ordinary tests inject fake adapters.

| Purpose | Allowed operation |
| --- | --- |
| Exact absence/reconciliation | `GET agent-registry/registration/entity-id/{entity}` and `GET agent-registry/registration/display-name/{reserved_name}` |
| Registration create | `POST agent-registry/register` with exact reviewed display name/entity/owner/description/ceiling and explicit flags, no `id` |
| Exact readback | `GET agent-registry/registration/id/{id}` plus entity/name joins |
| Binding/readiness | Exact entity/alias, OAuth profile, named policy, `sys/health`, capabilities-self and configured SPIFFE config/role metadata reads |
| SPIFFE metadata | `GET {mount}/config`, `GET {mount}/role/{role}` |
| Native identity issue | `POST {mount}/role/{role}/mintjwt` with exactly one pinned audience and candidate direct OAuth token |
| Published trust | `GET {mount}/.well-known/openid-configuration`, `GET {mount}/.well-known/keys` via independently pinned HTTPS URLs |
| Safe activity/permission test | Exact reviewed `GET {kv_mount}/data/{fixture}` only; no query or wildcard |

Registry updates/deletes, identity/policy provisioning, SPIFFE config writes, role deletion,
namespace listing and credential-issuing probe paths are not supported. Readiness imports
administrator-reviewed license/entitlement evidence when no narrow metadata endpoint proves
it; a successful health response alone does not prove a feature license.

Registration uses `no_default_ceiling_policy=true` and a reviewed explicit policy list
excluding `root`. `optional_authorization_details=false` is explicit. Candidate direct client-credentials
requests include exact `vault:path_access` details (read for the reviewed KV path, update
for the exact mint path). Verify the signed output matches that request and has no `act`
claim before sending it to Vault. Missing/opaque/different RAR output blocks the path;
no silent optional-RAR or subject-exchange fallback. Each token request is a tracked effect. Candidate OAuth issuer/subject and
Vault alias/entity matching use exact canonical documented values, not case folding of
identity strings. If an issuer requires normalization, record the provider-defined canonical
value in configuration and compare exactly thereafter.

An authenticated 404 from an exact authorized registry lookup can establish current
absence. A 401/403, malformed response, sealed/unhealthy provider, missing profile or
unavailable endpoint cannot. Pre-registration denial requires valid credentials, exact
intended request and healthy control. Readiness snapshots cannot grant inferred privileges.

## Registration transaction and containment

Require confirmed controlled-case observation, owner mapping, independent bootstrap binding,
fresh readiness, exact policy/role/config digests and current hold-free anchors. Acquire the
lock order in plan.md; no network under short control transactions. Re-read metadata,
consume the review and reserve/persist submitted intent before POST. Store returned ID
before subsequent work; readback must match every security field. Do not claim registration
from HTTP acknowledgement alone. A new containment event blocks subsequent phases even
if the in-flight provider write completed.

On restart submitted work is uncertain. Exact metadata readback is allowed. A matching
foreign registration cannot be claimed as locally created; a missing registration cannot
prove the earlier request will never finish. Resolve only through explicit evidence review,
without automatically POSTing again. A definitive authenticated rejection with no create
can be terminal denied; a new attempt needs a new review and fresh absence proof.

## Independent relying service

`relying.sock` is a fixed owner-only Unix-domain socket. Startup refuses unsafe existing
files or a live owner; remove only a verified stale socket after service lock acquisition.
`GET /health` returns readiness only. `POST /verify` accepts private JSON with candidate,
attempt, generation, one-use challenge and JWT-SVID. Cap the envelope at 64 KiB; no access
logging, credentials in URLs or arbitrary callback destinations. Health is not identity proof.

The relying process independently reads the active trust profile and current registration
proof, rejects containment/staleness, atomically consumes the challenge and verifies with
its own bounded public-key client. Before committing the result it rechecks the same
generation, registration/profile digests and current hold state in short transactions;
a concurrent hold or change makes the proof blocked. No network I/O holds those locks. It cannot use a caller-supplied profile, key or decoded
claim as authority. Reject unexpected JOSE headers (`jku`, `x5u`, `jwk`, `crit`, etc.),
algorithm/key confusion, duplicate JSON keys, private JWK fields, malformed SPIFFE URIs,
wrong entity/audience/issuer, invalid time ordering and expired tokens. `kid` is required
by this Vault profile even though it is optional in generic JWT-SVID.

Return only `{schema_version, proof_id, candidate_id, generation, result, reason_code}`;
store token digest and trust/readback fingerprints privately. A consumed/expired challenge
returns a fixed rejection. Success grants no runtime admission or extra permissions.
A valid SVID can be reused elsewhere until its real expiry; this service provides one-time
proof attempts, not a claim of global token replay prevention or immediate revocation.

## Evidence and closeout

Private import envelope has schema version, candidate/case IDs, generation, environment
and implementation digests, source/profile digest, artifact digest/reference, observed time,
clock bound, evidence kind and structured fields. Kinds: collector finding/notification,
registry absence/creation/readback, identity issuance/verification, permission decision,
VIP triage, audit correlation and uncertainty resolution. Freeform text cannot set a pass.
Imported historical evidence is retained but cannot bypass current-generation or chronology
rules. Immutable identical artifact IDs/content are idempotent; changed content conflicts.

Review records operator label/time and exact evidence digest. Explicit local review does
not authenticate the original source; provider provenance and authenticated capture are
separate requirements. Each native predicate requires current implementation, environment,
profile and candidate generation, matching identity/correlation and no contradictory latest
qualifying observation. No report writes public acceptance automatically.

| Test | Passing predicate; otherwise explicit blocked/fail/inconclusive |
| --- | --- |
| F11-T1 | Exact absence plus controlled activity, actual collector discovery and notification, bounded pre-registration chronology and reviewed agent classification |
| F11-T2 | Otherwise valid unregistered actor denied on actual agentic path, healthy control, matching later positive path and registration enforcement attribution |
| F11-T3 | Native candidate-bound mint, signed entity provenance, independent relying success and reviewed published trust |
| F11-T4 | OBO allowed read and excessive read denied with human baseline/RAR allowing the latter, ceiling digest/readback and provider attribution |
| F11-T5 | Actual linked VIP and Vault audit records connecting observation, owner, enrollment and denial; unavailable audit stays blocked |
| F11-T6 | Actual unauthenticated mint denied with healthy issuer control plus labeled verifier tamper/audience/expiry/trust/entity negatives |
| F11-T7 | Same approved actor/entity with separately proven OBO ceiling and ordinary baseline allow/deny decisions |

## Browser status

Existing authenticated workspace gets read-only `GET /api/governance` (no arbitrary owner
parameter). Filter by trusted principal issuer/subject in reviewed candidate owner binding.
Unbound findings remain operator-only. Use existing origin/session/CSRF/security conventions;
return safe generated aliases and separate statuses with fixed help text, never source text,
entity IDs, owners' names or evidence payloads. Loading, empty, unavailable and blocked
states remain readable. Clear governance DOM on sign-out, expiry and session suspension.
No browser route creates a registration, mints an identity or accepts raw private evidence.
