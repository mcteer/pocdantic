# Data Model: Model Gateway and Credential Guardrails

These boundary contracts are implemented by the classes listed in the final section. All use
frozen validated values and reject extra fields. Remote identifiers, reviewer details and evidence remain private.
Local operator configuration and OS ownership are trusted; these records resist mistakes and
stale configuration, not a hostile administrator who can replace the executable or its files.

## ModelRoutePolicy

- `mode`: `gateway` or `direct`; absent blocks live admission.
- `region`: `us` or `eu`, required for Gateway; no implicit region.
- `route`: 1–64 characters matching `[a-z0-9][a-z0-9_-]*`.
- `protocol`: `google-cloud`, `openai-chat`, `openai-responses` or `anthropic`.
- `model`: 1–128 characters matching `[A-Za-z0-9][A-Za-z0-9._/-]*`.
- `allowed_models`: 1–16 unique protocol-qualified exact models; selected model must be a member.
- `policy_digest`: 64 lowercase hexadecimal characters; canonical nonsecret route/model settings.
- `route_ref`, `model_ref`: generated opaque UUID registry references, privately joined to the
  exact configuration; persist/reuse the references per policy digest within the deployment,
  with no tenant/model-label text in exported attempt records.

No wildcard, arbitrary URL, credentials in model names, cross-protocol route inference, media,
provider-native hosted tools, embeddings or unreviewed alternate endpoint. Direct-mode legacy
prefixes continue through their existing descriptor/custom-provider behavior; Gateway restrictions
must not accidentally narrow explicitly selected legacy mode. Protocol determines allowed wire
paths, not untrusted model output. The validated policy is immutable for one runtime instance.

## GatewayCredential

`SecretStr`, nonempty, `repr=False`; loaded only through trusted Settings. Explicit transport
credential, never sent to the upstream provider as prompt content. The operator may explicitly
bind the same project API key for Gateway and telemetry through private dotenv configuration;
there is no implicit fallback from LOGFIRE_TOKEN.
Use `GATEWAY_API_KEY` or documented `LOGFIRE_GATEWAY_API_KEY` alias; environment wins over file.
Conflicting nonempty process aliases are invalid. Reject surrounding whitespace/control bytes.

A one-way digest of the high-entropy key binds private review to key rotation; keep that digest
inside the private review, never in exported telemetry or the public policy digest. No secret
copy is persisted, logged, printed or placed in a provider descriptor. Do not hash arbitrary
user passwords for telemetry. Provider keys present in the environment are unused in Gateway mode.

## GatewayControlReview

- `schema_version`: literal `1`.
- `review_id`: UUID; immutable record identity.
- `policy_digest`, `credential_digest`, `implementation_digest`, `evidence_digest`: each 64
  lowercase hexadecimal characters, binding exact reviewed inputs.
- `reviewer`: 1–128 characters, private human/operator identity.
- `observed_at`, `reviewed_at`, `expires_at`: timezone-aware UTC; observed_at ≤ reviewed_at
  < expires_at ≤ observed_at + 24 hours; future observation/review times rejected.
- `administration`: `reviewed` (default legacy full attestation) or explicit `operator-owned`.
- `decision`: `approved` or `rejected`; required controls all need `pass` with source evidence.
  Routing, protection and telemetry privacy are always required; spending is additionally
  required in reviewed scope. Unknown/blocked/failed required controls never pass.
- `evidence_refs`: 1–1024 unique private local artifact basenames for approval, no absolute paths
  or traversal. Rejection may have no evidence and no configuration digests; it remains effective
  until explicitly superseded, independently of approval expiry.
- `control_revision`: digest of the administrator-reviewed endpoint/provider inventory,
  detector/action/target set, pricing/limits and retention settings. No unsupported remote API
  is assumed to generate it; changes require a new review.

Store records only beneath `.local/gateway/`, directory mode `0700`, files `0600`, with no
symlinks or hard-linked files, atomic writes and a maximum review-file size of 64 KiB. Follow
canonical root admission. Evidence imports use the same bounded private-file rules; credentials
and raw content are not valid review fields. Never silently replace a rejected/stale review with
an approved one. Read and validate the current immutable record before every model attempt.

The atomically replaced private `current.json` pointer contains only the current review UUID
(schema_version `1`, maximum 4 KiB); review files are immutable and are never selected by a
filename sort or modification time. Serialize approval/rejection under a local control lock and
recheck current revision/input digests before committing; a race is a closed conflict, not an
automatic retry. Per-turn admission rechecks the pointer immediately before final dispatch.

Derived status: `absent`, `invalid`, `rejected`, `expired`, `mismatch`, `approved`.
A local policy/key/implementation/evidence change produces mismatch. Expiry is checked per turn.
Remote drift is detectable only when observed/reported; no continuous attestation is claimed.
Revocation is a new rejected review. A request already dispatched when review changes cannot
be recalled; stop later turns and report its actual/uncertain completion.

## ControlEvidenceBundle

`agent gateway review --evidence` reads `bundle.json` from the selected private directory.
Its schema_version is literal `1`; source is `live` or `synthetic` (synthetic cannot approve
activation); policy/credential/implementation digests bind the tested inputs. Observations
contain fixed case/control IDs, protocol/model references, expected/observed outcomes, aware
UTC observation times and native source references. Required controls are routing,
protection and telemetry privacy; reviewed administration additionally requires spending. Each
has `pass`, `fail`, `blocked` or `unknown` disposition.
All required cases for enabled models/surfaces and every control must pass to approve.

The source manifest has 1–1024 unique local basenames and matching SHA-256 digests. Each source
artifact is at most 8 MiB, the total is at most 32 MiB, and bundle.json is at most 1 MiB. Apply
the same owner-only, no-link, no-traversal rules as review files. Probes append immutable result
artifacts; an operator assembles the complete bundle with remote administration/privacy source
evidence. Do not infer privacy or endpoint configuration from a successful probe. The reviewer
explicitly attests native evidence and exact configuration; the application checks structure,
coverage, file digests and freshness, not remote authenticity by an undocumented API. A changed
source invalidates evidence_digest and review. Never accept freeform text as a control outcome.

## ModelAttempt

- Generated `attempt_id`, `run_id`, `request_id`, `definition_ref`, `workload_ref`: UUIDs;
  `parent_run_id`: UUID or null. Trusted runtime creates these; no user-supplied attribution.
- `sequence`: positive integer scoped to a run; independent concurrent runs cannot overwrite it.
- `route_ref`, `model_ref`: generated opaque registry references; public records never include
  tenant endpoint slugs or freeform remote model labels. Authorized local status can join the
  references to the privately configured exact model, without exporting those values.
- `protocol`: closed ModelRoutePolicy protocol value; `mode`: gateway/direct/synthetic.
- `stage`: `admitted`, `dispatched`, `completed`, `denied`, `failed`, `cancelled` or `unknown`.
- `reason`: closed values from the runtime contract, never provider free text.
- `duration_ms`, `input_tokens`, `output_tokens`: nonnegative integers or null when unobserved.
- `cost_usd`: nonnegative decimal string or null; `cost_state`: `known` or `unknown`.
  Known requires an observed value/source; unknown requires null, never a fabricated zero.
- `cost_source`: `gateway`, `provider` or `unavailable`; unknown requires unavailable.
- `telemetry_state`: `ok` or `degraded`; cleanup disposition is separate existing runtime evidence.

Lifecycle: admission failure → denied; admitted → dispatched → completed/denied/failed/cancelled/
unknown. Exactly one terminal event per attempt. After-dispatch interruption with unknown remote
completion uses unknown, even if the run itself is cancelled. A process crash may leave an
admitted/dispatched record; status derives unknown and never replays it. Record start before
network dispatch. At most one actual model HTTP send per attempt; later legitimate turns get
new IDs. Respect existing bounded request/delegation limits instead of a new unbounded event log.
A local start-record failure prevents dispatch; exporter failure cannot suppress cleanup.

## ProtectionCoverageCase

`case_id` is a fixed registry identifier, not user text. Each case has a protocol, one of five
surfaces (`user`, `instructions`, `history`, `tool_arguments`, `tool_result`), a credential class,
synthetic generator revision, expected `block`/`allow`, and observed result. No actual credentials
or copied customer content are accepted. Generate realistic but invalid test strings at runtime;
public fixtures must not contain complete token/key material that resembles usable credentials.

Initial mandatory classes: selected provider API-key formats; Gateway key format; Vault token
format; bearer/JWT shape; PEM private-key marker; credential-bearing database URI; and explicitly
labelled password/client-secret assignments. The selected-provider class covers each enabled
provider. Prebuilt detectors are used where supported, custom patterns otherwise. Arbitrary
unlabelled passwords and encoded/fragmented values remain outside the claimed detection set.
All classes × five surfaces × enabled protocol/model combinations require positive and benign
negative cases. If a field or pattern is unsupported, that combination cannot be activated as
protected. Probe records store case IDs/outcomes and private request references, never payloads.

## ReadinessFinding and SpendReview

Reuse existing setup closed models. Add names-only Gateway findings/actions and a Gateway
administrator owner without changing schema-version or exit meanings. Distinguish local-ready,
review-required, protected-reviewed, legacy-direct and unsupported. Public JSON stays bounded
by the existing 32 KiB guide limit; no region, route/key/reviewer values or URLs appear in findings.

Private SpendReview inputs: dedicated key/project reference, finite per-key daily and monthly
whole-USD limits, pricing-required=true, blocking=true, reviewed optional organization/project
caps, observed accounting/reset behavior and concurrency limitation. Zero is deny-all; blanks
are unlimited and do not satisfy the baseline. These are remote administrator settings, never
application-authoritative billing counters. Native raw identifiers remain private.

## Native error signatures and implemented evidence schema

The implementation uses `EvidenceBundle`, `Observation`, `SpendControl`, `ControlReview` and
`ModelAttempt` in `src/agent/gateway/models.py`. An ErrorSignature has status 400–599, field
`code`, `error.code` or `error.type`, a 1–64-character alphanumeric/underscore/hyphen value,
and one closed guardrail/budget/model/auth/rate-limit reason. At most 16 mappings are reviewed
with the evidence bundle. Unknown schemas never acquire a specific denial classification.
Candidate bundle mappings classify fixed probes only and cannot approve ordinary execution.
Review rejection may omit digests, expiry and source evidence. Registry joins persist in private
`route-<digest>.json` files; probe payloads are generated in memory and never persisted.

Native Google refusals may supply only a generic numeric code and INVALID_ARGUMENT status.
A reviewed ErrorSignature may therefore use field `response_sha256` with an exact 64-character
lowercase SHA-256 digest of the bounded raw response, plus the exact HTTP status. No raw body
is persisted in the signature. Any byte or status difference fails matching; no keyword,
substring or generic numeric-code inference is allowed. Source evidence and final explicit
review remain required; a candidate mapping cannot approve ordinary runtime activation.

`EvidenceBundle.administration` and `ControlReview.administration` explicitly preserve the
review scope. Omitted values default to `reviewed`, requiring four controls and SpendControl.
`operator-owned` requires exactly routing/protection/privacy and no SpendControl or spending
disposition. Privacy then covers application/visible Gateway telemetry, with internal-service
retention/pre-block logging left operator-owned/unverified. This does not approve those
external administrative claims. Admission rechecks that the scope matches the bound bundle.
