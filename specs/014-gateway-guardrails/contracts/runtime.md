# Runtime Contract: Model Gateway and Credential Guardrails

**Status**: Proposed for implementation. Existing commands do not yet implement these additions.
References: [spec](../spec.md), [data model](../data-model.md), [administration](administration.md).

## Configuration and selection

| Input | Contract |
| --- | --- |
| `MODEL_MODE` | Explicit `gateway`/`direct`; missing blocks live work with migration guidance. New `setup init` writes gateway. Offline fixed commands do not read it. |
| `MODEL` | Gateway native prefixes `google-cloud`, `openai-chat`, `openai-responses`, `anthropic` plus exact nonempty model. No `gateway/` inference aliases or GLA in Gateway mode. Existing direct aliases remain in direct mode. |
| `GATEWAY_REGION` | Explicit `us`/`eu`; maps to the fixed vendor HTTPS origin. No custom URL/TLS bypass. |
| `GATEWAY_ROUTE` | Reviewed provider/endpoint slug for one provider, validated by the data-model grammar. No URL/path/query input. |
| `GATEWAY_MODELS` | JSON array of exact protocol-qualified models; no wildcard; bounded unique set including MODEL. |
| `GATEWAY_API_KEY` | Private nonempty credential; `LOGFIRE_GATEWAY_API_KEY` compatibility alias. Environment wins; conflicting nonempty process aliases reject. |
| Existing provider keys | Used only by explicit direct mode. Never Gateway fallback. |
| Existing Logfire settings | Separate optional metadata export credential; never reused as Gateway auth. |

Short nonsecret names retain standard `POCDANTIC_` aliases where the Settings alias generator
already applies; Gateway key uses only its two explicit aliases. `PYDANTIC_AI_GATEWAY_*`/`PAIG_*`
and SDK provider environment variables cannot override the admitted route/authentication.
Fresh live preparation rejects direct mode while enrollment is absent; existing matching recovery/
response enrollment permits explicit legacy direct selection, subject to its original holds.
No new enrollment is created through a direct-mode setup recipe.
A runtime policy change requires restart and new review; per-turn expiry/revocation checks still
apply while running. Missing mode yields a closed configuration error, not automatic migration.

Native path table is derived and tested against the locked SDK: OpenAI chat completions,
OpenAI responses, Anthropic messages, Google Vertex generate-content. Endpoint route names do not
select the protocol. Only supported model-request methods and suffixes may leave the transport;
reject uploads, files, batches, alternate hosts, redirect hops and arbitrary subpaths. Reject
multimodal content, URLs/binary attachments and provider-hosted tools in Gateway mode. Ordinary
JSON tool schemas/arguments/results used by this project remain supported.

## Admission and attempt sequence

1. Canonical deployment root and existing response/recovery admission apply first.
2. Validate mode, exact model, dependencies, explicit key and immutable route policy. No socket
   or credential acquisition occurs on local failure.
3. Before each model turn, validate current control review/expiry/digests and existing bounds.
   Synthetic fixed probes use the dedicated command path below; workspace and CLI cannot opt out.
4. Persist a content-free attempt-start record. Bind generated run/parent/definition metadata
   via the trusted capability context, isolated across concurrent requests.
5. Final transport checks exact origin/path, enforces closed headers and Gateway bearer, drops
   ambient provider credentials/custom headers/baggage, and allows one actual HTTP send only.
6. Normalize known denial signatures before SDK error instrumentation; terminate safely.
   Successful responses supply observed usage/cost only. Unobserved billing stays unknown.
7. Write one terminal attempt record. Runtime preserves existing cleanup even if model use,
   storage, export or cancellation fails. Shutdown closes owned clients after active work stops.

No generic network retry, automatic failover, key/model switch or model-directed repair occurs
on Gateway failure. Existing model output-validation turns after successful responses remain
bounded and re-admitted; a denied/uncertain attempt is never converted into ModelRetry.

## Closed outcomes

| Code | Meaning and action |
| --- | --- |
| `model_mode_required` | Choose explicit Gateway or legacy direct mode before live work. |
| `gateway_configuration_invalid` | Repair names-only configuration/dependency finding. |
| `gateway_model_denied` | Local model/protocol admission rejected, or reviewed exact remote access signature. |
| `gateway_review_required` | Review absent/invalid/rejected/expired/mismatched; administrator/reviewer action. |
| `gateway_payload_unsupported` | Unsupported surface or provider feature; no dispatch. |
| `gateway_guardrail_denied` | Exact reviewed remote blocking signature only; no matched data exposed. |
| `gateway_budget_denied` | Exact reviewed remote spending refusal only; administrator action. |
| `gateway_auth_denied` | Exact reviewed authentication failure; rotate/check private key. |
| `gateway_rate_limited` | Exact reviewed throttling signature; stop run, no retry. |
| `gateway_request_failed` | Safe generic confirmed failure/refusal; unknown cause stays unknown. |
| `gateway_dispatch_unknown` | Dispatch occurred but completion/billing is unobserved; no replay. |
| `gateway_observation_failed` | Local start record unavailable; no new dispatch. |

A generic 400/401/403/429/5xx alone does not establish guardrail/budget cause. Unknown response
schemas, malformed bodies or oversized error bodies (maximum parsing input 16 KiB) become a
safe generic code; no raw body, exception representation, arbitrary header or matched text is
returned. Bounded private native request IDs may be retained only for evidence joins. Mapping
changes require documented or privately reviewed synthetic-source signatures and negative tests.

CLI failure is nonzero using existing conventions. Workspace uses its closed WorkflowError/ERRORS
catalog, without returning provider bodies. Distinguish legacy direct status from protected
review status in workspace diagnostics; the browser cannot select model, key, route or review.
A failed model turn after a tool success must not report the whole user request as successful.
Cleanup pending/unknown still takes precedence in the existing workflow.

## Setup compatibility

`agent setup guide --recipe workspace-read --format json` and `setup check` retain their names,
version-1 JSON shape and exit meanings: 2 = local input/dependency/root repair; 3 = required
review/enrollment/recovery; 0 = successful requested local checks only. Both live recipes use
Gateway requirements for Gateway mode; offline requires none. New closed enum values are additive
and documented. Separate findings convey protected-review versus legacy-direct status.
`--network` remains bounded read-only reachability; it never sends model prompts, verifies spend
by charging a request, creates keys/policies or grants live acceptance.

`setup init` still refuses to overwrite private configuration. It emits Gateway mode and
names-only prompts for explicit model/region/route/key/allowlist input; no invalid fake live key,
model-availability claim or copied direct provider key. Existing configuration requires a deliberate
operator migration and is never rewritten by a check.

## Proposed Gateway CLI

- `agent gateway status [--format text|json]`: read-only local names-only state; 0 for a valid
  approved review, 2 for invalid input/root, 3 for missing/stale/rejected review. Direct mode
  returns 0 with explicit `legacy-direct`, never `protected-reviewed`.
- `agent gateway probe --case CASE [--format text|json]`: fixed synthetic case registry only;
  requires valid explicit Gateway transport settings but not an approved control review. No
  arbitrary prompt/file body/tools, direct mode or fixture override flag. It may spend money
  on benign controls and requires separate operational authorization. Bound each invocation to
  one case/attempt and existing timeout; write private evidence and emit case/outcome only.
  0 = observed expected result, 2 = local error, 3 = blocked/unknown/unmet live expectation.
  Run positive and benign cases separately; no automatic retry.
- `agent gateway review --evidence PRIVATE_DIRECTORY --reviewer ID --decision approve|reject
  --valid-hours HOURS`: explicit local review, not remote administration; HOURS >0 and ≤24
  applies to approval. For rejection, evidence and current configuration are not required;
  atomically select an immutable rejected record immediately.
  Read the bounded ControlEvidenceBundle from `bundle.json`. Resolve evidence only within
  canonical `.local/gateway/`, reject unsafe paths/files, verify
  digests/complete dispositions and atomically write an immutable private record. Approval never
  follows automatically from `probe` or `setup`. 0 = recorded, 2 = invalid arguments/root,
  3 = incomplete/stale/failed approval evidence; rejection does not require that evidence. Public output omits paths, reviewer and native IDs.

The probe path cannot pass synthetic status into a normal runtime or read database credentials.
The reviewer records remote administrative evidence separately; a probe alone cannot prove
retention, endpoint configuration or every budget scope. No command accepts a raw admin token.

## Observation and privacy

Use ModelAttempt's closed schema for local audit and optional telemetry. Record approved protocol
and opaque model/route references with generated correlation, timing, observed tokens and nullable
cost. An authorized operator joins private registry references to exact configured model/route;
remote dashboards expose their own priced usage. Do not send OAuth subjects, user email, tenant
identifiers or tool payloads as end-user attribution. Per-user remote billing is outside this scope.
Existing safe instrumentation excludes content, binary content and model request parameters.
Remote Gateway telemetry remains off unless an independently verified no-content mode satisfies
all privacy requirements. Exporter failure is degraded observation, not dispatch permission or
cleanup failure concealment. Root/key/review rotation does not silently reset incident state.

Native Google refusals may supply only a generic numeric code and INVALID_ARGUMENT status.
A reviewed ErrorSignature may therefore use field `response_sha256` with an exact 64-character
lowercase SHA-256 digest of the bounded raw response, plus the exact HTTP status. No raw body
is persisted in the signature. Any byte or status difference fails matching; no keyword,
substring or generic numeric-code inference is allowed. Source evidence and final explicit
review remain required; a candidate mapping cannot approve ordinary runtime activation.

## Explicit operator-owned administration scope

The operator approved `administration: "operator-owned"` for this deployment. That bundle
requires exactly passing routing, protection and telemetry-privacy controls plus full fixed
coverage. SpendControl is omitted, not populated with guessed/zero amounts. Internal service
retention and spending configuration remain operator-owned/unverified, not acceptance passes.
Legacy omitted/`reviewed` scope still requires all four controls and actual spending evidence.
Both modes retain explicit review, live-only source, 24-hour freshness, source/key/configuration/
implementation binding, rejection and per-turn admission. The selected scope is visible to
operators; the application never treats owner responsibility as vendor enforcement evidence.
This amendment supersedes earlier activation requirements for administrative claims in the
operator-owned scope; those earlier procedures remain available for full attestation.
