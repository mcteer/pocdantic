# Administrator Contract: Gateway Controls and Live Acceptance

This is a proposed operational runbook, not authorization to execute remote changes. Software
implementation does not create an organization, purchase a plan, enable billing, alter policies
or send acceptance requests. Use an authorized Gateway administrator and synthetic data first.

## Current deployment repair

The operator approved the US `google-vertex` route with native `google-cloud` Gemini and an
explicit shared project API-key binding. A bounded benign request succeeded, but the synthetic
Google-key case was allowed and its benign Gateway trace contained message content. Keep
protected runtime activation blocked until these controls are repaired and independently verified.

1. In [Guardrails → Protections](https://logfire.pydantic.dev/-/redirect/default-org/-/gateway/guardrails/protections),
   verify the selected organization. Inspect detector matches, target endpoint and action; install
   or repair **Block** for the approved endpoint, scoped to this deployment. Do not apply a broad
   organization change that would affect other applications without reviewing its actual scope.
2. In [Gateway settings](https://logfire.pydantic.dev/-/redirect/default-org/-/gateway/settings),
   under **Telemetry**, retain the intended **Project** and switch **Include messages** off.
   The operator supplied a screenshot confirming that exact control. Existing traces are
   retained; verify with fresh synthetic requests rather than treating old traces as new capture.
   Obtain retention/pre-block evidence as described below.
3. Confirm the endpoint's single approved upstream, model restrictions and pricing policy.
   The operator owns cap settings; do not change them as part of this repair.
4. After observed configuration repair, run the affected fixed canary and benign cases, inspect
   metadata without retrieving content, then complete the full applicable coverage and review.

The current provider-management API returns a plan restriction, not evidence of an incorrectly
configured token. The public schema inspected on 2026-10-18 exposes no Guardrails/settings
administration operation. Beta prebuilt/custom-pattern Block protections themselves are available
on every Gateway plan according to the current protection documentation. No upgrade or additional
credential rotation is required by this runbook; use an authorized organization-admin UI session
for controls that the available API cannot administer.

## 1. Prepare the deployment

Choose the organization/project and US/EU region privately. Verify current Guardrails availability
in that organization; the Beta documentation has changed and search results can be stale. Create
a dedicated project-scoped key for this deployment, with expiry/rotation policy. Keep upstream
BYOK credentials in Gateway administration, never in application config or chat. A Gateway credential
is separate from browser OAuth identity and upstream provider credentials. A project API key
with the required scopes may explicitly serve both Gateway and Logfire export; the user
authorized that binding for this deployment. Legacy telemetry-only write tokens do not imply
Gateway permission.

Prefer Manual setup and inspect all defaults before sending data. Recommended setup can enable
conversation telemetry. Record which provider bills the requests and whether auto-recharge exists;
a spending limit is not permission to add a payment method or enable auto-recharge.

Use the provider extras appropriate to the explicitly chosen native model. Google requires a
reviewed cloud/Vertex-compatible model; an existing `google-gla` model is not automatically
migrated. Set private runtime settings from the [runtime contract](runtime.md).

## 2. Restrict routing and models

Create or select an endpoint with exactly one approved active provider and no fallback/load
balancing. Record actual protocol, provider and model resolution. Check remote automatic retry
behavior; unsupported or unverifiable behavior remains a routing limitation, not a local test pass.
Use remote model-access allow/deny if available, but always retain the application's exact-model
allowlist. No additional provider should become reachable through a remote endpoint change.
Review body-transforming optimizations as disabled; they must not alter inspected content or
route semantics without renewed coverage/privacy review.

## 3. Apply credential protections

A protection name identifies the credential being detected, not the model provider to protect.
For example, OpenAI API keys must Block on the Google endpoint when Gemini is the selected
model: sending an OpenAI secret to Gemini is still credential disclosure. For this deployment,
OpenAI, Anthropic, Google, JWT and PEM protections all target `google-vertex` with Block.
Do not set only the OpenAI endpoint for the OpenAI-key detector or infer cross-provider coverage.

Inspect the current template catalog and supported actions. Install Block on the exact endpoint
for every mandatory credential class in the data model. Prebuilt rules may cover known API keys;
use reviewed custom patterns for uncovered structured classes. Do not assume JWT, Vault, Gateway
or database credentials are covered simply because an API-key template exists.

For each rule record privately: recognizer/template/revision or pattern digest, action, target,
protocol, synthetic positive and near-match benign cases. Never paste actual credentials into a
preview or model request. Test all five text surfaces, including tool-result continuation. Observe
and Flag are insufficient; Redact is not the chosen baseline. Unsupported surface/class coverage
blocks protected activation for that route/model. Keep false-positive changes narrow, reviewed
and followed by the full affected coverage set; never advise switching to direct mode to evade a
blocked request. Arbitrary opaque passwords, encodings, fragments and multimodal data are not
claimed covered.

## 4. Configure spending and pricing

Set finite administrator-approved daily and monthly whole-USD per-key limits; consider stricter
project/organization limits as needed. Empty/unlimited does not satisfy the baseline. Zero is a
useful deny-all test setting, not a usable operating allowance. Require pricing data so unknown-
price requests cannot evade accounting. Experimental advanced policies are optional; if used,
verify binding/attachment and blocking mode rather than alert-only.

Record configured amounts/scopes/windows, observed reset behavior, usage attribution and selected
BYOK accounting. Limits are soft: in-flight/concurrent requests may overshoot; no maximum dollar
overshoot is promised. Keep existing run/token/request limits. Review upstream billing controls
where applicable. Unknown cost after interruption remains unknown.

A separately authorized probe must demonstrate a spending refusal with no upstream model call.
Record the exact key/configuration at test time. A zero-limit test on a temporary key proves only
that tested configuration; it does not attest to an untested production key or restored limits.
Review the final deployment configuration after any temporary test change and preserve the
scope of each result. If budget enforcement for the deployment cannot be demonstrated under an
authorized bounded probe, keep spend acceptance blocked rather than deliberately overspend.

## 5. Establish remote privacy

Enable metadata-only Gateway telemetry to the intended project with **Telemetry → Include
messages** off, as confirmed in the operator-supplied current UI screenshot. Existing traces
are retained, so query only new synthetic request windows when verifying the change. Verify in
the selected service/organization that request
and response bodies, detector matches and blocked input are not retained in traces/logs, including
logging before blocking. Review service retention controls and applicable vendor confirmation;
the public supplemental terms allow some content logging, so an application setting or empty
trace search alone is insufficient. Capture content-free screenshots/configuration evidence or
vendor confirmation privately. If a safe configuration cannot be demonstrated, keep private-data
activation blocked and use synthetic inputs only. Do not claim that the Gateway itself never
receives the data it inspects.

Application metadata export continues through existing filtering. Verify SDK/application/exporter
logs contain no canary values, prompts, tools, credential headers or raw error strings. Record
spending analytics independently of conversation tracing. Application attempts own application
accounting; do not sum Gateway diagnostics again. Do not infer application agent parentage or
environment from independent Gateway records. Verify actual agent activity in Traces and Agents;
model-list requests are not inference evidence.

## 6. Probe, review and activate

After implementation, use `agent gateway status`, then separately authorized fixed
`agent gateway probe --case CASE` invocations. The maintained case registry supplies exact case
names; no arbitrary prompt/file argument exists. Confirm positive, benign, model-access, budget,
transport and privacy cases for every enabled model/protocol. Evidence must include native
Gateway decision/configuration and, where available, provider request evidence. The absence of
model output alone does not prove a blocked payload never reached a provider.

Store source evidence privately. Run `agent gateway review` only for an explicit review of that
exact evidence/configuration; reviewer, observation time, disposition and expiry are mandatory.
Unknown causes, unavailable controls or absent provider evidence stay blocked. Synthetic CI cannot
approve this review. Approval enables normal private work for at most 24 hours, subject to all
existing identity/policy/recovery checks. Sign in and perform the ordinary record-1 read or
sandbox status-count flow only with its existing authorization, then verify exact cleanup.

## 7. Changes, rotation and recovery

Remote control changes require immediate local invalidation (a rejected review), stopping new
runs/turns and repeating affected evidence before activation. Rotate keys privately and restart;
old credential binding cannot authorize the new key. Expiry stops later turns; already dispatched
requests may complete or remain unknown. Re-review at least every 24 hours and after any reported
remote change. The application cannot detect unreported remote drift continuously.

Preserve `.env.local`, `.local/`, enrollment and recovery holds. Transport-only changes invalidate
Gateway review/validation context, not database recovery ownership. Use existing recovery migration
for actual identity/database-target changes. Explicitly choosing legacy direct mode is a deliberate
loss of Gateway controls and must be visible; it is never an automatic outage/denial workaround.

## Source references

- [Gateway concepts and setup](https://pydantic.dev/docs/logfire/manage/ai-gateway/)
- [Credential protection](https://pydantic.dev/docs/logfire/manage/ai-gateway/protect-data/)
- [Spending controls](https://pydantic.dev/docs/logfire/manage/ai-gateway/spending-policies/)
- [Provider routing](https://pydantic.dev/docs/logfire/manage/ai-gateway/endpoints/)
- [BYOK administration](https://pydantic.dev/docs/logfire/manage/ai-gateway/byok-providers/)
- [Gateway supplemental terms](https://pydantic.dev/legal/terms-of-service-gateway)

Checked 2026-10-18. Revalidate beta behavior during implementation and live setup.

## Custom-pattern recipe for gaps in the observed prebuilt catalog

The observed catalog has no dedicated rules for the five classes below. Add each using
**New protection → Custom pattern**, with a descriptive name, **Specific endpoints** targeting
the approved PoC endpoint, and **Block**. Use no real credentials in previews. These original
patterns have local positive/benign checks against 30 generated examples per class; those
checks do not establish Gateway regex compatibility, surface inspection or upstream blocking.
The full fixed live coverage remains required after installation.

Gateway project key format (registry class `gateway_key`):

```regex
\bpylf_[A-Za-z0-9_-]{20,}\b
```

Vault service/batch/recovery token format (registry class `vault_token`):

```regex
\bhv[sbr]\.[A-Za-z0-9_-]{20,}\b
```

PostgreSQL credential-bearing URI (registry class `database_uri`):

```regex
\bpostgres(?:ql)?://[^\s:/@]+:[^\s/@]+@
```

Explicit password assignment (a nonempty value) (registry class `password`):

```regex
["']?[pP][aA][sS][sS][wW][oO][rR][dD]["']?\s*[:=]\s*["']?[^\s"',;}\]]+
```

Explicit client-secret assignment (a nonempty value) (registry class `client_secret`):

```regex
["']?[cC][lL][iI][eE][nN][tT][_-]?[sS][eE][cC][rR][eE][tT]["']?\s*[:=]\s*["']?[^\s"',;}\]]+
```

These rules deliberately do not claim arbitrary unlabelled passwords, fragments, encodings,
all database schemes or token formats outside the stated patterns. The Gateway receives the
content it inspects; Block protects onward model delivery, not disclosure to Gateway itself.
Keep the existing prebuilt Google/OpenAI/Anthropic, JWT and PEM protections; verify their exact
synthetic fixtures live rather than assuming a template name proves coverage.

### Single-protection alternative

To reduce manual setup, one custom protection named **PoC credential formats** may combine
the five patterns above. Choose **Custom pattern**, paste this entire expression, target only
`google-vertex`, choose **Block**, and save. Use either this combined protection or the five
individual protections; the combined version has the same local generated positive/benign
checks and still requires live coverage before activation.

```regex
(?:\bpylf_[A-Za-z0-9_-]{20,}\b|\bhv[sbr]\.[A-Za-z0-9_-]{20,}\b|\bpostgres(?:ql)?://[^\s:/@]+:[^\s/@]+@|["']?[pP][aA][sS][sS][wW][oO][rR][dD]["']?\s*[:=]\s*["']?[^\s"',;}\]]+|["']?[cC][lL][iI][eE][nN][tT][_-]?[sS][eE][cC][rR][eE][tT]["']?\s*[:=]\s*["']?[^\s"',;}\]]+)
```

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
