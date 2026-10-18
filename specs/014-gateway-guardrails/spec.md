# Feature Specification: Model Gateway and Credential Guardrails

**Feature**: `014-gateway-guardrails`
**Created**: 2026-10-18
**Status**: Implemented and software-verified; 100 live credential cases pass. Operator-owned
control review is recorded; signed-in read and analysis acceptance pass. Spending and internal
service retention remain operator-owned and unverified.
**Input**: Configure Pydantic AI Gateway and Gateway Guardrails for model-use visibility,
spend/control and defense against credentials reaching frontier language models; complete
specify, clarify, plan, tasks and analyze before implementation.

## Context

The runtime currently chooses a model provider directly. Its trusted adapters already keep
application credentials out of model messages, and its telemetry excludes conversation content.
This feature adds controlled model routing and Gateway inspection without weakening either
boundary. Gateway receives the model request in order to inspect it: blocking onward delivery
to a model provider differs from keeping application credentials out of requests entirely.
Detection has a defined coverage set; it cannot promise to recognize every possible secret.

Actors are the operator selecting a deployment's model route, the Gateway administrator
configuring remote controls, the signed-in workspace user, and the reviewer assessing evidence.
Planning authorizes no remote configuration changes, purchases, model calls or implementation.

## Clarifications

### Session 2026-10-18

- Q: Should Gateway be required for new live setups while existing deployments retain an
  explicit direct-provider mode? → A: Require Gateway for new live setups; preserve explicit
  legacy direct mode (user selected the recommendation).

- Q: Should spending configuration and Gateway-internal retention review remain operator
  responsibilities while activation requires reviewed routing, credential blocking and
  content-free telemetry? → A: Keep those operator-owned (user selected the recommendation).

The migration question above was asked and answered. During live setup, the user also
confirmed that the project API key supplied as `LOGFIRE_TOKEN` may authenticate Gateway.
Permit that explicit shared-key binding when its scopes support both uses; do not infer
Gateway permission from a telemetry write token or fall back to an upstream provider key.

 The structured scan finds scope, entities/lifecycle, user
flows, quality attributes, external dependencies, failures, tradeoffs, terminology, completion
signals and placeholders clear. Deployment identifiers, region and budget amounts are later
operator inputs, not unresolved feature choices. Blocking credential rules, metadata-only
visibility, no failover and hosted-only initial support are conservative design assumptions.

## User Scenarios & Testing

### User Story 1 — Route model work through the controlled gateway (Priority: P1)

An operator enables Gateway for a deployment and knows that each model turn, including child
agents and post-tool continuation, follows the same approved route and model selection.

**Why this priority**: All Gateway controls depend on requests actually passing through it.

**Independent Test**: Exercise CLI and workspace runs with synthetic transports, proving the
selected destination and absence of direct-provider dispatch for every model turn.

**Acceptance Scenarios**:

1. **Given** valid Gateway configuration, **When** either database profile runs, **Then** all
   model turns use the approved Gateway route and require no direct-provider credential locally.
2. **Given** missing Gateway credentials, an unapproved model or an unavailable Gateway,
   **When** work starts or continues, **Then** it stops safely without direct-provider fallback.
3. **Given** an offline rehearsal, **When** ambient live configuration exists, **Then** it
   remains synthetic and performs no Gateway, provider or telemetry traffic.

### User Story 2 — Stop covered credentials before model delivery (Priority: P1)

An administrator applies blocking credential protections to the deployment's Gateway route;
an operator receives a safe refusal when inspected material matches those protections.

**Why this priority**: Visibility alone does not prevent sensitive material reaching a model.

**Independent Test**: Synthetic credential canaries and benign controls exercise every supported
outbound text surface and denial path; live vendor enforcement is evaluated separately.

**Acceptance Scenarios**:

1. **Given** covered synthetic credential material in user text, instructions, prior messages,
   tool arguments or tool results, **When** the next model request would send it, **Then** the
   configured protection blocks onward delivery and reports only a closed, content-free reason.
2. **Given** a blocked request, **When** the runtime handles the refusal, **Then** it does not
   ask a model to repair the content, switch routes, retry it automatically or replay tool work.
3. **Given** ordinary synthetic text and a similarly shaped benign control, **When** submitted,
   **Then** permitted work continues; false positives have an administrator review procedure.
4. **Given** application-managed credentials, **When** tools and providers operate, **Then**
   those credentials remain in trusted adapters regardless of Gateway detector behavior.

### User Story 3 — Control permitted models and spending (Priority: P1)

An operator selects approved models while an administrator sets finite spending limits for
the deployment. Budget or model denials stop work without weakening local execution limits.

**Why this priority**: Unbounded or alternative model use can bypass the intended control.

**Independent Test**: A synthetic matrix covers allowed/disallowed models, exhausted budgets,
concurrent work, missing usage prices and safe handling of provider failures.

**Acceptance Scenarios**:

1. **Given** an unapproved model or route, **When** selected by configuration or untrusted
   input, **Then** the runtime rejects it before dispatch.
2. **Given** a remote spending refusal, **When** a turn is attempted, **Then** the run stops
   without changing models, keys or providers to evade the limit.
3. **Given** an uncertain or interrupted billable request, **When** reported, **Then** cost
   remains unknown where unobserved and the request is not automatically replayed.

### User Story 4 — Inspect use without retaining conversation content (Priority: P2)

An operator can correlate model attempts with runs and inspect usage, latency, known cost and
control outcomes without collecting prompts, tool data, credentials or raw provider failures.

**Why this priority**: Operators need useful evidence that preserves existing privacy rules.

**Independent Test**: Capture local audit and exported telemetry under success, refusal and
failure; verify bounded metadata and the complete absence of private canaries.

**Acceptance Scenarios**:

1. **Given** a permitted model request, **When** it completes, **Then** the operator can relate
   its approved model, usage, elapsed time and known/unknown cost to the run and attempt.
2. **Given** control refusal, timeout, cancellation or telemetry failure, **When** summarized,
   **Then** the outcome is distinct, content-free and does not claim unobserved completion.
3. **Given** remote content capture cannot be disabled and verified, **When** readiness is
   assessed, **Then** private-data activation remains blocked with a named administrator action.

### User Story 5 — Prepare, migrate and validate honestly (Priority: P2)

An operator receives exact prerequisites and administrator steps, can migrate an existing
deployment without losing enrollment, and can distinguish software support from live proof.

**Why this priority**: A beta service and local configuration are insufficient evidence of
effective protection, cost limits or privacy.

**Independent Test**: Read-only setup matrices cover absent inputs, unsupported integrations,
unavailable beta controls, stale reviews and preserved enrollment; separately review live probes.

**Acceptance Scenarios**:

1. **Given** incomplete configuration or unavailable beta protections, **When** setup checks
   run, **Then** they identify missing names, responsible owner and next action without
   requesting secrets in chat or changing remote state.
2. **Given** an existing deployment, **When** migrating to Gateway, **Then** private settings,
   recovery holds and enrollment survive; changed context follows documented migration rules.
3. **Given** passing synthetic tests, **When** reporting readiness, **Then** vendor protection,
   spending and privacy acceptance remain pending until source evidence is explicitly reviewed.

### Edge Cases

- Empty credentials, conflicting aliases, unknown provider prefix or SDK ambient fallback.
- Redirects, region mismatch, untrusted endpoints, proxy settings and key rotation.
- Secrets embedded in history or tool results; non-text payloads that cannot be inspected.
- False positives, unsupported formats, encoded/fragmented secrets and unavailable remote status;
  these must not become universal secret-detection claims.
- Authentication, budget, guardrail, rate-limit and generic failures sharing a status code.
- Failure before dispatch versus uncertainty after dispatch; cancellation during a turn.
- Denial after a database read, outstanding cleanup, child runs and resumed histories.
- Remote logging before redaction/blocking, SDK exception bodies and accidental content capture.
- Parallel requests crossing a budget boundary; missing price/usage; remote control drift.

## Requirements

### Functional Requirements

- **FR-001**: Provide explicit Gateway mode covering every live model invocation made by
  CLI and workspace, including both database profiles, child agents and later model turns.
- **FR-002**: In Gateway mode, require an explicitly selected Gateway credential and reviewed route/model
  selection; prohibit direct-provider fallback, arbitrary model resolution and untrusted selection.
- **FR-003**: Require Gateway for new live setups. Preserve offline isolation and existing
  deployments through an explicitly selected legacy direct-provider mode, unmistakably identified
  as outside Gateway protection. Missing mode is not implicit permission for direct dispatch;
  migration must give an actionable choice without silently switching an enrolled deployment.
  Fresh live preparation MUST reject direct mode before creating enrollment; existing enrolled
  deployments may explicitly retain it or deliberately roll back to it.
- **FR-004**: Keep authentication material confined to trusted adapters. Add regression coverage
  demonstrating that application credentials never enter model content, errors or telemetry.
- **FR-005**: Require blocking Gateway protections for the documented credential coverage set
  on every selected route. Observe, flag and redaction-only policies do not satisfy this baseline.
  Unsupported payload surfaces or missing coverage MUST block protected activation.
- **FR-006**: Test synthetic credential canaries in user input, instructions, prior history,
  tool arguments and tool results, alongside benign controls. Record detector limitations and
  false-positive review without shipping a bypass or claiming exhaustive secret detection.
- **FR-007**: Guardrail, spending and model denials MUST end the affected run safely, without
  automatic retry, content-repair prompts, alternate keys/routes or replay of completed tools.
  Cancellation and uncertain dispatch MUST preserve exact cleanup and honest outcomes.
- **FR-008**: Enforce a locally reviewed exact model allowlist and retain local time, token,
  request and delegation limits. Remote routing must not introduce unreviewed model/provider
  failover; remote model restrictions, where supported, supplement local admission.
- **FR-009**: Keep deployment spending configuration and its review operator-owned when explicitly
  selected. Preserve local execution bounds and remote budget-refusal handling; report limits
  as unverified when administrative source is unavailable. Full spending attestation remains
  supported as an explicit review scope. Never invent amounts or claim local hard billing caps.
- **FR-010**: Record per-attempt, content-free model-use metadata linked to run/definition and
  parent where applicable: approved route/model, timing, usage, known cost and outcome. Distinguish
  unknown cost from zero, and preserve visibility of failed and denied attempts.
- **FR-011**: Disable conversation/body capture in application and Gateway telemetry before
  private use. Activation requires reviewed application and visible Gateway telemetry privacy.
  Gateway-internal retention/pre-block logging review is explicitly operator-owned in that
  scope and remains unverified; it MUST NOT be reported as passed. Full attestation scope
  continues requiring its administrative evidence.
- **FR-012**: Expose only closed sanitized refusal/error categories and bounded metadata to
  browser, CLI, audit and telemetry. Never forward raw upstream bodies, matched text or headers.
- **FR-013**: Extend read-only setup guidance for Gateway credentials, dependencies, endpoint
  trust, remote controls and evidence state, preserving existing JSON and exit-code meanings.
  Local prerequisites alone MUST NOT attest that remote controls are enabled.
- **FR-014**: Document administrator-owned enablement, credential rotation, route/model and
  spending configuration, protection rules, retention review and rollback. Remote changes and
  billable acceptance probes require their own authorized operational scope.
- **FR-015**: Bind protected activation to reviewed configuration and private evidence with
  reviewer, timestamp and disposition. Changed route/model/protections/spend/privacy settings
  invalidate the applicable review; drift limitations and periodic rechecks MUST be explicit.
- **FR-016**: Preserve identity verification, deterministic tool policy, narrower child
  authority, approvals, root admission, recovery holds and exact cleanup. Gateway is additional
  model-use control and MUST NOT supply tool authority or replace the sandbox boundary.
- **FR-017**: Add deterministic negative, cancellation, cleanup, replay, privacy and installed
  compatibility checks without live providers in ordinary CI. Keep software and live acceptance
  separate; unsupported beta behavior remains blocked with an owner and next action.
- **FR-018**: Update public setup/configuration/usage and agent-facing guidance, with explicit
  compatibility and migration steps. Maintain the slim base and reviewed optional provider extras.

### Key Entities

- **Model Route Policy**: Deployment mode, approved destination, protocol and exact model set.
- **Gateway Credential**: Private transport authority, distinct from upstream provider credentials. An explicitly
  selected project API key may authorize both Gateway and telemetry with the required scopes.
- **Control Review**: Configuration binding, reviewer/time/expiry, evidence references and disposition
  for protection, spending, remote privacy and route behavior; never authority from model output.
- **Model Attempt**: Run-correlated attempt identity, lifecycle, usage and known/unknown cost.
- **Protection Coverage Case**: Credential class, outbound surface, synthetic/benign control and result.
- **Readiness Finding**: Closed code, responsible owner and next action, with local/live distinction.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Every turn in the supported CLI/workspace and parent/child test matrix uses the
  selected controlled route, with zero direct dispatch in Gateway mode and zero live offline calls.
- **SC-002**: Every documented credential canary/surface pair is blocked before onward model
  delivery and every reviewed benign control succeeds. Application credentials appear in zero
  captured model bodies or public outputs. Synthetic and live results are reported separately.
- **SC-003**: Every tested model or spending denial produces zero automatic retries, route/key
  substitutions or repeated tool effects; existing execution limits and cleanup remain effective.
- **SC-004**: Each model attempt has a correlated terminal outcome or explicit unknown state;
  exported records contain zero content canaries and never label missing cost as zero.
- **SC-005**: All setup/migration matrix cases report the correct owner and next action while
  preserving private configuration, enrollment and holds; stale or missing review never yields
  protected activation.
- **SC-006**: Software checks pass independently of services. Live acceptance of routing,
  detection, spending and remote privacy requires source evidence, reviewer and dated disposition;
  none is inferred from settings or synthetic success.

## Assumptions

- Hosted Gateway in the operator-selected supported region is the initial deployment target.
  Self-hosting, third-party DLP services, embeddings, media and remote provisioning automation are
  outside this feature. Unsupported model payload types are refused in protected mode.
- Initial protocols retain the project's reviewed Google, OpenAI Chat/Responses and Anthropic
  integrations; each is subject to compatibility tests and explicit live evidence before use.
- An eligible organization and administrator are available for later setup; plan entitlement and
  beta behavior are verified per deployment, not inferred from marketing or the browser toggle.
- Budget amounts, organization/project identifiers, credentials and region are private deployment
  inputs supplied later. Planning does not choose financial commitments or ask for secret values.
- Remote inspection is defense in depth for text reaching the model boundary. It does not grant
  permission to include adapter credentials or prove arbitrary-secret, encoded-data or prompt-
  injection prevention. The existing secret-isolation boundary remains mandatory.

## Operator-owned administration amendment

Evidence and immutable reviews carry explicit `administration` scope: `reviewed` (legacy
four-control/full attestation) or `operator-owned`. The latter requires passing routing,
protection and telemetry-privacy evidence, complete fixed-case coverage and all existing
source/key/implementation/expiry bindings. It has no spending disposition or invented amounts;
spending configuration and internal-service retention remain operator-owned/unverified.
Missing scope defaults to the stricter legacy mode, never an inferred relaxation. Synthetic
evidence, unknown required controls, drift and expiry continue to block ordinary dispatch.
