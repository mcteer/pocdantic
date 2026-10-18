# Quickstart Validation: Model Gateway and Credential Guardrails

**Implemented workflow**: Gateway commands and tests below are available. Software and
bounded live checks are recorded in [validation.md](validation.md). Configuring protections
or passing synthetic probes does not itself approve normal private-data activation.

## Deterministic development validation

Use Python 3.12+, canonical repository root and the committed lockfile. Install the complete
selected extras set together; the SDK already carries HTTPX2 and there is no Gateway extra.
For the full synthetic protocol/browser matrix:

```sh
uv sync --locked --extra server --extra postgres --extra sandbox --extra google --extra openai --extra anthropic --extra logfire --group dev --group browser
uv run --no-sync playwright install webkit
uv run --no-sync pytest -q tests/test_gateway_configuration.py tests/test_gateway_transport.py tests/test_gateway_controls.py tests/test_gateway_privacy.py tests/test_gateway_review.py tests/test_gateway_probes.py
uv run --no-sync pytest -q tests/test_model_configuration.py tests/test_runtime.py tests/test_api.py tests/test_telemetry.py tests/test_offline_entrypoints.py
uv run --no-sync pytest -q tests/test_setup_guidance.py tests/test_setup_readiness.py tests/test_setup_walkthrough.py tests/browser/test_workspace_gateway.py
uv run --no-sync python scripts/check_onboarding.py --case offline
uv run --no-sync python scripts/check_onboarding.py --case guided
uv run --no-sync agent demo
uv run --no-sync agent sandbox demo
```

All tests use synthetic transports and isolated settings/state. Expect no sockets to Gateway,
model providers, identity/Vault/database services, telemetry or phone services. Verify native
constructor/header/path correctness, one send per attempt, later-turn/child admission, terminal
denials, cleanup, cancelled/unknown outcomes and metadata privacy. Add focused tests before
implementation, then run the complete applicable CI gates in the workflow.

## New live deployment after implementation

Follow [administrator preparation](contracts/administration.md) in an authorized operational
session. The operator supplies input names privately; no key or provider/admin token belongs in
chat or tracked files. `MODEL_MODE=gateway`, explicit supported `MODEL`, region, route, exact
allowlist and key are required. Use the selected provider extra plus server/postgres, and sandbox
only for analysis. Optional Logfire export adds the logfire extra.

```sh
uv run --no-sync agent setup guide --recipe workspace-read --format json
uv run --no-sync agent setup check --recipe workspace-read
uv run --no-sync agent gateway status --format json
```

Missing inputs give exit 2; absent/stale controls review gives exit 3. Local prerequisites are
not vendor acceptance. `setup check --network` does not issue a model request. Configure remote
protections/pricing/spend/privacy via the administrator runbook before any private-data request.
Use the fixed probe case names from the implemented registry, separately authorized for their
bounded model cost, then explicitly review private evidence. The runbook explains the proposed
`probe` and `review` command arguments; they must not be run as part of ordinary CI.

After review, reuse the existing recovery/policy enrollment procedure, preserving holds and
review requirements. Launch `agent workspace`, use its actual printed URL/callback, sign in,
select `database-reader`, and request record 1. For analysis substitute `workspace-analysis`,
select `database-analyst`, and request count by status. Verify observed stages and cleanup with
`agent recover status`; model narrative alone does not establish success.

## Existing deployment migration

A missing `MODEL_MODE` must produce migration guidance before any model call. To retain legacy
behavior, the operator explicitly chooses `direct`; setup and workspace display absence of Gateway
protection. To migrate, configure Gateway inputs and obtain new review; do not auto-convert a GLA
model into Vertex or assume the same name is available. Checks preserve existing private file
bytes and enrollment. Model-routing changes invalidate validation context and Gateway review,
while identity/database-target changes use existing recovery migration. No reset or state copy.

## Expected demonstrations

| Scenario | Observable result |
| --- | --- |
| Benign permitted request | One approved Gateway dispatch per model turn; correlated metadata, observed/unknown cost. |
| Covered synthetic secret on any supported surface | Reviewed blocking outcome, zero onward provider dispatch; no matched text in errors. |
| Local disallowed model | Rejection before transport, no model call. |
| Remote budget/access refusal | Terminal closed error, no retry/fallback or repeated tool effects. |
| Interrupted dispatch | Unknown remote completion/cost, normal cancellation/cleanup behavior, no replay. |
| Missing/expired/mismatched review | Exit 3/readiness blocker before private request; probe path remains synthetic-only. |
| Poisoned SDK environment/header values | Explicit region/route/Gateway auth retained; no credential leakage or redirect. |
| Content-bearing upstream error | Safe bounded local reason; no body or SDK exception text in browser/CLI/traces. |
| Transport-only migration | Recovery/enrollment bytes and holds preserved; control review invalidated. |

Record software results and each live acceptance item separately in [validation.md](validation.md).
Unexecuted or unsupported checks stay blocked with an owner and next action.

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
