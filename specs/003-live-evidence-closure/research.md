# Research: Live readiness and evidence closure

Reviewed 2026-10-09. Read-only code inspection and primary documentation; no live service was
called and no credential was examined. Research resolved implementation choices; external
capability/proof availability remains an explicit execution gate.

## R1 — Reuse the existing live runner

**Decision**: Keep the four factories, per-run imports/reviews and bounded execution. Add small
readiness/context/closeout modules.
**Rationale**: `scenarios.py:191` has coarse truthiness preflight; `commands.py` exposes no
readiness or multi-run closeout. `runner.py` already handles deadlines, cleanup and interruptions.
`report.py` and `review.py` already rebuild evidence and reject stale reviews.
**Alternatives considered**: A new orchestrator or auto-running four-case suite would duplicate
execution and conflict with the requirement for individually witnessed phone decisions.

## R2 — Readiness is local configuration assessment

**Decision**: No network, token acquisition, trace export or file persistence. Mark remote checks
unverified and rerun execution checks at the actual effect boundary.
**Rationale**: `probe.py:37` acquires an API token, reads inventories and persists them; invoking
it would exceed a harmless selected-case readiness assessment.
**Alternatives considered**: Optional network mode and automatic login add permissions and
failure modes without being necessary for this feature; defer both.

## R3 — Native Vault shape and exact linkage

**Decision**: Parse `request.id` and nested `response.secret.lease_id`; keep existing top-level
lease representation as a legacy input only when it does not conflict. Pair request/response
using exact IDs; require exact cleanup evidence. Keep unknown HMAC linkage unsupported.
**Rationale**: The current parser reads only `response.lease_id`. The official audit schema puts
leased-secret metadata under `response.secret`. Audit strings may be HMAC-protected. A native
request ID or opaque correlation header establishes request linkage, not raw lease equality.
**Alternatives considered**: Raw audit logging or automatic audit-hash calls would change
administrative boundaries. Timestamp-only matching is insufficient.
**Sources**: [Vault audit schema](https://developer.hashicorp.com/vault/docs/audit/schema),
[audit logging](https://developer.hashicorp.com/vault/docs/audit),
[audit-hash API](https://developer.hashicorp.com/vault/api-docs/system/audit-hash),
[audit device lifecycle](https://developer.hashicorp.com/vault/api-docs/system/audit).
Disabling/re-enabling a device changes its hash context; a declared complete export is operator
provenance, not proof that it covers all devices. See [audit best practices](https://developer.hashicorp.com/vault/docs/audit/best-practices).

## R4 — Telemetry JSON compatibility and project identity

**Decision**: Support existing row-array/rows envelopes plus documented direct query JSON;
keep CSV, Arrow and NDJSON unsupported. Distinguish names from IDs, bind an explicit native
project ID in private import metadata if present, and keep source provenance visible.
**Rationale**: Current `normalize()` accepts arrays or `rows`; the direct query response uses
`schema` and `data`: schema.fields contains name/data_type/nullable metadata and data is
a list of row objects. The query client also offers a `columns`/`rows` form. Native project_id
is not universal metadata; the SQL reference classifies it as internal, so exports need not
select it. If supplied, it must never be compared to a display name. Exact trace/span/run
and parent checks already exist and must not be weakened. A project rename changes a name,
not the meaning of a native UUID.
**Alternatives considered**: Automatic read-token collection is unnecessary; manual exported
JSON avoids a new runtime credential. Export acknowledgment alone cannot prove receipt.
**Sources**: [Logfire export API](https://pydantic.dev/docs/logfire/manage/query-api/),
[query client](https://pydantic.dev/docs/logfire/api/query_client/),
[SQL reference](https://pydantic.dev/docs/logfire/reference/sql/).
Read/export access requires a read token distinct from the write token; the authorized operator's
export tool holds it. Runtime settings keep the existing write token and private project alias.

## R5 — Verify evidence limitations and decision semantics

**Decision**: Keep provider Events linkage unsupported. Tighten captured transaction ownership
and distinguish intentional denial from generic non-approval.
**Rationale**: `load_transactions()` currently groups denial, timeout, expiry, cancellation and
failure; those cannot all prove a witnessed denial. It also needs containing-run joins. The
Events API documents event and correlation IDs, but the reviewed sources establish no equality
with push transaction IDs. Events are delayed reporting data, not a synchronous proof stream.
**Alternatives considered**: Guessing linkage from shared IDs/timestamps would fabricate proof.
No new customer criterion is enabled based solely on an actor denial or simulated write.
**Sources**: [Events reference](https://docs.verify.ibm.com/verify/reference/getallevents),
[export guide](https://docs.verify.ibm.com/verify/docs/pulling-event-data),
[service payload](https://www.ibm.com/docs/en/security-verify?topic=reports-service-events-payload),
[token payload](https://www.ibm.com/docs/en/security-verify?topic=payloads-token-event-payload),
[verification initiation](https://docs.verify.ibm.com/verify/reference/initiateverification).
The endpoint reference permits readReports or manageReports. Default queries omit token events;
complete pagination uses paired cursors and unchanged bounds. These are manual export guidance,
not grounds to add collection permissions to the runtime.

## R6 — Closeout is a snapshot, not a new review authority

**Decision**: Explicitly select 1–4 run IDs; require a sealed equal private deployment context;
assemble four operation/evidence slots and 15 rows of existing per-run review decisions. No
aggregate customer pass/alternative. Require exact current evidence revisions and locked final checks.
**Rationale**: Existing `configuration_fingerprint` contains suite/bounds and cannot compare a
phone run with a database run. A new context excludes those execution choices and secrets.
Inspecting all selected reviews avoids convenient-run selection and conflict suppression.
**Alternatives considered**: A new cross-run review scheme substantially broadens the acceptance
model. Deferring it preserves the current explicit review contract and avoids false promotion.

## R7 — Dependencies and delivery

**Decision**: Reuse the locked stack and existing private-store mechanisms; add no new dependency.
Keep software completion, live evidence gates and server-side delivery controls independent.
**Rationale**: All planned work is local parsing/evaluation and existing live adapter execution.
The prior merge does not establish the constitution's required branch protection. Verify it
before 003 delivery; absence is a delivery blocker, not grounds to fabricate protection.
**Alternatives considered**: Administrative automation or a constitution exception is outside
this planning request. Neither is required to implement and test this feature.

## Live correction: native intentional denial

The witnessed cloud transaction returned USER_DENIED. IBM's verification API schema defines
this value as the user's explicit rejection through the authenticator. Accept this precise
native state alongside existing DENIED/VERIFY_DENIED aliases; continue blocking generic failure,
expiry, cancellation and timeout as intentional-denial proof. This corrects the original C06
state list without broadening approval or accepting guessed Events linkage.
Primary source: [IBM Verify transaction API](https://docs.verify.ibm.com/verify/reference/getverification)
(the embedded API schema includes USER_DENIED). Preserve the earlier failed run and require fresh
validation after the implementation change; do not rewrite its assertion or raw records.
