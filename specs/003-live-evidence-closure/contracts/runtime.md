# Runtime contracts: Live readiness and evidence closure

These are planned additions to the existing agent CLI; implementation has not begun.
The canonical command is agent; the legacy alias remains available. Versioned constraints
C01–C12 in [data-model.md](../data-model.md) are normative.

## Readiness

```sh
uv run agent validate ready --suite live-database
uv run agent validate ready --suite live-database --scenario actor-only-denial
uv run agent validate ready --suite live-phone --scenario phone-approved
uv run agent validate ready --suite live-phone --scenario phone-denied
```

The suite is required, live-only, and selection rules match the current catalog. A phone case
must be named exactly once; `--interactive` is not required for this local-only command and
must not be passed through as authorization to run. Internally validate selection with live
mode and a nonexecuting phone-selection context; do not weaken run's interactive requirement.
No `--root` or persistence option. Reject selection before loading Settings. Help text explains
that external identity/permissions/receipt remain unverified. JSON stdout uses ReadinessReport.
No environment value, config path, issuer, account identifier or validation exception is echoed.

Readiness IDs and local predicates (all applicable checks are evaluated):

| Section | Registered check IDs | Predicate |
| --- | --- | --- |
| Execution | human-token, oauth-client, oauth-audience | Required values present; token validity unverified. |
| Execution | oauth-config, profiles | Existing trusted configuration parses; selected profile exposes required capability. |
| Execution/database | postgres-extra, vault-target, delegated-audiences, database-target, database-tls | Existing adapter prerequisites parse; fixed path and CA are readable/bounded. |
| Execution/phone | phone-enabled, phone-client, phone-mapping | Explicit push flag and trusted user/device/API credentials present. |
| Execution | configured-exporter | When a write token is configured, optional exporter SDK and HTTPS override validate. |
| Evidence | telemetry-config | Write token, exporter SDK and expected project alias configured for this walkthrough. |
| Evidence | vault-export, verify-events-export, logfire-export | Manual source export/read access remains unverified; no probing. |
| Execution | remote-identity, remote-permissions, remote-reachability | Always unverified until the selected real run. |

Owners: local settings are operator; external permissions/exports are integration_owner;
review obligations are reviewer. A field can be not_applicable for the other suite.
Execution does not require evidence-only settings: the existing runner invokes the shared
execution evaluator then performs genuine ingress verification and scoped effects.

## Native imports and joins

Use existing `validate import --run ... --source ... --input ... --manifest ...`.
The manifest selects format_version 1 or 2; all other existing input bounds remain.
Supported new shapes are strictly the C05 forms. Include native `trace_id`, `span_id`,
`parent_span_id`, `start_timestamp` and trusted attributes for telemetry. Optional native
project fields obey name/ID-specific matching; absence is operator-scoped provenance.

Normalize documented Vault request/response IDs and nested secret lease metadata. Exact opaque
request/header linkage does not establish raw/HMAC lease equality; incomplete or incompatible
lease evidence remains blocked. Verify Events are importable reporting data but are not linked
to runtime OAuth/push operations without a separately supported mapping.

For each approval, trusted code persists approval_ref/action_digest in its private operation
binding before the HTTP request. After response, it binds native_transaction_id to that same
operation. Add these optional fields to the private binding contract (UUID and Digest); they
are mandatory for new approval evidence. Historical bindings missing them remain readable but
cannot qualify for a new closeout or passing phone review. Capture/reconstruct binding failures
fail safely and cannot execute the simulated write. One raw transaction ID cannot be reused
across case slots or selected runs. DENIED/VERIFY_DENIED/USER_DENIED alone establishes a witnessed denial;
all other non-success states are decision_unverified for phone-denied.

Existing per-run review requires exact referenced artifacts covering C12. A declared source
kind and one unrelated matched event are insufficient. Correlations for unsupported Verify
Events stay explicit even when a verified transaction response supports the phone operation.

## Closeout creation and inspection

```sh
uv run agent validate closeout --run DATABASE_RUN_UUID --run APPROVED_RUN_UUID --run DENIED_RUN_UUID
uv run agent validate closeout --closeout SNAPSHOT_UUID
```

`--run` is repeatable 1–4 times; `--closeout` is mutually exclusive and accepts one UUID.
`--root` has the same private-root restriction as existing validation commands. The common
three-run selection uses one database run containing both database cases plus one run per
phone case. Two separate database runs are also allowed, yielding four total runs. Supplying
only some cases creates a blocked snapshot with missing slots; duplicate cases never choose
one observation as authoritative. Offline/foreign suite selection is invalid and produces no
snapshot. All selected live members require C04 context and current compatible revisions.

Creation rebuilds each run, evaluates the matrix below and projects its reviews. It writes a
new immutable snapshot and prints safe JSON including snapshot_id/content_revision. JSON and
Markdown carry identical case/member/criterion conclusions. Inspection reads a named snapshot,
revalidates all inputs and prints current applicability; it never rewrites the saved snapshot.
Changed input reviews count as a revision change even if the operation outcome stays the same.
A user creates a new snapshot explicitly to include updated imports/reviews.

## Four-case obligation matrix

| Case | Operational proof | Required source evidence for selected closeout |
| --- | --- | --- |
| delegated-database-read | Verified ingress/delegation, fixed read, successful exact cleanup; zero forbidden effects. | Matched native acquisition and cleanup request/response pairs with exact lease linkage; all expected telemetry spans received. |
| actor-only-denial | Exactly one actor-only attempt, explicit expected denial, no usable credential or database read. Unexpected issuance fails even if cleanup succeeds. | Complete matched native denied request/response pair for the exact operation; all expected telemetry spans received. |
| phone-approved | Exactly one request, native approved response for the bound action, one simulated write and no forbidden effect. | Exact containing-run/observation/action-bound transaction response; all expected telemetry spans received. |
| phone-denied | Exactly one request, intentional native deny, zero simulated writes. Expiry/cancel/timeout cannot substitute. | Distinct exact containing-run/observation/action-bound intentional denial transaction; all expected telemetry spans received. |

Configured write-key acknowledgment is insufficient for any receipt slot. Source exports and
transaction bodies stay private. A matrix success establishes only these four observed cases
and source requirements. Unsupported Verify Events linkage, UC3/VIP/workload claims, unrelated
path/SQL write-denial obligations and broader customer criteria remain visible and blocked in
per-run review projections. There is no aggregate customer acceptance field.

## Atomicity and output

Acquire all selected member locks in sorted UUID order, fail with storage_error on contention,
then collect input inventories, reconstruct and recheck inventories before atomic finalization.
Context, source, transaction, binding, review and definition/implementation changes are included.
A 30-second deadline or interruption releases locks and never publishes a finalized success.
This controls cooperating local writers and detects byte changes; it authenticates neither a
hostile filesystem owner nor an operator-supplied export.

Output projection: schema version, opaque snapshot/run/observation/review IDs, registered case
and criterion labels, enum outcomes, safe reasons/owner roles, counts, UTC time and digests.
Private native IDs, context digests, settings values, raw paths and free text are excluded.
Generated closeout/context files are publication-forbidden even when force-added elsewhere.

Exit precedence and local timing bounds follow C03/C11. A complete operational/evidence
walkthrough can exit 0 while unsupported customer criteria remain blocked; stdout states each
layer independently. Existing run, report and review commands keep their separate semantics.

## Compatibility and live authorization

No new environment variables or extras. The configured Logfire project alias remains private;
a renamed project does not rewrite historical manifests. Old v1 source records and per-run
reports remain readable; new evidence requirements may invalidate old review applicability.
Run IDs lacking a sealed context cannot be upgraded from current settings. Explicit new live
runs are necessary for combined closeout when historical records lack required bindings.

Planning authorizes no live phone request. At implementation time, database execution uses the
existing authorized PoC target; each phone invocation still requires one operator-selected
case, interactive mode and a present witness. Exports are manual, private and authorized.
No command provisions services, grants permissions, changes audit settings or promotes tracked
acceptance.json. Delivery controls are checked separately before any merge.
