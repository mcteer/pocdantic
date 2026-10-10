# Validation ledger: Provider detection and remediation

## Planning scope — 2026-10-10

Prepared specification, clarification review, researched plan, data model, runtime
contracts, validation guide, task list and design checklists on
`feature/007-provider-remediation`. No application code, dependency, live provider,
credential or enrolled local response/recovery state changed.

Clarification: zero questions required; accepted roadmap and prior decisions resolved
scope. Requirements checklist: 16/16. Security checklist records design coverage only.

Research used repository code, the private supplied roadmap and linked primary provider
documentation. Native VIP transport/schema/collector evidence remains an enrollment
prerequisite; no tenant API was guessed. Existing Development-tier audit limitation
remains documented and is not a request for another human token.

Pre-analysis artifact checks passed: all-feature Spec Kit gate, runtime configuration
gate, 59 sequential task IDs, all 22 requirements and seven criteria mapped, 23 exact
data-model constraints quoted in tasks, and valid local document links. The prospective
planning tree is also checked for whitespace and publication privacy. No application
tests or live probes were run for this documentation-only phase.

Pre-analysis technical review corrected native-login uncertainty, negative-probe recovery,
canonical resource deduplication, per-incident notification identity and the unsupported
actor-configuration recovery route. Formal read-only consistency analysis follows these
artifact checks and is reported in the completion response; this ledger does not pre-claim
that analysis result.

## Implementation validation — 2026-10-10

All four stories are implemented with strict provider contracts, bounded authenticated
native projection, durable exact actions, isolated proof processes, independent reporting,
WebKit session isolation, and explicit reviewed recovery. No dependencies or environment
variables were added. No live provider configuration or private enrollment was modified.

Threat/compatibility review: preserved 006 normalized source permissions and short local
containment, all legacy recovery receipts and schema boundaries. Offline migration sends
no provider requests and preserves original holds. Native projection rejects secret fields,
ambiguous mappings and changed selected security content; enrollment races fail closed.
Canonical resource/generation fences, prospective accessor ownership and explicit subject
holds prevent scope widening. Network calls occur outside control transactions; inherited
FDs retain child ownership after parent exit. Mutation intent precedes dispatch; timeout,
cancellation, lost reply and interrupted adoption retain uncertainty and never replay effects.
Reviewed retry reads current metadata before a linked bounded attempt. Newer hold/revision
races cancel the decision. Late native joins preserve the strongest required-proof flag. Old-credential lifetime safety cannot become enforcement proof.
Renamed private artifacts, secret maps, DSNs, receipts and publication examples are fenced.
Near-capacity regression confirms result writes consume their reservation rather than
double charging it; acquisition intent reserves future handle/result space before dispatch.
Module/function documentation explains purpose, effects, failure and ordering; usage/config
and ADR guidance cover migration, private input, per-provider repair and native limitations.

Final software validation passed for implementation digest
`b38119468ee834cbbed98469fcf2a0f30b3f66e678eeee7be1611ca0309d9005`.

| Check | Result |
| --- | --- |
| `uv run --group browser pytest -q` | 709 passed in 101.52 seconds, including WebKit scenarios |
| CI repeatability, 10,000-event report, readiness and closeout tests | 29 passed in 5.14 seconds |
| `uv run ruff check .` / `uv run ruff format --check .` | Passed; 249 files formatted |
| All-feature and runtime configuration gates | Passed for all seven features; live criteria retain blocked dispositions |
| `uv run agent validate run` | Nine selected/completed offline scenarios, all pass |
| `uv run agent demo` | Passed with synthetic adapters |
| `python3 scripts/check_privacy.py --history` / staged whitespace check | Passed against the proposed publication tree |
| `uv build` / `uv run python scripts/check_distribution.py` | Wheel and source distribution built; distribution privacy passed |

The quickstart's four synthetic story workflows, migration interruptions, owner survival,
lost replies, persistence failures, capacity bounds, enrollment races and renamed private
artifacts are covered by the passing regression suite. Live quickstart steps remain subject
to the exact prerequisites below. No extension hooks are configured.

## Native Function 10 dispositions

No 007 live effects were requested or executed during implementation. All nine native
scenarios are **blocked**, with concrete prerequisites below. Synthetic tests exercise
these workflows without certifying providers. All 15 acceptance entries remain unchanged;
closeout never writes acceptance.json. The Development-tier audit limitation remains.

| Scenario | Exact unavailable prerequisite | Operator step and expected recheck |
| --- | --- | --- |
| F10-T1 | Reviewed VIP rule schema, authenticated relay route and collector receipt | VIP operator exports the minimal schema/sample/receipt into `native-ALIAS.*.json`, pins digests and relay subject/audience in the private draft, runs `providers readiness` then enrolls. An authorized safe trigger must automatically POST to `/response/native/ALIAS`; import correlated native intake evidence. |
| F10-T2 | Authorized isolated dynamic lease, installed revocation-SQL review and distinct healthy direct DB account | Vault/DB operator reviews the configured role's canonical revocation statements, supplies its digest and private healthy DSN alias. Enable existing automatic exact cleanup prospectively. Start `dynamic_database` proof before the authorized event; expect separate fresh-login denial and independent held-session termination with healthy control and exact recovery receipt. |
| F10-T3 | Exact registration control authority plus captured unexpired delegated JWT and distinct enrolled peer | Vault operator confirms registration/entity/OAuth-profile mapping and scoped read/delete capability. Start `same_jwt` and separately `fresh_issuance` proofs before distinct authorized events; import reviewed provider denial observations. Registration absence alone is insufficient. |
| F10-T4 | Dedicated mapped tenant user, reviewed API-client entitlements/session schema and Teams message receipt | Verify administrator supplies `verify-ALIAS.authority.json` and reviewed session selector/schema digest, then grants exact tenant user/session authority. Workflow owner supplies the private URL and posting connection. Start `user_sessions` before the event; import tenant suspension and correlated notice delivery evidence. Upstream/global IBMid logout remains unsupported. |
| F10-T5 | Authorized isolated static role, separate proof/healthy DSNs and nonoverlapping rotation schedule | Vault/DB operator confirms the exact role/user, metadata/rotate capability and direct isolated-session controls. Start `static_database` before the event; old-password denial and replacement usability must pass independently. Scheduled overlap is inconclusive. |
| F10-T6 | Reviewed source and last-required-denial evidence with clock bounds | Integration operator records UTC source/collector/proof clock bounds of at most five seconds each and imports correlated observations. Status shows an interval only when every required path is proven; its upper bound must be below 30 minutes. Missing clocks remain unavailable. |
| F10-T7 | Prospectively captured exclusive native service accessor and separate healthy root | Vault operator enrolls the exclusive login mount/role and scoped accessor control authority. Host-register two roots and capture both native accessors before exposure. Start `native_token` for the target root before its authorized event; the peer token must remain usable. Ordinary OBO has no native accessor path. |
| F10-T8 | Complete enrolled definition inventory and all existing/fresh path proofs | Integration operator enrolls exact registration/user/static resources and authorized rules, then runs the applicable pre-event proofs. Import reviewed outcomes for every enabled route, resolve all unknown acquisitions and exact cleanup. A separately enabled native JWT-role fresh-login path remains explicitly unverified; OAuth denial cannot certify it. Partial/unknown inventory cannot pass full containment. |
| F10-T9 | Same captured JWT still unexpired, real native intake evidence and bounded receiver/proof clocks | Run the `same_jwt` pre-event workflow with a healthy peer; import correlated native intake and immediate actual denial evidence with clock bounds. Expiry, cancellation, outage or a missing baseline cannot pass immediate enforcement. |

Use [the runtime guide](../../docs/usage.md#provider-remediation) for exact command syntax,
private stdin fields, current revisions and receipt import. Before a live effect, identify
and authorize the isolated target/action; this ledger does not authorize provider changes.
