# Quickstart: End-to-End PoC Closeout

The installed `agent closeout` commands below run locally without provider effects.
Use the [contract](contracts/runtime.md) for argument/schema and proof rules and
[data model](data-model.md) for limits. Substitute UUID/N placeholders with returned values.
Never paste credentials, real exports or reviewer files into an issue, PR or chat.

## Contributor setup and software validation

```sh
uv sync --locked --extra server --extra logfire --extra postgres --group dev --group browser
uv run --group browser playwright install webkit
uv run pytest -q tests/test_closeout_models.py tests/test_closeout_catalog.py tests/test_closeout_store.py
uv run pytest -q tests/test_closeout_sources.py tests/test_closeout_assessment.py tests/test_closeout_counting.py
uv run pytest -q tests/test_closeout_review.py tests/test_closeout_package.py tests/test_closeout_cli.py tests/test_closeout_privacy.py tests/test_closeout_bounds.py
```

The new tests must construct synthetic private files in temporary roots, deny network/subprocess
execution and poison provider environment. No test uses an existing `.local/` or `.env.local`.
The CLI integration fixture supplies owner-only inventory/source/review files in its temporary
project, runs the lifecycle below and checks zero provider calls plus explicit software provenance.
Implementation must document every maintained module/function and keep registered tool prompts stable.

## 1. Prepare and follow guides

Operator prepares an owner-only inventory file using the [documented schema](../../docs/usage.md#poc-closeout): actual version/
edition capability declarations, source profiles, owner roles and policy/dataset fingerprints. The
implementation adds schema examples within documentation/Python fixtures, not generated real evidence
in tracked JSON. Do not copy an entire local settings file; inventory contains no secret values.

```sh
uv run agent closeout prepare --inventory PRIVATE_INVENTORY_PATH
uv run agent closeout guide --dossier DOSSIER_UUID
uv run agent closeout guide --dossier DOSSIER_UUID --use-case UC1
uv run agent closeout inspect --dossier DOSSIER_UUID
```

Expected: revision 1, four guides, complete fifteen-row coverage, exact missing-evidence/owner/action
entries, no authentication or phone prompt. Missing inventory/capabilities stay blocked. An explicit
`amend` with current revision makes new inventory history without erasing old state.

Guides link the existing live workflows in
[003](../003-live-evidence-closure/quickstart.md),
[007](../007-provider-remediation/quickstart.md) and
[008](../008-shadow-agent-governance/quickstart.md).
Each suggested command is labeled with its actual effect. Run live commands only under the existing
authorized test scope. If IBMid sign-in is needed, use the local workspace page and scan inside IBM
Verify. Capture a new phone result only for an actual chosen test; packaging does not need a token.

## 2. Capture and assess

After an existing authorized check, select its returned member ID. Use the latest dossier revision
for each mutation; the following operations each return a new revision.

```sh
uv run agent closeout capture --dossier DOSSIER_UUID --revision N --kind validation --member RUN_UUID
uv run agent closeout capture --dossier DOSSIER_UUID --revision N --kind response --member INCIDENT_UUID
uv run agent closeout capture --dossier DOSSIER_UUID --revision N --kind governance --member CANDIDATE_UUID
uv run agent closeout import --dossier DOSSIER_UUID --revision N --manifest PRIVATE_MANIFEST_PATH --input PRIVATE_SOURCE_PATH
uv run agent closeout assess --dossier DOSSIER_UUID --revision N
uv run agent closeout report --dossier DOSSIER_UUID --assessment ASSESSMENT_UUID
```

Expected: every original criterion, distinct operation/proof/decision fields, exact evidence linkage
or specific blocker. Source roots retain identical file contents and metadata. A later repeated read
preserves the historical captured outcome and separately reports freshness/drift. F10 evidence already
expired before capture cannot be backdated into eligibility. Record actual capture promptly after the
demo; a historical source snapshot alone cannot recreate a missing in-time assessment.

Test missing, mixed-environment and contradictory members. Delete only synthetic fixture sources to test
missing applicability; never delete real evidence for a test. A failed native control must remain visible
when an older successful source is present. UC3 policy denial must not satisfy JWT-invalid proof.

## 3. Prepare and reconcile client experiments

The provider owner supplies a genuine 100-subject cohort, approved successful operation workflow,
actual identity mappings and entitled export access. `agent-only-users` and `direct-users` may require
an existing external provider test harness; the local app must not change its actor-only denial to
manufacture these scenarios. Missing surfaces receive a named prerequisite and expected evidence contract.

```sh
uv run agent closeout guide --dossier DOSSIER_UUID --experiment agent-repeat
uv run agent closeout experiment --dossier DOSSIER_UUID --revision N --input PRIVATE_EXPERIMENT_PATH
uv run agent closeout measure --dossier DOSSIER_UUID --revision N --experiment EXPERIMENT_UUID --input PRIVATE_MEASUREMENT_PATH
```

Before `experiment`, import baseline activity and entity/alias inventory and the reviewed cohort. Prepare
before the first scenario operation. After externally executing 100 successful operations, import the
roster, post-mapping inventory and complete final activity export after its reporting delay. Repeat for
agent-only-users, agent-obo-users and direct-users. The guide provides the evidence protocol and official
provider API link; it never executes or provisions users.

Expected: four independent measured statuses, distinct execution/subject/entity counts, scenario total
versus incremental count, reused/unrelated/non-entity/missing/extra sets and explained deltas. Synthetic
fixture result remains software evidence. A plausible total with a false or incomplete cohort cannot pass.

## 4. Review, package and handoff

Use private review files matching the strict discriminated schemas. Source profiles/extractions and
attachments have their own reviews; criterion decisions reference exact eligible assessment digests.
No CLI flag can bypass missing evidence. A source review attests review, not verified reviewer identity.

```sh
uv run agent closeout review --dossier DOSSIER_UUID --revision N --input PRIVATE_REVIEW_PATH
uv run agent closeout package --dossier DOSSIER_UUID --revision N --assessment ASSESSMENT_UUID
uv run agent closeout report --dossier DOSSIER_UUID --package PACKAGE_UUID
```

Expected: sealed private core with complete matrix, guides, evidence index, gaps, readout, timing/counts
and explicitly reviewed sanitized attachments. No raw source files, tokens or unreviewed screenshot is
copied into the core. A blocked package is useful and allowed; exit 0 only means creation succeeded.

Hold the actual witnessed review. Record one explicit decision for each required role—agent engineering,
Verify, Vault, VIP and customer security—against the returned core digest using `review`. A person with
several roles still records each role. Alternatives need customer and relevant vendor agreement and
preserve the original unmet criterion. Record real attendance/decision references; do not prefill approval.

```sh
uv run agent closeout handoff --dossier DOSSIER_UUID --revision N --package PACKAGE_UUID
uv run agent closeout report --dossier DOSSIER_UUID --package HANDOFF_UUID
```

Expected: new sealed private bundle containing unchanged core and applicable attestations/final decision.
No upload, email, provider change or public acceptance edit occurs. Reinspection verifies all bytes;
changed/missing dependencies qualify applicability. Original failed or blocked criteria remain visible
under accepted exceptions. Outstanding cleanup/integrity conflicts cannot be waived.

## Known external blockers and concrete next steps

| Gap | Responsible role | Action and expected recheck |
| --- | --- | --- |
| Demo-tier Vault audit unavailable | Vault owner | Supply an audit-capable approved environment/export linked to the tested operations, or obtain explicit criterion-exception agreement; recapture and reassess UC1-05/UC2 audit rows |
| Verify phone denial fails | Verify owner | Repair the registered-device flow with provider support; then intentionally run one phone-denied check and capture the exact decision/zero-issuance evidence; no automatic repeats |
| VIP event or native source unavailable | VIP owner | Supply reviewed event/collector schema and actual correlated finding/remediation receipt under 007/008; recapture relevant incident/candidate |
| Activity export unavailable/incomplete | Vault owner | Confirm access to the official activity-export endpoint for the exact namespace/edition; provide complete baseline/final files with effective period and collection metadata; rerun local measure |
| 100 distinct subjects or execution surface unavailable | Verify/Vault and agent owners | Provide reviewed native subject/entity roster and successful mode-specific operation evidence from an explicitly authorized test harness; do not replace it with repeated tokens for one account |
| Required witness absent | PoC lead and named role | Schedule the real review of the sealed package, record actual decision reference, then regenerate handoff |

These are native acceptance actions, not unfinished software tasks. All software paths must be implemented
and tested even when the only honest native report is blocked.

## Delivery checks

Run all `.github/workflows/ci.yml` commands, including privacy/history, all-feature/runtime gates, Ruff,
full pytest/WebKit, full two-policy security regression, deterministic validation, targeted repeatability/
readiness/closeout, offline demo and build/distribution checks. Add a 010-focused repeatability/performance
check to CI only if not already exercised by full pytest. No credential-bearing CI fixture is allowed.

Record actual implementation results and native limitations in a sanitized
`specs/010-poc-closeout/validation.md` during implementation. Leave software tasks unchecked until executed;
keep acceptance.json blocked until separately reviewed native proof and owner decisions exist.
