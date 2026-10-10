# Implementation validation ledger

Software implementation complete. Live and delivery gates remain open independently.

## Dependency baseline and threat review (T001)

Existing locked Pydantic AI Slim/Pydantic, settings, HTTPX and PyJWT/cryptography suffice.
No dependency or lockfile changes are planned. Baseline licenses are MIT (Pydantic AI,
Pydantic/settings, PyJWT), BSD-3-Clause (HTTPX) and Apache-2.0 OR BSD-3-Clause (cryptography).
Existing PostgreSQL/Logfire SDKs remain optional.

Readiness and closeout are local-only. Untrusted exports, conflicting IDs, wrong-run approvals,
concurrent edits and stale reviews must fail safely. Context snapshots contain selectors but
no credential values and remain private. Digests establish byte consistency, not authenticated
provenance. Sorted nonblocking locks and final inventory checks protect cooperating writers.
Exact-action binding precedes requests; capture failure must prohibit simulated writes.

002 T036/T037 retain their original real-proof obligations. Feature 003 software does not
complete them. Missing native audit linkage remains blocked; no customer acceptance is promoted.
Default branch protection and later delivery authorization are separate T028 prerequisites.

## Results

Requirements checklist: 16/16 passing, unchanged.

- Privacy and tracked-history gate passed. Prospective new paths also pass the publication allowlist.
- All-feature specification gates passed for 001, 002 and 003; each retains 15 blocked live criteria.
- Runtime configuration, Ruff check/format, Git whitespace review and offline demo passed.
- Full regression suite: **223 passed in 16.39 seconds**. Boundary tests cover readiness without effects,
  v2 native shapes, wrong transaction joins, intentional denial versus non-approval, context changes,
  review eligibility, snapshot tampering/staleness, contention and interrupted finalization.
- Four synthetic maximum runs each contain 10,000 normalized native events. Pure closeout assembly
  stays under ten seconds after private input reconstruction; the complete performance test passes
  in approximately four seconds locally. This is deterministic application proof, not vendor proof.
- Wheel and sdist built successfully and passed distribution privacy checks. No dependencies or
  lockfile changed. New context/manifest/closeout files are rejected even when force-added elsewhere.
- Installed base wheel tested from /tmp with network denied: optional Logfire, PostgreSQL, server
  and Google SDKs absent; readiness safely returns blocked and all nine offline scenarios pass.
- Deterministic quickstart: local ready selections and offline validation pass their documented
  exit contracts. New CLI selection guards and immutable snapshot creation/inspection are tested.

## External proof gates (T022–T024)

The operator completed authorization-code/PKCE sign-in through the already configured login
application. The resulting user JWT was signature/issuer/audience/expiry verified before private
storage. Runtime ingress independently verified the human identity and required tool scopes.
A token expiry blocked an attempted phone case before effects; a second explicit sign-in refreshed
it. No administrative credential substituted for the user token.

Genuine database runs passed delegated read, exact lease revocation and actor-only denial with
no acquired credential. Native Logfire row exports matched all 28 expected spans after fixing
the actor-only root observation binding. Export acknowledgment and imported remote receipt are
separate checks; both now hold. The live run remains evidence-blocked by missing Vault audit.

The HCP portal shows the configured cluster is Development tier. HashiCorp documents that this
tier has no downloadable audit logs. A scoped sys/audit read returned 404; the operator confirmed
no audit-log UI. No cluster upgrade, audit-protection change or additional provisioning was
performed. Original [002 T036](../002-security-validation/tasks.md) and 003 T022 remain open until
native acquisition/cleanup/denial audit proof exists; runtime observations do not replace it.

Phone approval was explicitly selected and witnessed; exactly one simulated write occurred.
The first witnessed denial returned native USER_DENIED, exposing a missing precise state alias.
Regression tests failed before the fix; the native schema confirms this is user rejection.
That original failed run remains untouched. Fresh runs on the corrected implementation are
recorded below. Generic failure, expiry, cancellation and timeout remain unverified decisions.
Native transaction proof does not establish independent Verify Events linkage; original
[002 T037](../002-security-validation/tasks.md) stays open. No customer acceptance was promoted.

003 T024 remains open while required database source evidence is absent. Any private closeout
can record the observed operational cases, remote receipts and outstanding source blocker;
it cannot create missing source proof or reviewer signoff.

## Delivery gate (T028)

Read-only GitHub API inspection of default-branch protection returned HTTP 404, "Branch not
protected." Required validate status, code-owner review, stale-approval dismissal, resolved
conversations and force-push/deletion controls cannot be verified as enforced. Delivery remains
blocked. No protection setting was mutated. The later explicit merge instruction authorizes preparing
and delivering this change, subject to the required controls and review.
A later explicit delivery instruction and the required controls/review remain necessary.

## Final threat review

Readiness never treats a token's presence as verified identity. Runtime ingress remains genuine;
there is no synthetic/admin fallback for live work. Approval/action binding is persisted before
requests and persistence failures prevent push or authorization of the simulated write. Cleanup
still follows acquired leases. Native identifiers and deployment/reviewer values never appear in
public projections. Snapshot conclusions are reconstructed from current private inputs and digest
bound inventories; missing, stale and corrupted inputs cannot be reported as current success.
Hashes and operator manifests prove consistency, not authenticated source provenance. Cooperating
writer locks and final inventory checks do not claim protection from a hostile local administrator.
All broader customer enforcement and reviewer signoff obligations remain separate.

## Live-discovered compatibility corrections

- IBM Verify native USER_DENIED now maps to intentional denial, with trusted approval/action/run
  joins unchanged. The primary API schema is cited in research.md; timeout/expiry/failure do not qualify.
- The actor-only root span now includes its selected observation UUID, so every exported root and
  child span receives a private trusted binding and remote receipt can cover the entire inventory.
- The existing legacy-format Logfire token was authenticated against the native info endpoint and
  matched the configured project. Its verified US base URL was set privately via the existing override.
- Phone push was enabled privately for the explicitly selected witnessed tests. No tracked settings,
  credentials, native source IDs or raw exports were published.

## Final build and operator-directed continuation

The operator explicitly directed continuing the build after repeated IBM Verify app failures.
Fresh denial prompts were individually requested and witnessed, but the app displayed
"Oops, something went wrong" after Deny. Authenticated read-only transaction checks returned
PENDING; interrupted attempts were preserved privately. These attempts do not establish a
native denial. No further phone requests were sent. T023 remains open, independently of the
successful witnessed approval and its complete native Logfire receipt.

A private closeout assembled the final current-code database and approved-phone runs. Both
creation and explicit snapshot inspection returned blocked (exit 2), with current applicability:
operational closure lacks the final denial case, and evidence closure lacks Vault audit proof.
All 15 customer criteria retain their existing blocked reviewer dispositions. No source evidence,
review or acceptance decision was synthesized. T022 and T024 remain open.

Final build verification: 223 tests passed in 16.18 seconds; lint and formatting passed;
privacy/history, all-feature and runtime gates passed; offline validation and demo passed;
wheel and source distribution built successfully and distribution privacy passed.
The operator's continuation authorizes software delivery with these live limitations recorded.
It does not claim successful vendor enforcement or change repository protection settings.
