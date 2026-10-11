# Implementation validation: Security Regression Validation

**Date**: 2026-10-10 (local). **Branch**: `feature/009-security-regression`.
**Baseline**: merged 008 (`3560bfbd49a19648c4e494bd6f4b791429f04aae`).

## Software result

Contributor list/run/report tooling implements the complete Function 12 catalog: fourteen
build items, ten security groups, ten compiled cases and both actual synthetic policies.
The installed runtime interface, dependencies, lock and package inclusion are unchanged.
CI retains its full WebKit, publication, runtime, validation and distribution gates and
adds the full synthetic matrix. Software checks do not promote native acceptance.

Two final full runs used distinct UUIDs, identical content/policy digests and identical
classifications; all 230 expanded results per run passed, with owned process groups drained.
Run1 `f22ff5ac-6f8b-41d9-910b-7cba9ce4d154` took 10.281960 seconds. Run2 `56ac2325-2a02-4b12-8f45-7f5ed9cf327c` took 10.137269 seconds.
Both runs execute 100 real signed-token runtime invocations per profile, with distinct
request/run/token references and one approved fixture definition mapping. Durable ownership
checks reject foreign subject substitution and actor remapping. These are synthetic identities,
not native entity-count or billing measurements.

Content digest: `078468868fc6b14dc1889d6620d898c43d27c2db6b9258660b80d5986989b667`.
Baseline policy: `fe346ca7aef52211671fb80db4119b7f33557ccc3a70a93a5a7744030b907537`.
Restricted policy: `eeda23a74b727193045e4f727899e5f174042f05b037b6f2e338795645cc73a8`.
ALT-1 authorization changes between actual Policy objects; POC-1 remains permitted.

| Case | Baseline results | Restricted results | Software |
| --- | ---: | ---: | --- |
| signed-authority | 26 | 26 | pass |
| four-source-escalation | 12 | 12 | pass |
| permission-intersection | 10 | 10 | pass |
| approval-effects | 21 | 21 | pass |
| independent-revocation | 16 | 16 | pass |
| partial-incident | 5 | 5 | pass |
| confidentiality | 6 | 6 | pass |
| policy-delta | 2 | 2 | pass |
| stable-identity | 5 | 5 | pass |
| svid-containment | 12 | 12 | pass |

Recorded dependency versions: cryptography 50.0.2, fastapi 0.143.0, httpx 0.28.1, logfire 5.1.1, opentelemetry-api 1.44.0, opentelemetry-sdk 1.44.0, psycopg 3.3.6, pydantic 2.14.0, pydantic-ai-slim 2.55.0, pydantic-settings 2.15.0, pyjwt 2.15.1, pytest 9.1.1, pytest-asyncio 1.4.0, python 3.12.14, uvicorn 0.54.0.

## Boundary and compatibility review

All 26 new maintained modules and their functions have explanatory docstrings. Review covered
identity, broker, policy, approval, runtime, durable response/worker/proof, telemetry,
publication, contributor child lifecycle, snapshots, immutable storage and normalized reports.

The signed actor-purpose regression first failed: the broker accepted an explicit
`grant_type=authorization_code` actor claim. A minimal original-contract correction rejects
explicit non-client-credentials grants before exchange. Issuers omitting this optional claim
remain supported. Signed mutation controls and existing broker regressions then passed.
A second regression reproduced static-proof failures under Python hash seed3: unordered
required-control sets changed digest on JSON roundtrip. JSON serializers now sort required
controls, allowed scopes and reviewed entitlements, preserving authority while stabilizing
fingerprints. The failing roundtrip and affected provider checks pass under that seed.
Older multi-value set fingerprints may require fresh provider readiness/review; local state
and previous evidence are preserved. No broad runtime redesign or provider administration
was introduced.

The expired-session WebKit regression also exposed a test synchronization race: page reload
completed before asynchronous cookie/CSRF bootstrap, while synthetic operator cleanup acquired
its recovery lock. The test now waits for the recovery control to be enabled before starting
that effect, preserving the production bootstrap guard and all original effect assertions.

Isolation precedes collection: maintained snapshot/source import checks, no dotenv/private
state copying, minimal environment, disabled plugin autoload, external socket/DNS/HTTPX/native
DB guards and restricted local Git subprocesses. Caught denied attempts still fail isolation.
The owned watchdog independently kills a test group after owner death or deadline. TERM/KILL
and reap/drain precede success and temporary cleanup; uncertain drain retains scratch instead
of deleting potentially active state. These are accidental-effect protections for trusted
Python, not an OS sandbox against malicious same-user code.

Inventory and phase accounting rejects deselection, empty collection, missing parameters,
skip/xfail/xpass, failed setup/teardown, missing terminal metadata and duplicate/foreign items.
Raw streams are concurrently discarded. Frames, artifacts, counts and aggregate storage are
bounded; overflow before collection dispatch prevents test calls. Local hashes and private
ownership detect accidental drift/corruption, not authenticated provider origin. Seals and
derived reports are bound by immutable integrity records. Inspection is read-only, active
runs are busy, abandoned runs incomplete, and earlier failed runs remain immutable.

Privacy regressions cover private-source reduction, model content and telemetry, safe errors,
runner raw streams and renamed/damaged private regression records. Publication adds content
signatures without expanding the allowlist. Full CI retains excluded WebKit, separate-process
SVID and nested publication-scanner tests; the catalog documents their safe matrix substitutes.

## Validation ledger

- Focused regression checks, child owner-loss/deadline/native isolation, immutable storage,
  strict JSON/models and all ten independent group aggregations pass.
- 10,000 normalized-result reporting passes the five-second assertion; metadata, per-artifact,
  100-artifact and 100-MiB quotas reject overflow without partial publication.
- Both full two-profile runs pass (230 results each); list, group/case partial execution and
  immutable report inspection pass. Partial reports leave nine omitted groups incomplete.
- All-feature gates 001–009 and runtime configuration pass; Ruff lint and formatting pass.
- Offline validation passes all nine scenarios; demo completes delegated synthetic read.
- Existing repeatability/report-budget/readiness/closeout targeted checks: 29 passed in 5.51s.
- Wheel and sdist build and distribution privacy pass; contributor scripts remain excluded.
- Full WebKit suite under the previously failing hash seed3: 1,002 passed in 134.91s.
- Final staged-tree/history privacy passed against the complete implementation publication tree.

## Native dispositions and acceptance

Every F12-T1 through F12-T10 native row remains **blocked** with a provider owner, missing
prerequisite, concrete action and expected recheck. The exact native instructions are in the
[native contract table](contracts/runtime.md#native-function-12-dispositions) and the compiled
listing/report. Identity/approval owners need reviewed signed/phone evidence; Vault owners
need native policy and entity checks; database owners need independent reuse/session proofs;
integration owners need actual VIP and notification observations; security owners need exports,
permission-change receipts and licensed SVID/scope/recovery evidence. Demo-tier native audit
is explicitly unavailable. Existing 003/007/008 workflows require separate native authorization.
All fifteen [customer criteria](acceptance.json) retain blocked status. Function 13 owns
witnessed end-to-end acceptance and billing experiments. No live effect, credential acquisition,
phone prompt, native import/review, push or merge was performed for this implementation.

## Artifact closeout

All 22 FR/SC requirements trace to tasks and tests; all sixteen constraints retain task quotes.
SC-004 wording now matches the approved 10,000 expanded-result model. Requirements16/16 and
security19/19 checklists remain read-only and unchanged. All forty task markers are complete. Before/after implementation extension hooks were
checked; `.specify/extensions.yml` is absent. No hook dispatch was required. See [tasks](tasks.md) and [contributor guide](../../CONTRIBUTING.md#security-regression-checks).

Final software disposition: **complete**. Native acceptance remains **blocked**.
