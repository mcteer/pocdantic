# Implementation validation ledger

Owner: maintainer. Software tasks T001–T035 and T038 complete; live and delivery gates remain open.

## Dependency and license baseline (T001)

The committed lockfile supplies all planned dependencies. No new dependency or lock change.
Installed baseline: pydantic-ai-slim 2.55.0 (MIT), Pydantic 2.14.0 (MIT),
pydantic-settings 2.15.0 (MIT), HTTPX 0.28.1 (BSD-3-Clause), PyJWT 2.15.1 (MIT),
cryptography 50.0.2 (Apache-2.0 OR BSD-3-Clause). Optional provider, Logfire and
PostgreSQL dependencies remain opt-in under existing reviewed extras.

## Threat boundaries

Catalog data selects only registered factories; it cannot provide executable expressions,
credentials or tenant settings. Public events and reports accept closed metadata schemas.
Native IDs, raw imports, configuration details and review text stay in owner-only ignored files.
All effects retain existing verified ingress, policy and approval checks. Import metadata is
operator provenance, never authenticated source proof. Timestamp proximity cannot prove linkage.
Digest-bound local reviews detect changes but do not authenticate a reviewer or source export.
Storage rejects symlinks, traversal, overwrites and concurrent writers before effects.
Cancellation and sink failures must preserve cleanup; uncertain operations are never retried.
Offline models and adapters are explicit; no live fallback or administrative token is permitted.

## Results

T001: dependency baseline and threat review recorded. No new dependencies.
T002: packaged fixed catalog contains nine offline, two database and two phone scenarios.
Checklist: requirements.md 16/16 checked; no checklist markers edited.

## External gates

T036 requires genuine database execution, remote receipt and supported Vault correlation.
T037 requires individually selected human-witnessed phone decisions.
T039 requires maintainer review and verified server-side branch protection before an authorized merge.
These gates cannot be replaced by deterministic fixtures or automatically promoted acceptance.


## Software validation (T038)

- Full regression suite: 178 passed in 12.85 seconds.
- Ruff lint and formatting: passed (93 Python files); Git whitespace check passed.
- Privacy gate including Git history: passed. The former Python package path remains
  allowlisted solely to keep immutable historical source eligible for inspection.
- Both feature artifact gates passed independently of the local feature pointer;
  each retained 15 blocked live criteria. Runtime configuration gate passed.
- Offline demo passed; validation suite passed all nine terminal cases with exit 0.
- Ten-run repeatability, two synthetic configurations, poisoned environment/network
  denial, cancellation/cleanup and 10,000-event report budget checks passed.
- Wheel and sdist built; distribution privacy gate passed. Installed base wheel ran
  all nine offline cases outside the repository with socket access denied and no
  Logfire, PostgreSQL driver or OpenTelemetry SDK installed.
- Python package moved from src/pocdantic to src/agent at the owner's request.
  Imports, packaged resources, entry point target, support scripts and source paths
  were updated. Distribution/CLI/environment and deployed identity names remain stable.
- No extension hook configuration exists; post-implementation hooks were skipped.

## Outstanding execution and delivery

The live database invocation returned exit 2 with both cases blocked on missing
prerequisites and zero effect attempts. Database configuration and a human bearer
were unavailable; a Logfire token was present but the expected project binding was
absent. No real receipt or source-system correlation was obtained. Verify OAuth
and actor audit linkage remain unsupported until a documented native mapping exists.

Phone scenarios were not invoked: a single witnessed case and authenticated human
identity are required. Deterministic approval fixtures do not establish live acceptance.

Repository checks confirm that main is not protected. The owner explicitly authorized
push, PR creation and merge after reviewing the implementation summary. Publication
contents passed the staged privacy/history gate. Delivery will wait for the PR validate
check; server-side review and branch-protection controls remain absent, so T039 remains
open even if the explicitly authorized merge succeeds.
Tracked acceptance snapshots were not promoted.
