# Implementation Plan: Live readiness and evidence closure

**Branch**: `feature/003-live-evidence-closure` | **Date**: 2026-10-09 | **Spec**: [spec.md](spec.md)
**Input**: `specs/003-live-evidence-closure/spec.md`

## Summary

Add local-only `agent validate ready` and immutable `agent validate closeout` commands around
002's existing runner, importers and per-run review system. Correct documented native Vault
and Logfire import shapes and tighten transaction ownership/intentional-denial checks. Preserve
all 15 customer criteria as per-run review projections; do not invent an aggregate acceptance
promotion or a new review authority. Actual live execution remains separately gated.

## Technical Context

**Language/Version**: Python 3.12+, existing agent package.
**Primary Dependencies**: Existing locked Pydantic AI Slim 2.55.0, Pydantic 2.14.0,
pydantic-settings, HTTPX, PyJWT/cryptography; existing optional Logfire and PostgreSQL extras.
No new dependencies, collector SDKs or environment variables planned.
**Storage**: Existing owner-only private store under `.local/validation/`; immutable context
sidecars in runs and separate `closeouts/<UUID>/` snapshot directories.
**Testing**: pytest/pytest-asyncio; HTTPX MockTransport and native-format synthetic fixtures;
network-denial/canary tests, Ruff, existing specification/privacy/distribution gates.
**Target Platform**: Existing macOS/Linux CLI and CI; installed base wheel outside checkout.
**Project Type**: Library and CLI; no new HTTP service or frontend.
**Performance Goals**: Readiness ≤2 seconds; four-run closeout ≤10 seconds excluding I/O in CI.
**Constraints**: No network/effects for ready/closeout; all per-run 002 limits remain; public
metadata only; no secret-bearing hashes published; frozen source evidence and explicit review.
**Scale/Scope**: Four case slots, 1–4 selected runs, 15 criterion rows; operator-driven local use.

## Constitution Check

Pre-research and post-design checks: planned software satisfies principles I–VI. The design
reuses slim dependencies and trusted adapters, adds boundary/privacy/replay tests, retains
bounded cleanup, treats source exports as untrusted provenance and leaves unsupported claims
blocked. No planned constitution exception.

Existing delivery noncompliance is recorded explicitly: main was unprotected at 002 delivery.
That is a pre-merge gate for 003, not a claim of compliance. Task T028 must verify required
validate/review checks, stale-review dismissal and force-push/deletion protection before any
merge. If unavailable, delivery remains blocked; no automatic settings mutation or bypass.
Planning and deterministic implementation may proceed. An owner reviews security-sensitive
changes and the threat analysis before delivery. Live provisioning is outside this feature.

## Project Structure

### Documentation (this feature)

```text
specs/003-live-evidence-closure/
  spec.md, plan.md, research.md, data-model.md, quickstart.md, tasks.md
  acceptance.json, checklists/requirements.md, contracts/runtime.md
  validation.md  # created during implementation, with software/live gate results
```

### Source Code (repository root)

```text
src/agent/validation/
  readiness.py    # new: local checks reused by live execution
  context.py      # new: sealed private context identity, no credential values
  closeout.py     # new: bounded snapshot assembly and revalidation
  models.py, commands.py, runner.py, scenarios.py
  importers.py, correlation.py, report.py, review.py, store.py
src/agent/observability.py, src/agent/verify.py  # preserve precise phone terminal evidence
src/agent/settings.py                         # existing short names; no new settings
scripts/publish_policy.py                      # reject new generated evidence names
tests/test_validation_readiness.py, tests/test_validation_context.py
tests/test_validation_closeout.py, tests/test_validation_importers.py
tests/test_validation_review.py, tests/test_validation_scenarios.py
tests/test_validation_cli.py, tests/test_validation_store.py, tests/test_publication.py
docs/usage.md, docs/configuration.md, docs/adr/0005-live-evidence-closure.md
```

**Structure Decision**: Extend existing modules at their current boundaries. No second runner,
report engine, provider abstraction or generalized workflow framework.

## Phase 0: Research decisions

See [research.md](research.md). Local code inspection and primary native-schema documentation
establish concrete parser fixes and gaps. Manual exports remain sufficient; unknown Verify
linkage and HMAC lease comparisons stay blocked. Readiness is entirely local and must not call
`probe()`, which obtains an administrative token and inventories. Existing run configuration
fingerprints contain suite/bounds, so use a separate sealed deployment-context digest.

## Phase 1: Design

1. **Readiness**: select the fixed suite/cases before loading settings; collect all applicable
   static configuration/package/profile checks through one evaluator. `run` reuses its execution
   subset immediately before adapters; evidence warnings do not gate business effects. Token
   signature/expiry and service entitlement remain for authenticated live execution. No JWT
   decoding is presented as verification. Invalid Pydantic errors are mapped without values.
2. **Context**: snapshot all non-secret deployment selectors used by the four cases (including
   both agent and administrative identities, source project, profile contents and TLS trust
   file content digest) privately at run creation. Exclude suite, bounds and all credential
   material. Seal the sidecar in execution integrity. Require unchanged current implementation,
   catalog/mapping revision and equal context digests for closeout. Missing old context blocks
   only combined closeout; old per-run reports remain supported.
3. **Native evidence**: support Vault `response.secret.lease_id` and reject contradictory legacy
   fields; support documented Logfire JSON row envelopes without guessing column order. All
   aliases for source identity must agree with their declared kind. Optional private native
   project-ID binding is an import-manifest field, not a new environment variable. Preserve
   missing explicit identity as operator-scoped provenance, never authenticated project proof.
4. **Transaction correctness**: validate validation/observation/run/source/action joins on every
   reconstruction; retain the raw decision distinction. Only intentional documented denial
   states satisfy phone-denied. Current per-run review eligibility must resolve the exact
   relevant phases/artifacts, not unrelated matched records. Supported customer criterion IDs
   remain UC1-01, UC1-05 and UC2-02; broader customer claims remain blocked.
5. **Closeout**: acquire selected run locks in sorted UUID order without waiting indefinitely;
   reconstruct their reports and exact input inventories, then evaluate a fixed four-case
   obligation matrix. Keep all 15 criterion rows with per-run dispositions and review IDs.
   Create no aggregate acceptance status. Compare input inventories immediately before atomic
   finalization, release locks, and persist only safe report content plus private references.
   Later inspection revalidates inputs and returns stale when any revision changed.
6. **Live walkthrough**: use separate run invocations, private exports and existing `review`.
   Link evidence to original 002 T036/T037 only after their proof is observed; gaps never
   authorize another live retry. A later intentional retry must receive a new run ID and be
   selected explicitly for a subsequent snapshot.

Detailed field constraints, exit precedence, obligation coverage and compatibility rules are
in [data-model.md](data-model.md) and [contracts/runtime.md](contracts/runtime.md).

## Threat and compatibility review

Untrusted exports, ambiguous source aliases, replayed transactions, transplanted sidecars,
concurrent file replacement, spoofed reviewer text and forged manual provenance are inputs to
validate, not authority. Digests detect changes; they do not authenticate a source or reviewer.
Local private-store access is a trusted operator boundary, not tamper-proof remote attestation.
No live tenant/project identifiers or endpoints enter tracked fixtures or reports.

Existing CLI/run/import/review semantics remain unless a false-positive evidence claim is
corrected. Imported v1 records remain readable; unsupported/new envelope formats use explicit
format versions. Old reviews become stale on implementation/mapping changes under existing
revision rules. Old snapshots are never rewritten. New contexts do not migrate old runs by
reading today's environment. No runtime dependency/lock change is expected.

## Implementation and delivery strategy

Deliver US1 readiness first, then native evidence/joins (US2), closeout (US3), then authorized
external walkthrough (US4). Tests precede boundary-changing code. Software can complete with
external tasks open. Documentation, privacy and package verification follow stable interfaces.
Planning stops here; tasks are separate and implementation is explicitly deferred to the next model.
