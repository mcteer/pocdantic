# Implementation Plan: Portable PoC Setup

**Branch**: `011-portable-poc-setup` | **Date**: 2026-10-11 | **Spec**: [spec.md](spec.md)

## Summary

Deliver a short colleague setup flow, accurate capability report, standard Vault JWT-login
route and compatible generic sign-in. Preserve the advanced delegated flow explicitly.
One trusted database target removes tenant/mount coupling throughout runtime and evidence.
Software completion and real two-provider/colleague acceptance remain separate.

## Technical Context

**Language/Version**: Python 3.12+, existing JavaScript workspace.
**Primary Dependencies**: Existing Pydantic, httpx, PyJWT, FastAPI, psycopg; no new dependency.
**Storage**: Private local configuration and versioned durable recovery journals; no new hosted store.
**Testing**: pytest, deterministic provider fixtures, Playwright/WebKit, existing security regression.
**Target Platform**: Existing macOS/Linux local CLI and browser prerequisites.
**Project Type**: Python CLI/local browser workspace.
**Performance Goals**: Default local checks finish within 2 seconds; explicit network checks
use per-call deadlines at most 10 seconds and an overall deadline at most 30 seconds.
**Constraints**: No ambient provider calls in tests; no default credential issuance; exact
cleanup and existing recovery block survive mode changes. HTTPS trust remains mandatory.
**Scale/Scope**: One employee/deployment per local workspace; two real identity products and
Vault instances for live portability; existing fixed database query only.

## Constitution Check

Pre-research and post-design: pass by design, no exceptions requested.
I: reusable adapters/configuration, no new dependencies. II: verified human authorization,
explicit route selection, negative tests, no weaker fallback. III: private secrets and evidence,
sanitized publication. IV: separate live portability/colleague evidence; original fifteen rows
stay blocked unless independently proven. V: bounded checks, durable native-token and lease
ownership, cancellation and exact cleanup. VI: locked build, meaningful regression, migration,
owner review of new security boundaries before merge. Existing branch-protection shortcomings
are not repaired or waived by this feature.

## Project Structure

Documentation: spec.md, research.md, data-model.md, quickstart.md, contracts/runtime.md,
checklists/requirements.md, checklists/security.md, tasks.md, acceptance.json, validation.md.

Source changes: src/agent/setup/{models,commands,readiness}.py (new); settings.py, cli.py,
probe.py, oauth.py, broker.py, vault.py; workspace/{auth,runs}.py and workspace capability display;
recovery/{models,store,lifecycle,commands,proof,workers}.py; shared provider HTTP construction and
workspace/diagnostics.py workers; validation/{readiness,context,importers,models,catalog,runner,commands}.py
and config/validation-suites.json.
Tests: tests/test_setup_*.py, tests/test_portable_vault.py, tests/test_portable_oidc.py,
tests/browser/test_workspace_portability.py. Documentation: docs/setup.md (new),
docs/configuration.md, docs/usage.md, README.md, .env.example.

**Structure Decision**: extend existing trusted boundaries; no plugin discovery, arbitrary
provider scripts, hosted wizard, or second authorization framework.

## Phases and compatibility

1. Capture route/trust/target contracts and versioned recovery design; add adversarial fixtures.
2. Implement non-overwriting setup and bounded readiness projections shared with workspace.
3. Integrate standard JWT login into the existing broker without weakening verification,
   deterministic policy, ownership, SQL limits, or cleanup. Keep delegated default.
4. Wire custom targets and provider trust through all affected evidence/recovery boundaries.
5. Document both modes and optional features; run regression/gates; record software evidence.
6. Run separate authorized two-product live validation and colleague timing/repeat test when
   deployment access exists. Document exact missing prerequisites otherwise; do not mark tasks done.

Existing aliases and delegated behavior remain compatible. Existing snapshots retain original
path/mode/context; a safe idempotent journal migration preserves unresolved state and may
require reviewed reconstruction if legacy ownership is insufficient. Switching deployment or
mode never bypasses an unresolved recovery block. Setup must refuse conflicting mode inputs.

## Threat and boundary analysis

No unverified token may reach Vault login. Cross-host discovery requires explicit trust;
redirects, token-purpose confusion, forged subject, missing scopes and issuer/audience mismatch
fail closed. A user-jwt success cannot satisfy delegated actor/RAR criteria. Native token login
is a credential effect with write-ahead ownership before network dispatch. Handle a lost login
response as uncertain, block execution and preserve repair history. Clean exact database lease
before exact native-token self-revocation, and verify both dispositions before success. Cancellation
must shield/drain cleanup; no acquisition retries to diagnose uncertainty. Old evidence must
retain original route/deployment digest. Administrator permissions are never worker authority.

## Implementation prerequisites resolved in planning review

Use renewable-compatible hard-capped service tokens as specified in the contract; no renewal
permission or call. Separate role-scoped provider cleanup from exact adapter ownership and
always attempt token cleanup if lease cleanup fails. Journal v3 and command/proof readers must
support human owner plus linked acquisitions, including restart and immutable provider context.
Carry provider-specific CA trust into every trusted client and isolated diagnostic worker.
Baseline verification does not require agent/service OAuth credentials. Add the explicit
live-portability suite and private route-aware validation records before attempting native proof.
A missing denied test identity is an exact live prerequisite, not a reason to weaken scope checks.
These choices preserve the six constitution principles; no exception is needed.
