# Security and Design Review: Model Gateway and Credential Guardrails

**Date**: 2026-10-18. Planning-agent review of requirements and contracts; no live or
maintainer acceptance is asserted. These checks assess design completeness, not test execution.

- [x] Gateway processing is distinguished from onward frontier-model delivery.
- [x] Existing verified identity, deterministic tool authorization and narrower child rights remain mandatory.
- [x] Application credentials remain adapter-only; Gateway is additional defense, not permission to send secrets.
- [x] Short private configuration, precedence, key rotation and explicit legacy direct migration are specified.
- [x] Native protocol admission covers CLI, runtime, API, workspace and child/later turns.
- [x] Exact origin/path/auth/headers, ambient provider settings, TLS/proxies and redirects are addressed.
- [x] SDK/internal retries and remote failover have explicit local controls and live proof obligations.
- [x] Blocking coverage, synthetic positives, benign controls and unsupported/encoded-data limits are defined.
- [x] Model allowlists, soft spending caps, pricing gaps, BYOK accounting and unknown cost are distinguished.
- [x] Application content exclusion and remote retention/pre-block logging are reviewed independently.
- [x] Closed error classification never infers guardrail/budget cause from status alone or exposes bodies.
- [x] Attempt metadata is bounded, content-free, correlated and isolated across concurrent runs.
- [x] Cancellation, uncertain dispatch, post-tool refusal and exact cleanup prevent false success/replay.
- [x] Review expiry/digests/change invalidation and unreported remote drift limits are explicit.
- [x] Fixed synthetic probes resolve activation bootstrap without a normal-runtime bypass.
- [x] Root admission, private-file ownership, bounded parsing and safe atomic evidence/review writes are specified.
- [x] Setup reads preserve enrollment/configuration and distinguish inputs, reviews and verified support.
- [x] Dependencies, license/lockfile review, optional extras and artifact-install matrices are included.
- [x] Vendor acceptance remains blocked without live source evidence, reviewer/time and disposition.
- [x] Threat model, public documentation, privacy checks and compatibility/migration are covered.

Result: 20/20 design-review items pass. The user authorized planning through analysis and supplied
the migration decision. Software tasks and operational proof remain unexecuted. No constitutional
exception or remote administration authorization is inferred.
