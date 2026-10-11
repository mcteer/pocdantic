# Validation guide: Shadow Agent Governance

These commands describe the implemented workflow. Synthetic validation is the default.
Native steps need named isolated resources and explicit live authorization; ordinary tests
perform none. See [runtime contracts](contracts/runtime.md) for private inputs and exits.

## Deterministic software checks

```sh
uv sync --locked --extra server --extra logfire --extra postgres --group dev --group browser
uv run --group browser playwright install webkit
uv run ruff check .
uv run ruff format --check .
uv run python scripts/check_gates.py --all-features
uv run python scripts/check_gates.py --runtime-only
uv run --group browser pytest -q
uv run agent validate run
uv run pytest -q tests/test_validation_runner.py::test_ten_repeatable_runs_under_budget tests/test_validation_report.py::test_ten_thousand_normalized_event_report_budget
uv run pytest -q tests/test_validation_readiness.py tests/test_validation_closeout.py
uv run agent demo
uv build
uv run python scripts/check_distribution.py
python3 scripts/check_privacy.py --history
```

Tests deny network and poison ambient provider settings. Temporary fixture roots replace
real private state; tests never load `.env.local` or call actual providers.

| Story | Independent scenario and required result |
| --- | --- |
| US1 | Seed a reviewed synthetic source, prepare a case, submit duplicate/changed/forged findings; first evidence persists once, no authority granted |
| US2 | Seed an observed candidate and exact metadata; preview/apply/read back, lose response, restart, change policy and introduce hold; no repeat or broadened create |
| US3 | Seed confirmed registration and fixture signer; separately started relying service accepts valid identity and rejects every negative class, stale cache and nonce replay |
| US4 | Seed native/synthetic/missing records; each F11 result stands alone, audit remains blocked, owner isolation and sign-out clearing pass in WebKit |

Interrupt each persistence boundary, retain child ownership after parent death, change
metadata after review, saturate journal capacity before/after effect submission, and rotate
keys. At 1,000 candidates/10,000 observations the status report must finish within five
seconds excluding I/O. Unresolved work remains pinned; no test produces a vendor pass.

## Native prerequisites and exact operator actions

| Prerequisite | Operator action | Recheck |
| --- | --- | --- |
| Real discovery source | VIP operator exports the tenant's actual collector/event schema and a minimal private fixture, documents agent classification and notification, then configures the reviewed relay's separate audience/scope and exact source-object mapping | Configure source; confirm authenticated native intake and independent collector receipt |
| Isolated actor | Verify administrator creates a dedicated candidate client with JWT access tokens, exact Vault audience and constrained `vault:path_access` RAR type/property filters; supply client credentials only in the private secret file | Readiness plus signed direct-token validation during observe; absent RAR stays blocked |
| Vault entity/alias | Vault administrator prepares one candidate entity and its exact issuer/external-ID alias and OAuth profile, without creating an Agent Registry record | Readiness confirms exact binding and absence by entity and reserved name |
| Limited policy fixtures | Vault administrator creates dedicated synthetic KV-v2 read fixtures, narrow direct candidate ACL, human baseline and ceiling; human baseline/RAR permit the excessive OBO path while ceiling denies it | Read policy digests and execute separate allowed/denied proof paths |
| Native SPIFFE | Vault administrator verifies licensed support, enables/configures the selected mount and role, fixes trust domain/subject template and TTL at no more than 300 seconds, and grants exact candidate mint permission | Readiness pins config/role/trust; identity proof checks signed entity and independent verification |
| Healthy control | Integration operator provides a distinct registered control actor and applicable human OBO token privately; give control only the reviewed harmless reads | Healthy proof succeeds during each negative provider test |
| Exclusive test administration | Provider owner reserves the exact candidate entity/name and records that no other administrator will change it during the controlled case | Fresh readbacks match before every effect; drift blocks |
| Native audit | Record the existing demo-tier limitation; use a separately supported environment only if native audit acceptance is later pursued | F11-T5 remains blocked without actual native audit evidence |

## Run the authorized controlled case

1. Stop the existing browser workspace before privileged governance commands; they require
   its recovery workspace ownership. Keep response intake available so a new hold can still
   block governance. Preserve all response/recovery files and resolve existing holds normally.
2. Run `uv run agent govern prepare`. Edit only the generated private configuration/secret
   files. Run `uv run agent govern configure --revision N --operator LABEL` using status's
   current revision. This activates local source configuration, not provider privileges.
3. Run `uv run agent govern case prepare --source ALIAS`. Fill its generated private
   candidate draft with the exact actor/entity/owner/policy/trust bindings. Run
   `uv run agent govern readiness --candidate UUID`; follow each specific missing step.
4. Start `uv run agent govern serve`. Configure the authorized relay to POST to
   `http://127.0.0.1:8002/governance/native/ALIAS` through the local approved transport;
   public exposure and hosting are outside scope. Use the separate enrolled relay credential.
5. Run `uv run agent govern observe --candidate UUID --revision N`. It records absence,
   bounded safe activity and its actual provider decision. Confirm the real collector's
   discovery and notification reach intake for this case. If late, inspect status and
   import correlated evidence; do not register first and backdate discovery afterward.
6. Import/review the actual source evidence using `govern import` with a private bounded
   file, current candidate/revision and operator label. Run `govern review` and inspect
   the private exact registration preview. Apply the returned review with
   `uv run agent govern enroll --review UUID --revision N`. Expect confirmed readback;
   uncertainty requires `reconcile` and explicit evidence-backed `resolve`, never a rerun
   that issues another registration automatically.
7. Start `uv run agent govern relying serve` in a separate process. Run
   `uv run agent govern prove --candidate UUID --revision N --scenario identity`.
   Expect native mint plus independent verification; no bearer token appears in output.
8. Run the `permissions` and `negatives` scenarios with current revision and the required
   private inputs. Keep the five provider paths and synthetic token-negative results
   separate. Actual unauthenticated mint denial needs a healthy issuer control.
9. If supported, the VIP operator triages/manages the exact finding through the tenant's
   existing console, then imports its correlated native record. The application never
   invents an unsupported VIP administration endpoint or replaces first-observed evidence.
10. Run `uv run agent govern closeout --candidate UUID`. Inspect every F11 result and
    source/reviewer/time. Restart the workspace to view the safe owner-scoped summary.
    Local `close` archives only after all effects drain and credentials resolve/expire;
    provider resource deletion remains an explicitly separate operator action.

## Required native dispositions

F11-T1 needs real pre-registration discovery and notification; F11-T2 needs actual
registration-dependent denial; F11-T3 needs native SVID and independent verification;
F11-T4 needs OBO ceiling attribution; F11-T5 needs correlated native audit; F11-T6 needs
actual unauthenticated mint denial and verifier negatives; F11-T7 needs both OBO and
ordinary ACL proof. Every unavailable prerequisite is recorded with its owner/action/recheck.
No task may relabel synthetic evidence as a native pass to finish the checklist.
