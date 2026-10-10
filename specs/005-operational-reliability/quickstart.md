# Validation guide: Operational reliability

This is the implementation validation runbook. Recovery commands and new tests are
planned; they are not claimed to exist or pass during planning. Use synthetic fixtures
for failure injection. Never deliberately trigger a provider ban or try revoked/invalid
passwords against the live database to prove this feature.

## Prepare

```sh
uv sync --locked --extra server --extra logfire --extra postgres --group dev --group browser
uv run --group browser playwright install webkit
```

Tests create isolated private roots and controlled providers; they must not read local
customer settings or use network credentials. No provider extras are needed for the
synthetic runtime. Read [contracts/runtime.md](contracts/runtime.md) for the exact limits
and [data-model.md](data-model.md) for state transitions.

## Deterministic verification after implementation

```sh
uv run pytest -q tests/test_recovery_models.py tests/test_recovery_store.py tests/test_recovery_lifecycle.py
uv run pytest -q tests/test_recovery_proof.py tests/test_recovery_cli.py tests/test_workspace_diagnostics.py
uv run --group browser pytest -q tests/browser/test_workspace_recovery.py
uv run python scripts/check_gates.py --all-features
uv run python scripts/check_gates.py --runtime-only
uv run ruff check .
uv run ruff format --check .
uv run --group browser pytest -q
uv run agent validate run
uv run agent demo
uv build
uv run python scripts/check_distribution.py
```

Review the prospective staged tree, then run `python3 scripts/check_privacy.py --history`.
Do not run broad tests repeatedly after they pass unless further changes justify it.

| Scenario | Expected proof |
|---|---|
| Configuration/reachability/timeout/authorization/expiry/uncertainty | Correct distinct explanation/action; no unsupported ban assertion. |
| Bounded repeated diagnostics | Report by 30 seconds; one active request; zero acquisition, SQL, or provider mutation. |
| Issuance crash boundaries | Subprocess terminated before send, after send, before handle persistence, and after persistence; every unfinished attempt blocks restart. |
| Cleanup crash boundaries | Before sync request, after submission, after response before receipt, and after durable receipt; only durable confirmed cleanup resolves. |
| Native proof | Correct exact lease/denial accepted; generic error, conflicting IDs, wrong environment/path, stale revision, missing/HMAC IDs, queued cleanup rejected. |
| Shared entrypoints | Workspace, CLI run/batch, and bearer /runs cannot acquire around a blocked journal. |
| Valid session recovery | Operator CLI resolves idle workspace incident; fresh explicit submission runs without additional login; old job unchanged. |
| Expiry and sign-out race | Recovery may finish but zero unauthenticated effects and no session restoration occur. |
| Damaged/missing/full storage and competing processes | Fail closed; no unresolved eviction; cleanup of any in-memory handle still attempted. |
| Seeded secrets and source artifacts | No forbidden value in state, browser, CLI, errors, logs, traces, index, wheel, or sdist. |

Test the type-aware delegation comparator with true, false, 1, string true, omitted sync,
widened values, and the wrong lease. Test keyboard status controls and delayed initial
session bootstrap. Record counts and meaningful failure-injection results in validation.md.

## Guided local operation after implementation

For a genuinely new enrollment with complete trusted database settings:

```sh
uv run agent recover init
uv run agent recover status
uv run agent workspace
```

Initialization begins prospective tracking. It is never a remedy for a known incident,
damaged state, or historical 004 uncertainty. It does not sign in or contact providers.
In the workspace, use Check connection to see facts and repair instructions. After an
operator repairs a provider, Check recovery rereads the journal; healthy transport alone
leaves unresolved credentials blocked. The existing sign-in stays valid until its normal
expiry, idle limit, or explicit sign-out.

`agent recover status` gives a public incident UUID and the next action. For a known
handle, an authorized operator supplies existing VAULT_TOKEN privately and invokes
`agent recover revoke --incident UUID` with that reported UUID. No token or lease is typed
into the browser. For unknown issuance, obtain the matching native Vault request/response
records from the actual environment's audit export facility. If that facility or exact
correlation is unavailable, record recovery_evidence_required; do not invent a dashboard
menu or ask the user to repeatedly sign in.

Place actual source artifacts in an owner-only folder below ignored `.local/` and use
`agent recover import --incident UUID --source PATH --reviewer LABEL`, substituting the
reported UUID, actual private source path, and reviewing operator's label. This reviews
native provenance and exact linkage; a generic operator acknowledgement cannot clear
state. A lease-identification import still requires the exact revoke command. Importing
already-completed native sync cleanup or explicit pre-execution denial can resolve it.

The example deployment's RAR schema and Vault policy must permit boolean sync=true before
live cleanup. Instructions belong in docs/usage.md; application/CI must not apply them.
No wildcard/force revoke, DB invalid-password test, or automatic task replay is permitted.

## Optional live disposition

Use only separately authorized resources. Run a normal read with confirmed sync cleanup;
verify a valid-session recovery if a real safely resolvable incident exists. Do not create
an unknown live lease just to make a test case. Use already available native artifacts
for strict correlation when possible. Otherwise record the live case blocked and the
specific missing capability/evidence. User phone interaction is needed only if normal
authentication has expired, never merely because a diagnostic check ran.

For every live case record passed/failed/blocked, source location kept private, timestamp,
reviewer status, and remaining limitation. Keep the two 004 unknown attempts and 003
native audit/denial gaps unchanged. The acceptance manifest remains blocked until its
own required evidence and review actually support a change.
