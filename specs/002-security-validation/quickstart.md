# Quickstart validation guide

Owner: maintainer. These are the planned 002 interfaces, to run after implementation.
Do not execute them as part of the planning handoff. All live work uses authorized PoC resources.

## 1. Offline software proof

```sh
uv sync --locked --group dev
uv run agent validate list
uv run agent validate run
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run python scripts/check_gates.py --all-features
uv run python scripts/check_gates.py --runtime-only
```

Expected: the nine offline scenario assertions pass, no network or live credential is used,
JSON is printed and private JSON/Markdown reports are created under .local/validation/. An output override outside the project .local/ root, or not ignored
by Git when in a worktree, must be rejected before any write.
Customer criteria remain blocked unless separately backed by reviewed live evidence. Injected
cleanup failure is reported as an expected negative assertion with a failed underlying operation,
never as successful database execution. Ten-run CI coverage verifies <=30 seconds per offline run.

Use two synthetic provider/profile configurations in tests to prove the same catalog is reusable.
Both configurations must be accepted without changing scenario source. Tests poison ambient
provider/Logfire/OTel environment variables and deny network access to prove offline isolation.

## 2. Confidentiality and lineage proof

```sh
uv sync --locked --extra logfire --group dev
uv run pytest -q tests/test_telemetry.py tests/test_observability.py
```

Expected: captured parent/child and trusted lifecycle spans correlate. Seeded secrets in prompts,
results, upstream exceptions, tool schemas, span names, resource metadata and baggage appear in
neither export nor console/report output. This demonstrates the local export boundary; it does
not prove receipt by a remote project.

## 3. Explicit live database validation

Install only the required configured model-provider extra alongside logfire and postgres.
Keep identity, Vault, database settings and LOGFIRE_TOKEN in .env.local. The token has been supplied
for the current workspace; do not copy it into this document or any command argument. Obtain a
fresh signed user access token through an existing approved host and supply BEARER_TOKEN
privately. The published harness does not depend on the ignored chat or its control socket.

```sh
uv sync --locked --extra google --extra logfire --extra postgres --group dev
uv run agent validate run --suite live-database --mode live
```

Expected operational proof: genuine verified user/actor exchange, fixed SELECT, exact delegated
lease revocation and actor-only denial. Exports contain sanitized lifecycle spans. Record the
opaque validation UUID from output. A successful export/flush is not remote receipt; the final
source-correlation report remains blocked until matching private exports are imported.
If any prerequisite is unavailable, preserve the explicit blocked result and owner/reason.
Never replace a denied exchange with an administrative token.

## 4. Source export import and report assembly

Use the provider's authorized export process outside the harness. Prepare plain native exports
and a private manifest for each source according to [contracts/runtime.md](contracts/runtime.md).
HCP archives must be decompressed by the operator into a bounded private file; the importer does
not extract archives. Verify exports need declared window/completeness information. Unsupported
OAuth/actor linkage remains blocked even if other correlation succeeds.

For each source use the corresponding form, replacing the synthetic UUID with the actual run ID:

```sh
uv run agent validate import --run 00000000-0000-4000-8000-000000000002 --source vault --input .local/validation-input/vault.jsonl --manifest .local/validation-input/vault-manifest.json
uv run agent validate import --run 00000000-0000-4000-8000-000000000002 --source verify --input .local/validation-input/verify.json --manifest .local/validation-input/verify-manifest.json
uv run agent validate import --run 00000000-0000-4000-8000-000000000002 --source logfire --input .local/validation-input/logfire.json --manifest .local/validation-input/logfire-manifest.json
uv run agent validate report --run 00000000-0000-4000-8000-000000000002
```

Expected: exact matches are linked; missing/unsupported/ambiguous/incomplete evidence remains
blocked, contradicting or tampered evidence fails. Report includes every scenario and all fifteen
criteria. A local harness ID written into a manifest cannot substitute for a native exact match.
In tests, change one binding/digest and assert the relevant report check ceases to pass.

## 5. Optional witnessed phone scenarios

```sh
uv run agent validate run --suite live-phone --scenario phone-approved --mode live --interactive
uv run agent validate run --suite live-phone --scenario phone-denied --mode live --interactive
```

The authorized operator approves the first real phone request and denies the second. Expected:
one simulated restart after approval, zero simulated writes after denial. Preserve genuine
transaction evidence and clearly label any unavailable Events audit linkage. An unattended run
without --interactive, with no explicit --scenario, or with multiple phone scenarios must not
send either push. These are explicit separate live tasks, not CI.

## 6. Review and publication boundaries

Inspect the private source records and their provenance. Prepare a private review file containing
the reviewer, rationale, current evidence revision, observed time and opaque references. Then:

```sh
uv run agent validate review --run 00000000-0000-4000-8000-000000000002 --criterion UC1-02 --decision pass --review-file .local/validation-input/review.json
uv run agent validate report --run 00000000-0000-4000-8000-000000000002
uv build
uv run python scripts/check_distribution.py
python3 scripts/check_privacy.py --history
```

Expected: only a valid, evidence-bound explicit review can promote the selected criterion.
Changed evidence invalidates the previous decision. Keep all generated reports/imports/reviews
private; deliberately select a sanitized summary only after review. No command stages or uploads
files. Customer design sources, local chat and raw evidence remain absent from Git and packages.
