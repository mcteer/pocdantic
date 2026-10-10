# Validation walkthrough: Live readiness and evidence closure

Commands are implemented. Complete software checks first; real service checks may remain
blocked. Keep all private input and evidence beneath ignored .local/. See validation.md for
current software results and outstanding live prerequisites.

## 1. Install and check locally

```sh
uv sync --locked --extra logfire --extra postgres --group dev
uv run agent validate ready --suite live-database
uv run agent validate ready --suite live-phone --scenario phone-approved
uv run agent validate ready --suite live-phone --scenario phone-denied
```

Use the existing short settings in ignored .env.local. Supply a fresh externally acquired
human access token, the agent OAuth client/audience, exact Vault/database targets and TLS trust,
a separate Verify API client/user/device mapping for phone, and the Logfire write token/project
alias. Readiness must list missing field groups without revealing values or contacting services.
Resolve local execution/evidence blockers; a ready report does not verify identity or reachability.
Finish configuring all integrations before capture so all four cases share the same context.

## 2. Run the database cases

```sh
uv run agent validate run --suite live-database --mode live
```

Retain the returned validation UUID privately. Expect delegated read plus exact cleanup, then
actor-only denial with zero usable credentials/reads. Unexpected credential issuance is a failure
with exact cleanup, not a passing negative test. Do not retry uncertain effects automatically.
Missing/expired human identity or unavailable service prerequisites leave this live step open.

## 3. Run each phone decision with a witness

The operator explicitly selects the next case and is present to respond before each invocation.
Run these separately; do not launch both unattended or supply an automatic decision.

```sh
uv run agent validate run --suite live-phone --scenario phone-approved --mode live --interactive
uv run agent validate run --suite live-phone --scenario phone-denied --mode live --interactive
```

Approve the first exact simulated action and deny the second. Keep the two validation UUIDs.
A timeout, cancellation, expired request or generic failure is not a witnessed denial. A real
infrastructure write is never required. If no witness/token is available, leave the step open.

## 4. Import private native evidence

Use authorized source tools to export bounded JSON privately. Templates and bounds are defined
in [runtime contracts](contracts/runtime.md), not inferred from arbitrary fields. Vault needs
matched request/response entries for acquisition, exact cleanup and actor denial. Protected
lease IDs without compatible linkage stay blocked; never disable audit protection for the demo.

Export expected Logfire trace/span rows, including parent spans and trusted validation/run
attributes, separately for each selected run. Use the configured project name, and an explicit
private native project-ID binding if rows include an ID. Manual query tools may need their own
read token; do not repurpose the runtime write token or add a read credential to runtime settings.
Document time window/pagination and completeness truthfully. Receipt may arrive after execution.

```sh
uv run agent validate import --run DATABASE_RUN_UUID --source vault --input .local/input/vault.jsonl --manifest .local/input/vault-manifest.json
uv run agent validate import --run DATABASE_RUN_UUID --source logfire --input .local/input/database-spans.json --manifest .local/input/logfire-manifest.json
uv run agent validate import --run APPROVED_RUN_UUID --source logfire --input .local/input/approved-spans.json --manifest .local/input/logfire-manifest.json
uv run agent validate import --run DENIED_RUN_UUID --source logfire --input .local/input/denied-spans.json --manifest .local/input/logfire-manifest.json
uv run agent validate report --run DATABASE_RUN_UUID
```

Use a manifest window covering each corresponding export; split manifests when windows differ.
Verify Events may also be imported for manual inspection, but unsupported transaction/OAuth
linkage remains blocked. Captured phone transaction responses are separate evidence.

## 5. Review and close out

Use existing per-run `validate review` only after examining genuine evidence. Private review
files contain the current evidence revision, observation time, reviewer, rationale and exact
references; no unattended signoff. Unsupported criteria cannot be waived by choosing alternative.

```sh
uv run agent validate review --run DATABASE_RUN_UUID --criterion UC1-05 --decision pass --review-file .local/input/review.json
uv run agent validate closeout --run DATABASE_RUN_UUID --run APPROVED_RUN_UUID --run DENIED_RUN_UUID
uv run agent validate closeout --closeout SNAPSHOT_UUID
```

A closeout shows four cases, separate operational/evidence outcomes and 15 customer rows with
per-run review dispositions. It cannot invent a combined acceptance decision. Missing proof
returns blocked; contradictions fail. Changing any referenced evidence/review makes snapshot
inspection stale; explicitly build another snapshot after resolving/reviewing the change.

## 6. Record results and software checks

During implementation, create validation.md with sanitized results and link original 002 T036
and T037 to actual proof or blockers. Do not mark live tasks complete from fixtures and do not
promote acceptance.json automatically. Record software completion separately from live closure.

Run the CONTRIBUTING gates: privacy/history, all-feature specifications, runtime configuration,
Ruff check/format, pytest, offline demo/validation, build and distribution checks. New tests must
cover all C01–C12 boundaries, short/legacy settings, wrong-run transaction replay, denial versus
expiry, documented source envelopes, mixed contexts, stale snapshots, interruption, publication
privacy and both local time budgets. Run only deterministic tests in CI.

Before later delivery, verify required validate/review checks, dismissed stale reviews and
protected default-branch force-push/deletion settings. Their absence blocks merge; planning
and software tests do not establish them. Implementation starts only after the requested model change.
