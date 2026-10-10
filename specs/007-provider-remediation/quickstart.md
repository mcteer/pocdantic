# Validation guide: Provider detection and remediation

Commands below exercise the 007 implementation. Deterministic checks are the default;
live steps require explicit resource authorization and private configuration. See
[the runtime guide](../../docs/usage.md#provider-remediation) for private stdin and exit codes.

## Deterministic implementation validation

```sh
uv sync --locked --extra server --extra logfire --extra postgres --group dev --group browser
uv run --group browser playwright install webkit
uv run python scripts/check_gates.py --all-features
uv run python scripts/check_gates.py --runtime-only
uv run ruff check .
uv run ruff format --check .
uv run --group browser pytest -q
uv run agent demo
uv run agent validate run
uv build
uv run python scripts/check_distribution.py
python3 scripts/check_privacy.py --history
```

Use synthetic fixtures with network denied and poisoned ambient provider variables, as
in existing validation tests. Tests must not touch `.env.local`, actual `.local` state or
live providers. Rerun staged-tree/privacy gates after reviewing the prospective diff.

| Story | Fixture scenario and expected outcome |
| --- | --- |
| US1 | Valid source event commits one hold; duplicate/restart joins it; malicious target, stale token, schema mismatch and changed replay cause no effect |
| US2 | Root-only response leaves healthy peer usable; definition block tests same JWT/fresh issuance separately; user holds reject admission and close only matching sessions |
| US3 | Exact lease cleanup joins existing receipt; isolated static rotation/session targeting rejects shared roles and PID reuse; old/new/open-session proof remain separate |
| US4 | Partial result stays partial; Teams acceptance is not delivery; restart does not resend; unresolved/changed hold or unsafe old-token recovery prevents release |

Also interrupt migration at each persistence boundary, kill the parent while provider
children are active, lose an HTTP reply, fail persistence after a mutation, saturate
capacity, change enrollment during intake, and rename private fixtures into allowed
publication paths. Each must preserve holds, uncertainty and exact ownership.

## Preparing a deployment without mutating providers

1. Stop workspace and response service. Preserve existing private recovery/response state.
   Run `uv run agent respond status` and resolve active owners through ordinary cleanup;
   do not delete state. If recovery v1 is reported, follow its existing migration guide.
2. Run `uv run agent respond migrate`. Expect preserved holds/history and no provider calls.
3. Run `uv run agent respond providers prepare`. Edit the generated private draft only.
   The maintained synthetic example documents fields; do not copy live IDs into the repo.
4. Supply the exact inputs in the table below. Omit/disable optional capabilities that
   are not available; never invent mappings or label a synthetic fixture as native.
5. Run `uv run agent respond providers readiness`. Each requested action must be ready
   before activation; unsupported actions remain disabled with a clear native limitation.
6. Inspect `uv run agent respond providers status`, then run
   `uv run agent respond providers enroll --revision N` with its current revision.
   Enrollment is local authority activation, not a destructive provider test.
7. Start `uv run agent respond serve`; use the existing workspace command separately.

| Missing capability | Responsible role and concrete next action | Recheck |
| --- | --- | --- |
| Native VIP source | VIP operator: export the configured rule's event schema/version and one private sample; document the relay's vendor-authentication check, provision its separate response-audience identity, and supply collector receipt evidence for a safe test signal. Add exact object-to-root/definition mappings to the draft. No generic Verify SaaS event qualifies as VIP evidence. | `providers readiness`; native source remains disabled until mapping and evidence validate |
| Agent Registry control | Vault operator: verify installed Enterprise feature/version, read the exact actor registration/entity, and grant narrowly scoped read/delete authority for that ID. Do not delete it during readiness. | `providers readiness` reports exact registration mapping and capability |
| User response | Verify administrator: choose a dedicated tenant test user, confirm its issuer/subject mapping and supported federation behavior; grant session-list/revoke and user-update permissions to the configured service identity. Do not use global IBMid administration. | `providers readiness` reads the exact user/entitlements |
| Static credential | Vault/DB operator: create an isolated static-role test resource using the supported plugin, record its exact role/user and scheduled rotation configuration, and grant read-metadata/rotation plus separately authorized proof access. Never substitute database root rotation. | `providers readiness` checks metadata without reading the password |
| Session termination | DB operator: supply a private dedicated control DSN, isolated role ownership and direct-session visibility/termination authority; provide a separate healthy proof account. Pooled/shared role targets remain unsupported. | `providers readiness` checks privileges and ownership with fixed metadata queries |
| Teams | Workflow owner: in a standard test channel create a Workflows webhook posting an Adaptive Card, choose the documented URL-only trigger, ensure the posting connection works and assign a co-owner. Save its URL only in the generated private secret file. Supply a controlled workflow/message receipt when performing the authorized delivery check. | `providers readiness` validates local setup; actual delivery remains unproven until `providers probe`/import |
| Vault audit | Integration owner: record the existing Development-tier limitation. Do not generate another human token or search for a hidden audit menu. Audit-specific acceptance requires a separately provisioned supported environment if pursued later. | Evidence report retains audit-specific blocked disposition |

Use [research.md](research.md) for current primary documentation links. Provider UI menus
are not hard-coded here; instructions name the exact resource/API capability needed.
An unsupported feature does not require running a failing destructive test repeatedly.

## Authorized native demonstration

Only run after the operator has explicitly authorized the named isolated targets/actions.
The implementation's private report supplies exact UUIDs/revisions and scenario commands.
Never paste a token, password, DSN or workflow URL into chat or shell arguments.

1. Register two distinct test roots and record trusted actor/user/resource attribution.
   Start the relevant `providers probe --root UUID --revision N --scenario NAME --operator LABEL`
   before the event so it can observe successful baseline access. Its limited private
   credential/input channel must not expose secrets in flags/output. Wait for `probe_ready`.
2. Generate the enrolled safe VIP trigger. Confirm collector ingestion, event identity and
   source timestamp. The relay must automatically deliver it to native intake; an operator
   submit can test response wiring but cannot pass native detection acceptance.
3. Observe local hold/cancel, then exact configured provider actions. Test root-only and
   definition scope as separate incidents with the healthy peer control. A root-only
   shared JWT remains a labeled capability limit; do not broaden to a shared block.
4. Verify the same unexpired JWT against the provider, new issuance, exact native token if
   applicable, old/fresh DB connections, user-session behavior and static replacement
   usability. A probe that unexpectedly obtains a credential must track and revoke its
   lease. Healthy controls must rule out network outage/ban as the denial cause.
5. Read `providers status --incident UUID`; run read-only `providers reconcile` with the
   current revision. Import independently captured source/observation/delivery evidence
   with the explicit local import command and reviewer label. Keep raw evidence private.
6. Compare the upper bound of measured origin-to-last-required-denial with 30 minutes.
   Missing clock bounds, expiry, restart, an unblocked path or unavailable origin yields
   inconclusive. Report each Function 10 test independently; never auto-promote acceptance.
7. Follow the report's guided external restoration steps. Preserve the old identity block
   until minting has stopped and complete old-token lifetime safety is established. Changing
   actor/client configuration requires a future configuration migration and is not a 007
   recovery shortcut; never delete state to work around the configuration binding.
   Then verify required outcomes and use existing local `release` with all incident IDs
   and current revision. It never reactivates users or restores registry entries itself.

## Roadmap proof matrix

| Design test | Required independent evidence |
| --- | --- |
| F10-T1 | Real collector event → authenticated enrolled intake → automatic configured action |
| F10-T2 | Exact dynamic lease handling plus underlying fresh/open DB loss, healthy control |
| F10-T3 | Same external JWT/provider session cannot obtain new credentials; actual denial mechanism |
| F10-T4 | Mapped tenant user/session outcome and observed Teams message creation; federation scope explicit |
| F10-T5 | Real source event, supported static rotation, old-value denial and replacement usability |
| F10-T6 | Source/detection/decision/revoke/last-block timestamps with bounded uncertainty below baseline |
| F10-T7 | Targeted root loses attributable access while same-definition healthy peer remains usable |
| F10-T8 | Existing and fresh definition paths deny; unknown paths prevent full containment claim |
| F10-T9 | Immediate provider denial while external JWT remains unexpired; distinguish policy/token/validation |

## Migration and recovery drill

Use synthetic v1 state with unresolved 006 incidents. Migrate, inspect byte-preserved legacy
records, and attempt an old binary read: it must fail closed. Explicit enrollment adds no
historical provider plans. Interrupt after submitted intent, restart, and verify no second
provider call. Read-only reconcile may prove current state; operator retry creates a linked
record with a new action ID. Notification resend similarly creates a new notice revision.
A failed import, stale review or mere acknowledgment cannot authorize release.
