# Runtime contracts: Operational reliability

Status: planned interfaces; commands/routes below do not exist until implementation.
No authentication lifetime or existing task/retry ownership contract changes.

## Browser routes

All routes use existing loopback Host/Origin enforcement, no CORS, no-store responses,
strict versioned request models, and fixed safe error projection. Obtain the browser
cookie and anti-forgery token through the existing session bootstrap first.

| Route | Request / access | Response and effects |
|---|---|---|
| `GET /workspace/operations` | Existing browser cookie; no credential refresh | OperationalView with aggregate readiness/recovery/sign-in states. Owned incident details only for its active signed-in session. Unknown/missing cookie: 403. |
| `POST /workspace/diagnostics` | Existing cookie, Origin and CSRF; `{schema_version: 1}` | Bounded DiagnosticReport; read-only checks against configured targets. Signed-out bootstrap clients can see aggregate checks without incident ownership details. No provider credentials or task execution. |
| `POST /workspace/recovery/check` | Existing cookie, Origin and CSRF; `{schema_version: 1}` | Reread/revalidate journal and return OperationalView. No network mutation, proof import, native-handle input, or state reset. This route never itself resolves an incident. |

Operational views are separate from job outcomes. Recovery may make a new submission
admissible; old failed/canceled jobs stay unchanged. Login remains available during a
recovery block when no task/cleanup is active. Expiry and sign-out remove incident detail
access and user authority. These status reads/checks do not touch idle-session expiry or
initiate refresh. A new task uses the existing admission/conditional renewal logic.

One active diagnostic call per workspace; overlapping calls return 409 diagnostics_busy.
A report always returns by the 30-second deadline with unfinished checks marked
inconclusive/diagnostic_timeout. No implicit retries or polling of providers. Canceled
or overdue workers are canceled and drained; hold the diagnostic slot until they finish,
so an uncooperative DNS/transport worker cannot accumulate across requests. A workspace
recovery check uses only a bounded local read (2 seconds); lock contention returns 409.
UI refresh can reread status but never repeats diagnostics or task submissions on reload.

Diagnostic checks are fixed: local settings validity, public identity discovery, Vault
seal status, database TCP connect without authentication. HTTP bodies are streamed with
64 KiB maximum, verified TLS, no redirects and no environment proxy credentials. Database
TCP success is explicitly labelled transport-only; Vault seal success proves neither
issuance permission nor Vault-to-database connectivity. Authorization classification uses
observed sanitized normal-call failures, not a credential-creating diagnostic probe.

The browser renders plain-language explanations, a Check connection button, a Check
recovery button, and the applicable next action. Buttons stay disabled until session
bootstrap supplies cookie/CSRF, including delayed-bootstrap regression coverage. Announce
status changes through a polite live region; controls must work by keyboard. A report
older than 60 seconds is labelled stale, never silently presented as a fresh observation.

## Safe reasons and actions

These codes extend existing WorkflowError mappings; never forward exception/provider text.
Public category, stage, and action combinations are a closed lookup table.

| Reason | Stage/category | Action / explanation |
|---|---|---|
| configuration_missing | configuration | configure: list setting names only, link local configuration guide |
| dependency_unreachable | connection/reachability | check_connection: provider/network guidance; no asserted root cause |
| diagnostic_timeout | connection/timeout | check_provider: timed out; check provider status and configuration |
| provider_access_denied | credential/authorization | contact_operator: issuance permission denied; separate recovery status may remain blocked |
| sign_in_required | identity/sign_in | sign_in: authenticate when a new task is needed; does not clear recovery |
| acquisition_uncertain | credential/recovery | inspect_evidence: operator runs recover status/import with exact incident |
| cleanup_unconfirmed | cleanup/recovery | recover_exact_lease: operator cleanup command, no task retry |
| recovery_uninitialized | storage/recovery | initialize: initial enrollment command only, never an incident remedy |
| recovery_storage_error | storage/recovery | repair_storage: preserve files, restore a matching private backup or investigate damage |
| recovery_environment_mismatch | storage/recovery | restore_configuration: original configuration needed; no new empty journal |
| recovery_evidence_required | recovery | obtain_native_evidence: unique native request/response or exact lease handle is missing |
| recovery_evidence_invalid | recovery | inspect_evidence: strict schema/linkage/review failed |
| recovery_access_denied | recovery | contact_operator: exact cleanup authority unavailable |
| recovery_busy | recovery | wait: active effect/cleanup owns the lock |
| recovery_capacity | storage/recovery | resolve_incidents: unresolved state is retained; no silent eviction |
| diagnostics_busy | connection | wait: previous diagnostic check is still active/draining |

Browser incidents include only public UUID, stage, reason, and next action. After sign-out
or restart they are visible in aggregate only; local operator status supplies references.
Generic 400 is used for invalid requests, 401 for signed-in resource access after expiry,
403 for Origin/CSRF/cookie failures, 409 for contention, and 503 for recovery/storage blocks.
A diagnostic report with failed checks is HTTP 200 because the report itself completed;
transport errors that prevent report creation use a safe 503 response.

Supabase guidance links [Database Settings](https://supabase.com/dashboard/project/_/database/settings),
the destination verified from its official troubleshooting documentation on 2026-10-10, prompts the operator to verify the selected project and inspect Network
bans, and states the access required and expected result. No private project identifier
is embedded in public assets. Generic providers receive configuration/status guidance,
not an invented menu. Repair never marks uncertain issuance resolved.

## Operator CLI

Use existing Settings and project-root discovery. No new environment variables. Native
credentials come only from existing `VAULT_TOKEN` in the operator process; CLI must never
accept a token on its command line or print it. Workspace diagnostics/recovery paths do
not read or use this administrative setting, even if it exists in the local environment.
All commands emit sanitized JSON containing status, reason_code, incident_id when relevant,
and next_action; status exit 0 means state inspected, not live provider acceptance.

| Command | Contract |
|---|---|
| `agent recover init` | Explicit exclusive prospective enrollment. Create absent private root/anchor/state; validate complete live database target. Existing identical initialized root returns unchanged; partial, mismatched, or damaged state is rejected, never replaced. No network calls. |
| `agent recover status` | Read safe aggregate and incident references/states. Exit 0 clear/not_configured, 2 blocked/uninitialized, 1 invalid/storage failure. No tokens, native IDs, or evidence paths in output. |
| `agent recover import --incident UUID --source PATH [--source PATH] --reviewer LABEL` | Locally review/import up to two native JSON/JSONL artifacts; files must be owner-only regular files below project `.local/`. Require complete exact proof, explicit provenance review by the named local operator, and current incident revision. No network. A valid lease-identification receipt persists a private handle but leaves recovery blocked; revoked/not-issued proof can resolve. |
| `agent recover revoke --incident UUID` | Explicit provider mutation limited to one already-bound exact native handle. Require operator token and matching configured environment. Take effect lock, send a single sync revoke, durably record proof. No broad revocation, issuance, SQL, renewal, or automatic retries. |

Exit 0 for committed init/import/revoke result, 2 for unresolved/missing capability/busy,
1 for malformed input or unsafe storage. Output always states whether recovery remains
blocked. Repeating a completed command is a no-op after verifying its binding; repeating
a timed-out revoke is an explicit operator decision and remains exact-handle only.
No `reset`, `clear`, `force`, mark-resolved checkbox, or acceptance override is provided.

Imports read bounded bytes and derive digest-bound proof without copying raw artifacts.
Use the private safe opener/decoder; do not follow URLs, symlinks, or source-provided paths.
Review attests provenance of the bytes being imported, not merely that the user wants an
incident cleared. A stale revision or changed source fails; native records must be unique
within the supplied evidence. Unsupported/HMAC-only linkage stays blocked with exact
missing-field instructions. Import cannot change a preexisting handle or environment.
Direct revoke needs at most one 10-second network call and 30 seconds total including
drain. Timeout or lost response leaves uncertainty. Retain the effect lock until any
in-process child has terminated; journal uncertainty remains after process death.

## Native acquisition and cleanup

Durable intent exists before sending `GET` to the configured credential path. Send its
operation UUID as `X-Correlation-Id` without depending on validation-run IDs. Merge the
observer/recovery correlation through one shared binding so their IDs cannot conflict.
A credential GET is side-effecting and must never be automatically retried by any client.
Persist the handle before SQL and attempt cleanup even if subsequent validation fails.

Cleanup wire body is `{"lease_id": "exact private handle", "sync": true}`.
Signed authorization details bind `path=sys/leases/revoke`, `capabilities=[update]`,
`required_parameters=[lease_id,sync]`, and `allowed_parameters` to that one handle plus
`sync: [true]`. Type-aware matching rejects numeric 1, strings, omitted sync, false,
widened sets, extra fields, and unrelated handles. Provisioning HCL permits boolean true
and the existing role prefix; signed delegation narrows it to the exact returned handle.
The example schema adds `allowed_parameters.properties.sync` with `const: [true]`, while
retaining the existing string-array constraints for other keys. No async fallback.

Successful synchronous TLS cleanup can produce an operational receipt without audit
export. Publish a cleanup-complete event or successful task outcome only after that
receipt is durably committed; a storage failure must preserve the unresolved block. Imported cleanup proof instead requires exact request/response linkage,
`sync=true`, namespace/path/handle match, and successful native response. Unknown issuance
requires exact acquisition correlation first; generic audit error or missing lease field
never means not-issued. Only an explicit pre-execution ACL policy denial can establish
that outcome. Malformed/conflicting provider replies remain uncertain.

## Delivery and acceptance

Changing installed provider RAR/ACL configuration is a separately authorized guided action.
Runtime must fail safely when old policies reject sync=true. Keep previous 003/004 native
acceptance and historical uncertainties unchanged. Software task completion and live
validation dispositions are recorded separately; no command edits acceptance.json.
