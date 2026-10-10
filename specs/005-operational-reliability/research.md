# Research: Operational reliability

**Date**: 2026-10-10. Read-only code and primary-document research; no provider mutations.
Spec Kit planning dispatched separate native-proof and storage/runtime research agents.

## 1. Observed failure and diagnosis

**Decision**: Separate connection observations, unresolved access, and user sign-in.
**Rationale**: The sanitized 004 validation ledger records a 15-second credential failure
with a fresh token. A database network ban was later observed; unbanning restored a read.
Neither a healthy dashboard nor that successful read reconciled the two earlier unknown
acquisitions. The initial cause of the ban remains unknown.
**Alternatives**: Repeated sign-in, automatic credential retries, or treating health as
cleanup proof do not address these independent states.

Workspace checks use local prerequisite validation, configured identity discovery,
unauthenticated Vault seal status, and a TCP connection to the configured database host
without sending authentication data. No SQL/authentication probe is performed. TCP success
means transport reachable, not database ready or Vault-to-database connectivity proven.
Authorization failures can be classified from sanitized facts of previous normal calls;
no privileged authorization probe is introduced. Each check is at most 10 seconds with
one 30-second deadline, no automatic retry, redirects or environment proxy trust.

Vault documents seal status as unauthenticated; this observation does not verify database
issuance permission. [Vault seal status](https://developer.hashicorp.com/vault/api-docs/system/seal-status)

Supabase's current troubleshooting documentation links **Database Settings** and the
**Unban IP** action. Guidance will use that official link, require the operator to select
and verify their project, inspect Network bans, and unban only an identified applicable
address. The expected result is disappearance of that ban and a subsequent connection
check; the application does not infer a ban or unban automatically. CLI instructions are
an operator alternative, not a command executed by diagnostics.
[Supabase connection troubleshooting](https://supabase.com/docs/guides/troubleshooting/error-connection-refused-when-trying-to-connect-to-supabase-database-hwG0Dr)

## 2. Native cleanup proof

**Decision**: Require completed synchronous exact-lease cleanup, not a queued response.
**Rationale**: The current `VaultClient.revoke` omits `sync`. Vault documents `sync=false`
as asynchronous and `sync=true` as waiting for completion. A successful TLS response to
a trusted exact-lease synchronous request can support operational cleanup disposition;
it does not satisfy missing native-audit acceptance from 003.
**Alternatives**: Prefix/force revoke could affect unrelated access or ignore backend
failure. TTL expiry and an empty role query do not prove exact cleanup. None are supported.
[Vault lease API](https://developer.hashicorp.com/vault/api-docs/system/leases)

Update the wire request, exact delegated parameters, schema, and example provisioning
policy together; require boolean true, not optional or false. Existing installed provider
policy may reject it until manually updated. No planning or CI step changes that policy.

Use JSON boolean `true` in the request and `allowed_parameters.sync: [true]` in the
signed RAR; require both `lease_id` and `sync`. Add an exact `sync` property constrained
to `[true]` to the existing parameter schema, preserving string arrays for other keys.
HCL permits `sync = [true]`. The delegated-claim comparator must be type-aware because
ordinary Python equality treats `1` and `True` as equal. Reject numeric/string/false
values, omitted sync, widened arrays, and wrong lease IDs.
[Vault RAR parameter schema](https://developer.hashicorp.com/vault/ai/oauth-server/rar/type-specification),
[Vault ACL boolean tests](https://github.com/hashicorp/vault/blob/main/vault/acl_test.go)

## 3. Unknown acquisition proof

**Decision**: Persist a generated acquisition UUID before sending it as `X-Correlation-Id`.
Import a unique matching native request/response pair before accepting an unknown lease
handle. Require agreement of deployment, namespace, exact credential path, operation,
correlation UUID, and every supplied native request ID. An explicit native policy decision
that denied the request before execution can prove non-issuance; generic backend errors
cannot. Unsupported schemas or incomplete evidence remain unresolved.
**Rationale**: Vault documents correlation headers in audit records by default, but
operators can alter that configuration. Audit records expose request IDs, namespaces,
paths, policy decisions, and lease fields. Missing/HMACed identifiers may make this
release unable to establish the linkage.
**Alternatives**: Time-window matching, lease-prefix inventory, absent records, and a
manual acknowledgement do not establish exact causal linkage.
[Vault audit logging](https://developer.hashicorp.com/vault/docs/audit),
[Vault audit schema](https://developer.hashicorp.com/vault/docs/audit/schema)

HMAC-only lease or correlation identifiers are unsupported in version 1. Hashing a known
value for an audit device cannot recover an unknown handle. Do not guess the mapping.
[Vault audit hash](https://developer.hashicorp.com/vault/api-docs/system/audit-hash)

The current `validation/importers.py` drops critical policy/path/namespace fields and
maps generic audit errors to denial. `validation/correlation.py` accepts either of two
IDs rather than rejecting conflicts. Reuse strict decoding/private storage utilities,
not those functions as recovery authorization. Review binds immutable file digests and
incident revision; it remains an operator provenance review, not authenticated attestation.

## 4. Journal, locks, and initialization

**Decision**: Use a bounded strict JSON snapshot with owner-only permissions, atomic
replacement, file and parent-directory fsync. Use workspace lifetime ownership,
environment effect, and short journal transaction locks. Store an environment fingerprint
inside a fixed `.local/recovery` root; do not choose a new empty root on config change.
**Rationale**: Existing `validation/store.py` provides comparable stdlib primitives.
One serialized database effect and bounded records do not require another database or
third-party locking dependency. CLI recovery can update state while the idle browser
keeps its session. Every admission rereads durable state.
**Alternatives**: In-memory state loses uncertainty; SQLite adds unnecessary integration
for a small snapshot; browser-admin APIs widen authority; one lifetime lock for all work
would require stopping the server for recovery.

Initial enrollment is explicit (`agent recover init`). Missing state never means clean
state on startup. Existing damaged state cannot be reenrolled; restore its private backup
or investigate as a storage incident. There is no reset command. Filesystem durability
failures block effects; tests cover write/fsync/rename/crash boundaries. Local admin
rollback is outside the threat model. Resolved records may be pruned; unresolved records
never are. No authentication credentials, user identities, prompts, or results persist.

Coverage begins at enrollment. The two legacy 004 attempts remain separately unclosed;
005 cannot invent missing historical correlation. This is a stated compatibility boundary,
not evidence that enrollment resolved prior uncertainty.

## 5. Shared containment and session continuity

**Decision**: Journal all live `DatabaseBroker` acquisitions, including CLI/bearer paths.
Separate active-work busy status from recovery quarantine; preserve valid sessions during
checks and recovery, permit login while recovery is blocked, and recheck authority on new
submission. No background task replay or session restoration.
**Rationale**: Gating only the browser leaves alternate entrypoints able to bypass state.
Current `manager.busy` includes quarantine and blocks login; splitting those states avoids
requiring restarts. In the observed provider configuration there was no refresh token;
005 cannot promise silent renewal beyond provider support.
**Alternatives**: Persisting tokens or extending their lifetime violates the intended
security model. Repeated login cannot reconcile native access.

## 6. Delivery and public guidance

**Decision**: Keep README concise; detailed commands and migration go in usage/configuration
and ADR 0007. Root AGENTS.md summarizes contributor guidance and links authoritative rules.
**Rationale**: User requested that companion file and previously requested shorter names
and less README repetition. No new environment settings are needed for this feature.
**Alternatives**: Additional framework/tool files and copied policy documents would create
competing instructions. Existing branch-protection gaps remain a later delivery gate;
no previous merge authorization is inherited.
