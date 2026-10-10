# 0009: Exact provider response and independent proof

Status: accepted for feature 007 implementation. Date: 2026-10-10.

006 commits local containment before waiting for effect owners. Extend that boundary
with an atomic response journal v2 containing exact provider enrollment, immutable
plans, resource fences and independent observations. Keep the recovery lease lifecycle
and existing source policy/anchor identities. Migration preserves old incidents as
local-only and never schedules historical provider effects.

Native risk events use bounded tenant-specific scalar projection behind pinned source
authentication. No universal VIP schema is assumed. Collector evidence, authentication,
provider acknowledgment and observed access denial remain different claims.

Registration removal blocks the enrolled actor's Vault OAuth route. It does not revoke
native tokens or globally invalidate signed JWTs. Exact native accessors require
prospective ownership. Tenant user/session controls cannot claim global IBMid logout.
Root scope excludes shared security controls, preserving healthy peer executions.

Every mutation has durable submitted intent and no automatic replay. Read-only
reconciliation cannot acquire credentials. Dedicated negative probes have their own
intent lifecycle; an unexpected credential is adopted into exact recovery before use.
Provider uncertainty, unresolved acquisition and missing proof keep holds in place.

Rotation uses isolated static roles. Direct session termination requires an isolated
role and rechecked backend identity; its native PID fencing limit is reported. Teams
Workflows acceptance is distinct from delivery and notices deduplicate per incident.

External restoration is guided and requires complete old-token lifetime safety. The
existing environment fingerprints prevent changing actor configuration without a
future explicit migration. Local release admits a fresh generation only.

New SDKs, public hosting, guessed event schemas, broad revocation, shared-role SQL,
automatic retries and automatic provider re-enablement were rejected. Maintained
modules/functions explain effects, failure states and security ordering. Deterministic
tests establish software behavior; native acceptance needs private live evidence/review.

The implementation also records finite JWT issuance separately from Vault leases. An
unknown exchange remains pinned; known signed JWTs can satisfy lifetime safety after
expiry plus skew, without claiming provider denial. Probes run in a compiled child with
private stdin and inherited lifetime/effect descriptors. Database controls compare the
server's actual healthy identity. Tenant-session proofs require a reviewed field selector
and schema digest instead of assuming a response field. Root native events bind their
host request to exact enrolled actor/user metadata; selected native security content and
the enrollment digest are fenced through the final intake transaction.
