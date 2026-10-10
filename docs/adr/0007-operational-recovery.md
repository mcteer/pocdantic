# 0007: Durable operational recovery

Status: accepted for implementation. Date: 2026-10-10.

## Context

A reachable provider does not prove that an interrupted credential acquisition issued
nothing or that cleanup completed. In-memory quarantine disappeared after restart.
The threat and boundary analysis is in
[the implementation plan](../../specs/005-operational-reliability/plan.md#threat-and-boundary-analysis).

## Decision

Track prospective live database acquisitions in a private project-root journal. Persist
intent before sending, the native handle before SQL, and a synchronous cleanup receipt
before resolving. Every live database entrypoint shares the boundary. Offline fixtures
remain independent. Enrollment cannot reconstruct the two historical 004 incidents.

Use three locks in order: workspace lifetime ownership (when applicable), effect ownership
through acquisition/cleanup or reconciliation, then brief journal transactions. Never hold
the journal lock during provider I/O. An explicit owner object hands off the effect lock;
recursive acquisition and implicit reacquisition are forbidden. A cancellation-resistant
cleanup worker retains ownership until it actually stops.

Use atomic replacement and file/directory fsync with owner-only state. Invalid, missing,
full, mismatched, or damaged state blocks acquisition. No reset or automatic reenrollment.
Resolved records have bounded retention; unresolved records are never pruned.

Known-handle recovery requires exact synchronous revocation. Unknown issuance needs a
unique native request/response pair with exact correlation and explicit provenance review.
Generic errors, timestamps, TTL expiry, absent database users, or healthy transport do not
resolve incidents. Imported artifacts remain untrusted until strict verification; raw
records stay operator-held. A reviewer label records provenance, not authenticated identity.

Browser checks are read-only and separate connection facts, sign-in, and recovery. Operator
cleanup and native evidence import remain CLI actions. Recovery preserves a valid session
but never extends authority, restores a discarded session, or replays an old task.

## Alternatives and consequences

Memory-only state loses uncertainty. A browser-admin API grants unnecessary authority.
A lifetime effect lock prevents an idle workspace from being recovered by the operator.
General-purpose correlation is too permissive to authorize recovery. Prefix/force revoke
and asynchronous acknowledgement do not prove exact completed cleanup.

Installed Vault RAR/ACL policies must separately permit strict boolean sync=true. This
repository changes examples, not installed policies. Native audit linkage may be unavailable;
unsupported proof stays blocked. Local administrator rollback and remote filesystems are
outside the local crash-safety claim.

New modules/functions follow AGENTS.md: document contracts and explain security ordering,
side effects, cancellation, and failure behavior. Tool docstrings remain model-facing inputs.

## Owner review before delivery

Review shared-entrypoint enforcement, strict proof and delegation types, filesystem identity
checks, process-death boundaries, cancellation lock retention, secret-free projections,
session ownership, and prospective-only migration. Record software and live dispositions
separately. Verify required CI/review/protection controls before a later merge; implementation
scope does not itself authorize publication or provider changes.

## Implemented boundaries

Native import supports private JSON envelopes or header-first JSONL, with explicit
operator review of source provenance. The schema/instance/fingerprint header is local
attestation; the original native records supply exact operation, pair, namespace, path,
and lease linkage. Generic errors and HMAC-only linkage remain unsupported. Imports
retain only typed derived receipts. The publication policy rejects journal/anchor and
recovery-receipt filenames even when copied into otherwise publishable directories.

Production diagnostics and exact administrative cleanup isolate network work in trusted
subprocesses. Private cleanup inputs pass through stdin. Spawn cancellation and process
termination retain ownership until the child is confirmed stopped. Injected controlled
transports use the same cancellation/drain ownership rules in deterministic tests.

Workspace lifetime ownership begins when initialized storage is available, including
explicit enrollment after a missing-state startup. Startup normalizes abandoned attempts
only under effect ownership. Check recovery only observes verified closure and can clear
volatile quarantine with exact owned incident linkage; it does not modify old jobs or
session lifetime. Settings removal cannot bypass existing journal state.
