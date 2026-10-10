# Security design review: Incident containment and exact cleanup

Reviewed 2026-10-10 against constitution 1.2.0 and the runtime contract. Checked items
mean the design addresses the boundary; implementation tests and owner review remain.

- [x] Exact source identity, token purpose/audience/scope and local operator authority are distinguished from human/model input.
- [x] Native VIP payload and public ingress are not invented; relay contract and native evidence are separate.
- [x] Signal parsing, freshness, duplicate semantics and target mapping fail before new effects.
- [x] Root ownership is host-derived and stored before issuance; descendants cannot choose another root.
- [x] Stable definition identity is distinct from a telemetry UUID; generations prevent old work after release.
- [x] Every live entry point and awaited trusted effect transition has a durable guard.
- [x] Control locking can cancel an active effect owner without deadlock; cleanup waits for drain.
- [x] Production child workers inherit root/effect lock ownership so parent death cannot falsely prove drain.
- [x] Exact cleanup uses configured separate authority, fixed destinations and attributed handles only.
- [x] Cross-incident action lookup prevents automatic repeated submission against one attempt.
- [x] Submitted intent survives crashes; uncertainty never becomes success through TTL, empty lookup or acknowledgment.
- [x] Migration preserves anchor/receipts and all attempt data, never infers legacy owners, and replaces one snapshot atomically.
- [x] Storage permissions, atomicity, bounded queue/records and reserved completion capacity are specified.
- [x] Expired settled records can be pruned without authorizing old roots; unresolved references remain retained.
- [x] Cross-store retention pins unresolved ownership and unconfirmed-action receipts; missing records do not imply successful cleanup.
- [x] Explicit local_only and not_configured modes avoid requiring relay/database setup while missing formerly enrolled state remains blocked.
- [x] Local release requires current revision, all holds, drained owners and confirmed cleanup; provider re-enablement is excluded.
- [x] Session-owned browser detail and anonymous aggregate status are separate; no browser administrative mutation.
- [x] Reports and telemetry exclude identities, native handles, raw payloads, destinations and secrets.
- [x] Renamed private artifacts and staged/distribution trees have explicit publication regression coverage.
- [x] Timing labels distinguish local measurements, unavailable intervals and native detection/enforcement claims.
- [x] Offline tests cannot mutate live providers; live work is optional, separately authorized and independently reviewed.
- [x] Unavailable Development-tier audit and deferred native Function 10/11 controls remain explicit limitations.

No design exception requested. The threat model assumes a trusted local administrator;
advisory locks and anchors do not protect against rewriting the application and all state.
