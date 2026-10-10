# 0008: Durable incident containment and attributable cleanup

Status: implemented; local validation recorded in feature 006. Date: 2026-10-10.

## Context

Process-local cancellation disappears on restart. Recovery records previously lacked
run attribution, so administrative cleanup could not safely select an incident scope.

## Decision

Use a separate private control journal, host-derived root ownership, stable definition
generations and short control locks. Local-only input requires no relay; remote input
requires a dedicated audience and exact source mapping. Commit containment before
acknowledgment, then cancel owners and wait for ordinary cleanup to drain. Effect child
processes inherit ownership descriptors so parent death cannot falsely prove drain.

Migrate only the recovery snapshot to v2, keeping the v1 anchor and receipts. Preserve
legacy records as unattributed. Pin cross-store records while an incident or unresolved
attempt needs them. Submit only exact attributable cleanup with separately configured
operator authority. Persist action intent and never automatically replay uncertain work.

## Alternatives and consequences

A shared long-running lock would prevent cancellation of its owner. Timestamp-based
ownership guesses and cleanup prefixes would expand authority. Volatile holds would
permit restart bypass. Those alternatives were rejected.

Live paths now require explicit response enrollment. Local definition release requires
current holds/revision and confirmed drain/cleanup; old roots and approvals cannot resume.
A deliberately non-database installation has no recovery lock; missing formerly enrolled
state is still an error. Native risk detection, provider-wide token/user blocking, rotation,
notifications and shadow governance remain follow-on work. Local tests do not accept them.
