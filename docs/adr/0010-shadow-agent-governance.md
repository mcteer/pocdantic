# 0010: Shadow agent governance and independent identity proof

Status: accepted for feature 008 implementation. Date: 2026-10-10.

## Context

Discovery, registry enrollment, SPIFFE identity and policy enforcement are different
claims. An unknown collector finding must not grant authority, and a successful mint
must not be equated with relying verification. Existing response/recovery holds and
ownership already protect provider work; governance must use that same boundary.

## Decision

Keep a separately anchored owner-only governance journal with immutable installation
identity and a durable seal binding its revision, digest and current state inode. Use
atomic fsync commits, exact reference closure, finite capacities and pre-dispatch result
reservations. Never reset authority, release containment or replay unknown issuance.

Enroll tenant-specific observation projections behind a separate relay audience/scope.
Store selected scalar receipts and preserve first observation. Privileged compiled
workflows inherit recovery workspace, response worker/probe, governance effect and
recovery effect locks in that order; short control transactions never surround I/O.
Parent death leaves the child owning those locks until termination/deadline.

Native creation consumes one exact fresh review before one create POST. Persist the
returned identity before subsequent exact ID/entity/name readbacks. Foreign matching
presence and 404 readback cannot establish local creation or permit blind retry. Candidate
direct OAuth requires independently verified exact actor/audience/RAR without delegation;
OBO separately validates the human, actor and returned delegation.

A separate private Unix-socket process reads current pinned trust and fetches public
keys itself. Its one-use challenge binds candidate, generation, issuance intent and
implementation. Verify signatures before trusting claims, including the nested signed
Vault entity. Mint/admin credentials never enter this service. Nonce consumption is a
local proof property, not global JWT revocation or replay prevention.

The browser exposes only verified-owner read-only generated labels/status. Seven
Function 11 predicates independently require current correlated reviewed evidence,
healthy controls and appropriate chronology. Missing audit/source/license prerequisites
remain blocked. Public acceptance files require separate reviewed native evidence.

## Alternatives

A single mint-and-verify process would blur independent relying proof. Provider mutation
from a collector event or browser would bypass host review. Inferred generic vendor
schemas and administrative token substitutes would overstate both discovery and candidate
permissions. None supplies the required evidence/authority separation.

## Consequences

Operators prepare isolated provider resources and reviewed private mappings before native
work. Lost issuance can require provider evidence and explicit resolution. Existing
workspaces must drain before privileged governance commands. Synthetic tests exercise
contracts and process failure boundaries; they cannot certify vendor acceptance.
Existing response/recovery schemas, OAuth flows and CLI compatibility remain unchanged.
