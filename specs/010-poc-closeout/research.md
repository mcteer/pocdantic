# Research: End-to-End PoC Closeout

**Date**: 2026-10-10. Planning research only; no private live state inspected, provider operation
executed or external acceptance claimed. The approved scope is guided execution and evidence
collection. Read-only research agents examined existing evidence surfaces and client counting.

## 1. Separate aggregate workflow

**Decision**: Add `agent closeout` and `src/agent/closeout/`, preserving `agent validate closeout`.
**Rationale**: The latter validates four database/phone cases, not UC1–UC4. Its per-run review
supports positive eligibility for only UC1-01, UC1-05 and UC2-02. Reusing its name or broadening
its eligibility implicitly would misrepresent existing evidence.
**Alternatives considered**: Extend the old snapshot schema (breaks scope/compatibility); build a
second executor (unneeded authority, contrary to clarification); a static checklist alone (does
not bind evidence, measurements or reviews).

Reuse `src/agent/evidence.py::CRITERIA`; `validation/closeout.py` immutable member principles;
`validation/report.py::rebuild_report(..., persist=False)`; Function 10 assessment in
`validation/closeout.py::provider_closeout`; Function 11 in `governance/report.py::closeout`.
Do not call CLI dispatch or constructors that mutate member permissions/locks while inspecting.
Refactor only pure assessment helpers if needed, preserving original commands with regression tests.

## 2. Historical capture and current applicability

**Decision**: Capture exact owned member bytes into a private dossier before pure evaluation,
record the actual evaluation time, and preserve that immutable result. Compute later applicability
separately: `current|historical|missing|invalid`.
**Rationale**: Function 10 currently requires observations within 300 seconds; Function 11 uses
revision/generation/environment matching. Evaluating old records with a fabricated past clock
would manufacture eligibility. A historical recorded evaluation can support a historical witnessed
demonstration, but cannot certify the current live deployment.
**Alternatives considered**: Extend native freshness indefinitely (unsafe); discard old evidence
(loses review history); always demand a new phone prompt (unnecessary and contrary to user workflow).

Capture adapters examine the complete relevant attempt history in selected scope, not only a
passing row. A deterministic global lock order is unnecessary for external stores: perform
bounded descriptor-safe snapshot reads and verify inventories before/after; fail if they move.
Seal last; never write or chmod a member root. Evaluation includes relevant later failures already
present at capture. A new contradictory capture supersedes eligibility but preserves the old result.
Missing source roots affect current applicability, not the integrity of retained historical bytes.

## 3. Proof obligations, review and exceptions

**Decision**: Use the explicit fifteen-row proof matrix in [contracts/runtime.md](contracts/runtime.md).
New native formats must be pinned and reviewed with digest-bound selected fields and correlation;
free-form claims never become a pass. Existing native limitations stay blocked. A new review schema
binds criterion assessment or core package digest, role and private attestation.
**Rationale**: The existing public acceptance schema checks required fields, not actual sufficiency.
Local role labels also do not authenticate a reviewer. Actual witness confirmation is owner evidence.
**Alternatives considered**: Import any existing `pass` string; count process exit 0 as acceptance;
automatically edit tracked acceptance.json; waive original requirements with an alternative decision.

Original status is `pass|fail|blocked`; an agreed alternative is separate and requires customer plus
relevant vendor agreement. The original result remains visible. Code computes eligibility, human
review decides acceptance, and remaining failed controls remain explicitly reported even when an
exception is accepted for the historical PoC.

## 4. Client activity evidence

**Decision**: Import a versioned Vault activity JSONL format separately from audit logs, together
with baseline, actual identity mappings, execution roster and collection metadata. Analyze locally.
**Rationale**: The existing importer does not support client activity; 009's 100-run test is synthetic.
**Alternatives considered**: Subtract aggregate counters only; count tokens as clients; provision
100 users; use a narrow timestamp window without checking provider export semantics.

Provider facts checked against the [counters API](https://developer.hashicorp.com/vault/api-docs/system/internal-counters):
exports cover calendar months, may lag current activity by 20 minutes, include a namespace and its
descendants, require read plus sudo capability, and are documented as preview. Entity inventory is
not active-client evidence. Effective periods and version/edition must be recorded; unknown formats
remain blocked. The documented first-use field differs between prose and examples, so importer
versions must explicitly select the supported spelling and reject conflicting values.

The [client-counting rules](https://developer.hashicorp.com/vault/docs/concepts/billing/clients/counting)
count agent and delegated subject separately and do not deduplicate across clusters. Other client
categories can affect totals. Controlled expectations are one agent for repeated executions or
agent-only access, 101 entities for one agent plus 100 distinct delegated users, and 100 direct
clients. These are explained test expectations, not a price quote.

**Engineering choice**: Keep scenario-associated and newly active sets separate. Reusing a human
cohort for direct access after OBO can produce 100 scenario clients with zero incremental clients.
Use exact roster membership and explain every extra/missing/reused entry; no numeric tolerance
turns an unexplained difference into a pass. Scope cluster/namespace/mount and full period explicitly;
compare exports only within compatible scope. An export row alone cannot prove an operation occurred
in the experiment window; correlated operation and mapping records supply that proof.

## 5. Guided native execution and unavailable operations

**Decision**: Provide checked recipes for existing workflows and an evidence collection protocol for
experiments without a native bulk runner. List the required externally prepared cohort and successful
operation evidence, with owner and exact prerequisite. No new runner is implied by a guide.
**Rationale**: 100 distinct subjects cannot be replaced with repeated tokens for one human. Existing
application flows do not automatically support every agent-only or direct-client experiment.
**Alternatives considered**: Fabricate a universal executable command; alter actor-only denial into
success; collect credentials through CLI parameters. All would undermine prior controls.

Use 003, 007 and 008 quickstarts as owned source guides. Validate linked command forms against current
parsers. Unknown provider console paths are not invented: reference the official API/documentation,
name the product owner and describe the expected artifact. A unsupported execution mode is a named
external prerequisite; it does not block implementation of the importer, reconciler or review flow.

## 6. Private package and bounded storage

**Decision**: Fixed ignored `.local/closeout/` with immutable revisions and sealed directory packages;
no archives, arbitrary output roots or automatic upload. Core package is sealed before role review;
final handoff copies that core and applicable review sidecars into a new sealed directory, avoiding
self-referential hashes. All generated content stays private, including sanitized summaries.
**Rationale**: Existing publication guards already reject generated closeout records. A package
assembler must not convert arbitrary source prose or unreviewed screenshots into a public report.
**Alternatives considered**: Zip arbitrary paths; recursively copy entire source stores; render raw
provider logs; automatically erase old failed runs; expand public allowlists.

Package output is rebuilt from allowlisted facts. Optional text/image attachments must have explicit
sanitization review for exact bytes; they remain supporting proof. Raw source records are retained
privately in the dossier, excluded from handoff core. No image OCR/redaction guarantee is claimed.
The software reports operator review as an attestation, never verified absence of every possible
secret. Known-token/credential scanning is a defense-in-depth rejection, not sufficient approval.

## 7. Stack and validation

**Decision**: Existing Python >=3.12, Pydantic, argparse, stdlib JSON/hash/path operations; no new
dependency, extra, environment variable or schema migration. Add one installed command group.
Use synthetic fixtures in Python so generated evidence files cannot be mistaken for publishable data.
**Rationale**: This is a bounded local evidence workflow. All normal tests can deny network and poison
provider configuration. Existing full CI, WebKit and 009 regression checks remain authoritative.
**Alternatives considered**: New database, browser service, document renderer or provider SDK; none
is necessary for a private directory package and Markdown readout.

All planning unknowns are resolved into contracts, bounded assumptions or explicit operational
blockers. Provider eligibility and availability must still be verified for an actual live capture.
