# ADR 0003: Versioned governance and separate live acceptance

Status: Accepted. Date: 2026-10-09. Owner: mcteer.

## Context

Contributors need shared requirements and decisions to review changes. Customer
source documents and credentials must remain private. Software tests cannot prove
external vendor enforcement.

## Decision

Version the sanitized Spec Kit constitution, templates, scripts, secure-poc workflow,
feature specifications, plans, contracts, checklists, tasks and ADRs.
CI checks all versioned feature artifacts without machine-local pointers.
Keep customer design sources, environments, raw evidence, local inventories and
machine-specific integration/run state excluded from Git and distributions.

Version acceptance dispositions and sanitized validation summaries. A live pass requires
reviewed source evidence, a timestamp and an explicit reviewer. Private evidence stays
under ignored .local/ or private/evidence subdirectories; public references must not
expose customer identities or secret storage locations.

## Alternatives

Keeping all specifications local makes independent PR review difficult.
Publishing raw source documents or live evidence violates the project's privacy boundary.
Treating mocks as acceptance evidence misrepresents enforcement.

## Consequences

Reviewers can trace requirements to decisions and implementation. Maintainers must
sanitize published artifacts and separately control private evidence access.
Architecture/governance files belong in Git but are excluded from runtime distributions.
