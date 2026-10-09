# ADR 0001: Slim dependencies and native capabilities

Status: Accepted. Date: 2026-10-09. Owner: mcteer.

## Context

A reusable PoC must compose alternate agents without installing every provider
or binding behavior to one customer's environment.

## Decision

Use pydantic-ai-slim as the base and native Capability bundles for reviewed tools.
Provider, telemetry, server and PostgreSQL dependencies are optional extras.
Use typed profiles with stable definition IDs, shared usage budgets and bounded
delegation. Bundle default profiles in the wheel for installation outside a checkout.

## Alternatives

The full provider package simplifies installation but expands the dependency set.
Per-customer agents duplicate security logic. Both were rejected for this baseline.

## Consequences

Operators select needed extras; missing integrations fail explicitly.
New capabilities require policy and boundary review. Logical agents in one process
share workload trust and do not provide independent attestation.
