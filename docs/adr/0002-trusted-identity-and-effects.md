# ADR 0002: Trusted identity, authorization and effects

Status: Accepted. Date: 2026-10-09. Owner: mcteer.

## Context

Model instructions and retrieved data cannot establish authority. Leased credentials
and privileged approvals need enforceable boundaries outside model context.

## Decision

Verify signed user access tokens before model execution. Apply deterministic policy
at every effect and keep child permissions narrower than parent permissions.
Keep OAuth/Vault/database credentials inside trusted adapters. Validate subject/actor
lineage and exact RAR; never substitute an operator token after delegation failure.
Use fixed parameterized SQL, SELECT-only grants, verified TLS and explicit lease cleanup.
Bind approvals to requester, run, action, resource, parameters and expiry; consume once.
Simulate the infrastructure restart until a separate real write adapter is reviewed.

## Alternatives

Prompt-only authorization, standing database credentials and unbound approvals cannot
enforce these contracts. Broad retry/fallback behavior could mask denied access.

## Consequences

Trusted adapters carry policy and cleanup complexity. Unsupported provider features
fail closed. JWT, lease and active-session revocation have different semantics.
A pooler can defer rejection until a query; revoked-credential checks must execute a
fresh protected read rather than count connection construction as successful access.
