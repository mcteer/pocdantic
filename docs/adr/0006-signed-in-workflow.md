# 0006: Local signed-in browser workspace

Status: Accepted for implementation. Date: 2026-10-09.

## Context

The bearer CLI requires manual token acquisition and has no browser workflow for task results.
The operator selected a local browser interface and needs concrete, safe approval recovery.

## Alternatives

Retaining CLI-only token entry does not meet the selected user interface. A separate frontend
build and durable session service add deployment and credential-storage boundaries unnecessary
for a single-process local workspace.

## Decision

Add a separate loopback browser app using the existing server extra and bundled HTML,
JavaScript and CSS. Preserve the existing bearer service and CLI. Use a separate confidential
login client, code/S256 PKCE, browser-bound state and ID-token nonce, and separately verified
resource access tokens. Keep all credentials in bounded server memory.

One shared runtime and one process-wide admission/execution/cleanup slot preserve containment.
Reserve trusted IDs before effects. Bind idempotency keys and history to the owning session.
Twenty distinct keys include retry aliases; records are never evicted within a session.

Native denial and unconfirmed approval are separate outcomes. Retry invokes the shared
trusted action helper with frozen canonical action bytes and fresh request/run/approval IDs.
It neither calls the model nor replays earlier tools. Terminal approval invalidation is atomic.

## Consequences

Refresh runs once under the session lock at admission, with identity continuity and sufficient
lifetime for the runtime and cleanup budget. Sign-out contains before draining cleanup.
Unresolved cleanup retains its private context and quarantines admission. No browser decision
setter, durable session store, proxy deployment or remote host option is added.

WebKit is development-only; controlled signed-provider and exact-lease fixtures exercise the
complete workflow without live credentials. Deterministic software checks do not promote
customer acceptance or close historical vendor evidence gaps.
