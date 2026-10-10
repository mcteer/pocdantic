# Runtime contracts

CLI: pocdantic demo (offline), run --task TEXT --profile PROFILE (verified bearer from secret env),
batch --input FILE (JSONL), probe (read-only configuration/connectivity summary), serve (optional).
Batch output is JSONL with one independent result per input, nonzero exit if any input fails.
Server: POST /runs {task, profile}; Authorization bearer validated before any model call.
Health never returns configuration/credentials. Profiles are server-defined capability allowlists.
OAuth: form token requests; basic/post client auth, no redirects or provider failover. Exchange
requires subject and actor tokens. JWT signatures/issuer/audience/time/token purpose verified.
Vault: exact configured API paths; X-Vault-Token and optional namespace. Dynamic credentials remain
private to executor. Revoke exact lease in finally, propagate cleanup failure without raw responses.
Approval: a trusted backend observes decision; model/request JSON cannot mark approvals as approved.
Telemetry: no request body, model content, tool parameters/results or bearer tokens exported.


Optional CLI login: confidential human OIDC client, S256 PKCE, fixed loopback GET callback,
one valid state/code response, signed user API access token. Only a private token store is
written; stdout contains status, never codes/tokens.
Broker: validate user and actor independently before exchanging authority. Credential read
and exact-lease revoke use separate validated delegated grants. Cleanup is shielded and
failure propagates. No workload attestation is inferred from an OAuth client credential.
