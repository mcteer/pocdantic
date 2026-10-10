# ADR 0005: Local readiness and explicit closeout

Status: Implemented; real proof and delivery gates remain open. Date: 2026-10-09.

## Decision

Readiness assesses selected-case configuration locally without tokens, leases, model calls,
phone requests, exports or persisted runs. Closeout selects explicit run UUIDs, checks sealed
private context and exact current evidence revisions, and snapshots four case slots plus
existing per-run reviews for all 15 criteria. No aggregate customer acceptance is invented.

Manual native exports remain inputs. Vault v2 reads response.secret.lease_id and rejects
conflicting legacy fields. Logfire v2 accepts row arrays, rows and schema/data row-object
responses. Project names and IDs are distinct; project_id is not universally present.
Verify Events linkage and incompatible HMAC lease comparisons remain unsupported. A phone
transaction proves its bound decision, not independent Events audit linkage; only explicit
native denial (including IBM Verify USER_DENIED) proves a witnessed denial.

## Consequences

Reuse the locked dependencies and 002 runner/store/report/review contracts. Context and
snapshot artifacts remain ignored and owner-only. Old per-run records remain readable;
missing context/approval bindings cannot be reconstructed from today's settings. Source,
code or review changes invalidate applicability. Software and real proof gates are separate.

Native examples and primary documentation are recorded in
specs/003-live-evidence-closure/research.md and contracts/runtime.md. No collector, service
administration, policy weakening, read-token runtime setting or provisioning is introduced.

## Supported native shapes

Synthetic Vault v2 credential response:

```json
{"type":"response","time":"2026-10-09T12:00:00Z","request":{"id":"synthetic-request","path":"database/creds/read"},"response":{"secret":{"lease_id":"synthetic-lease"}}}
```

Synthetic Logfire v2 row-object export:

```json
{"schema":{"fields":[{"name":"trace_id","data_type":"Utf8","nullable":false},{"name":"span_id","data_type":"Utf8","nullable":false},{"name":"start_timestamp","data_type":"Utf8","nullable":false}]},"data":[{"trace_id":"00000000000000000000000000000001","span_id":"0000000000000001","start_timestamp":"2026-10-09T12:00:00Z"}]}
```

| Mapping | Result |
| --- | --- |
| Nested Vault lease with equal legacy alias | Supported |
| Conflicting nested/top-level lease | Contradicted |
| Protected lease HMAC without comparable trusted binding | Unsupported |
| Logfire named project equal to manifest | Supported |
| Internal project ID explicitly bound by v2 manifest | Supported |
| Internal ID treated as a project name or positional data array | Unsupported |
| Bound Verify transaction approval or intentional denial | Transaction proof only |
| Verify Events event ID/correlation ID guessed as transaction ID | Unsupported |
| Phone timeout, expiry, failure or cancellation | Unverified decision |
