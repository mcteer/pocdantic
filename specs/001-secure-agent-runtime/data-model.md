# Data model

RequestEnvelope: task, request_id (UUID), profile. Identity cannot be supplied in task JSON.
AgentResponse: status, output, error_code, request_id, run_id and correlation_id from server context.
Principal: frozen issuer, subject, scopes established by JWT verification or explicit offline fixture.
AgentDefinition: durable id, instructions and allowlisted capabilities; definition IDs never use run IDs.
RunContext: principal, logical role, stable workload id, run/parent IDs and private services.
ToolAction: operation, resource and canonical parameters; immutable approval digest includes run/user.
Approval: pending -> approved/denied/expired -> consumed; atomic consumption prevents replay.
Lease: private username/password, exact lease id, TTL; always revoke after protected use.
AuditEvent: event name, request/run/agent ids, outcome and opaque references; no arbitrary payloads.
Evidence: criterion, status, owner, reviewer, source, observed time, sanitized references and reason.
