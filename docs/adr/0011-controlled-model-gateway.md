# ADR 0011: Controlled model gateway

Status: accepted for software implementation; vendor acceptance remains pending.

New live deployments use Pydantic AI Gateway with a dedicated key, exact model admission,
blocking credential protections and finite remote spending limits. Existing enrolled deployments
can explicitly retain direct mode. The slim SDK and native provider protocols remain; Google
Gateway uses cloud/Vertex and does not silently translate a GLA deployment.

An owned HTTPX2 transport strips ambient auth/headers and forbids redirects, alternate hosts
and automatic retries. Every model turn has bounded metadata and fresh local control review.
Gateway never grants tool authority or replaces trusted credential isolation or sandbox admission.
Review rejection always disables further dispatch without needing current evidence; approval
requires complete live source evidence and expires within 24 hours.

Remote inspection receives model content. Conversation/body telemetry stays disabled; metadata-only application agent traces and Gateway
diagnostics may coexist with Include messages off. Application attempts own accounting; do not
count Gateway representations again. Verify hosted presentation separately. Service-side
retention and blocking coverage require separate evidence before private-data activation. Spend
limits are soft and observed costs can be unknown. No universal secret-detection claim is made.
Remote drift cannot be continuously attested by the current API; operator change control and
expiring reviews expose that limitation. See feature 014 contracts for migration and acceptance.
