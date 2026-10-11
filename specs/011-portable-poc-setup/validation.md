# Planning Validation: Portable PoC Setup

2026-10-11: specification, clarification scan, research, design, contracts and 32 tasks prepared.
No implementation or provider provisioning performed. No critical ambiguity required a question;
assumptions state the second product, two-instance proof and actual colleague participation.
Requirements review 16/16; boundary review 11/11, design only. Source inspection confirmed
ordinary Vault needs explicit JWT login and a separate credential lifecycle; endpoint trust,
provider selection and custom targets affect multiple existing trusted boundaries.

## Acceptance separation

Software validation is pending implementation. Real IBM Verify/Keycloak deployment tests and
colleague timing/repeatability are pending actual access/participation (T028–T029). Existing
fifteen vendor criteria remain blocked; baseline portability is a distinct claim.

## External prerequisites

For the second live deployment: approved HTTPS OIDC discovery and client credentials, exact
loopback callback, signed JWT audience/scope/purpose; independent Vault endpoint and optional
namespace, CA trust, administrator-configured constrained JWT auth role, SELECT-only database
credentials role, exact lease cleanup and revocable service-token support. Private configuration
and evidence must remain in ignored local storage. A real colleague is needed for the two timed
usability runs. Implementation supplies exact commands and expected results before requesting
these inputs. No fresh phone sign-in or provider change is needed for planning.

## Planning review refinements

The repeated planning pass corrected a standard-Vault incompatibility: JWT-issued service tokens
can be renewable. The contract now verifies a hard maximum lifetime and forbids renewal calls.
It also specifies role-constrained lease cleanup, recovery commands/proof for both credential
kinds, shared effect ownership and 20/10-second cleanup budgets, and completion only after both
credentials are resolved. Malformed token responses retain cleanup ownership.

Baseline browser settings exclude saved bearers and separate agent/administrative OAuth
credentials. Trust settings reach network workers. The live-portability suite and route-aware
private evidence are explicit implementation work, including a separately supplied denied test
identity. T028 and T029 remain real-deployment and colleague acceptance tasks. There are now
32 implementation/validation tasks; none are marked complete in this planning change.

Clarification scan required zero new questions. Scope, entities, user flow, nonfunctional
bounds, dependencies, failure behavior, constraints, terminology and completion are specified.
Provider configuration and actual colleague participation remain external prerequisites rather
than hidden implementation work. The source documentation links in research.md support the
compatibility decisions. No software changes, provisioning or live demonstrations were performed.


## Implementation boundary review (2026-10-11)

The explicit route is selected before issuance. Generic metadata never derives discovery from
leftover Verify administration. Human signature/issuer/audience/time/purpose and database scope
checks precede Vault login. The standard route does not use actor exchange or an operator token.
The policy example scopes provider cleanup to a dedicated role; application custody further
restricts it to the exact acquired lease. This is not native per-lease RAR enforcement.

Both native token and database lease have write-ahead intents, shared exclusive effect ownership
and independent receipts. Captured token authority is retained privately before other login
properties are validated. A malformed accessor or journal fault still triggers best-effort known
token cleanup. Lease failure does not skip self-revocation; cascade, expiry, denial and lost
responses never manufacture an independent lease receipt. Restart and changed-context tests
preserve uncertainty. Provider, namespace, target and CA fingerprints pin original custody.

Default setup creates only a non-overwriting private template or reads local state. Public network
checks are separate and cannot issue credentials. Cross-host metadata requires explicit trust;
identity and Vault use independent verified TLS contexts, including isolated cleanup/diagnostic
workers. Ordinary portability tests deny unmocked provider transports and use temporary stores.
The existing local response-control enrollment remains mandatory for effects and is explicitly
included in the setup guide; it does not enable optional provider remediation.

Native capability projection requires recent sealed provider-origin live-portability evidence,
matching original context, successful read and both native cleanup correlations. Synthetic,
foreign, stale, damaged and incomplete captures do not promote support. The original closeout
still accepts only its four delegated/phone cases. Original fifteen acceptance rows remain blocked.

## Outstanding real prerequisites and owner review

T028 remains unchecked: no independently prepared IBM Verify and Keycloak deployments with
separate Vault instances were supplied for this feature. Existing tenant access alone does not
establish the new JWT role/policy or a second deployment. Follow docs/setup.md: have each identity
administrator register the exact loopback confidential client, audience and scopes; have each
Vault/database administrator configure its constrained JWT role, role-limited synchronous
cleanup and SELECT-only credentials target. Supply those values privately in each deployment's
.env.local. Then run its documented sign-in, allowed read, denied read and recovery checks,
retaining original evidence under ignored .local/. Record actual versions and outcomes here.
No remote provisioning or fresh phone prompt was attempted by the implementation workflow.

T029 remains unchecked: an actual unfamiliar IBM colleague must perform the two fresh setup
runs. Use the same guide without undocumented assistance or source edits, record each duration,
and record/exclude only actual external waits. Self-testing cannot substitute for participation.

T032 owner boundary review remains pending. Publication/privacy review is performed against the
proposed index; the owner must review the route/policy scope, private native-token retention,
independent cleanup evidence and these live limits before merge. Implementation authorization
is not represented as review of the completed security change.


Final custody review strengthened durable token capture: persist the bearer before validating
optional accessor/request metadata, then attach provenance without changing acquisition state.
Malformed optional metadata rejects the operation but preserves exact cleanup authority and
correct acquisition/revocation counts. Capacity reserves use protected serialized bytes rather
than masked debug output, so old retained tokens cannot hide storage consumption before issuance.
Certificate inputs are bounded regular non-linked files; a pipe is rejected without waiting.
Capability reconstruction uses an explicitly read-only evidence store: no permission repair,
new lock, artifact write or source rewrite is permitted. Vault trust failures do not disable an
independently configured OIDC sign-in. These refinements have focused regression coverage.


## Final software validation (2026-10-11)

The stable implementation tree passed 1,196 tests in 161.50 seconds, including
Playwright/WebKit browser checks. Targeted CI repeatability, normalized-report budget,
readiness and closeout checks separately passed 29 tests in 4.92 seconds. The final
profile-readiness regression passed all seven setup-readiness tests.

Ruff lint and formatting passed (406 files). All eleven feature gates and runtime
configuration passed. The nine offline security scenarios passed and the synthetic demo
completed. Both-profile security regression completed 230 checks across twenty passing
case/profile results and ten passing software groups, with cleanup drained; its native
provider criteria remain blocked. The wheel/source build and distribution privacy gate
passed. No new dependency or lockfile change was required.

T031 is complete. T028, T029 and the owner-review portion of T032 remain unchecked for
the exact reasons and execution steps above. Synthetic results do not establish actual
IBMid/Keycloak interoperability, universal provider compatibility or the colleague timing
objective. This branch has not been pushed, opened as a PR or merged by implementation.

The prospective staged publication tree and Git history passed the privacy gate;
the staged diff also passed whitespace validation. Owner review is still outstanding.

## Delivery disposition (2026-10-11)

After receiving the completed implementation, validation results, remaining acceptance
limits and setup/Dependabot documentation, the repository owner explicitly requested
merge. This records the owner delivery disposition; it does not invent a GitHub approval
review or promote live acceptance. T028 and T029 remain outstanding.
