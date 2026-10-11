# Data Model: Portable PoC Setup

## DeploymentProfile

Strict versioned model; authentication_mode is `delegated-exchange|user-jwt` (legacy default
`delegated-exchange`). Private provider URLs/secrets remain Settings inputs. trusted_hosts is
an explicit unique list of at most 16 DNS hostnames, each at most 253 characters, no schemes,
paths, wildcard, userinfo or redirects. Certificate-authority references are private validated
files; verification cannot be disabled. Requested features is a fixed capability enum, not
arbitrary endpoint/action text. Configuration fingerprint pins mode, target and trust inputs
without publishing native identifiers or secret values.

## DatabaseTarget

Private mount and role each use validated relative Vault path grammar; credentials path is
exactly `{mount}/creds/{role}`. Reject traversal, query/fragment and ambiguous mismatches with
legacy VAULT_READ_PATH. New deployments may choose another database mount; legacy path resolves
identically. Persist original target and deployment fingerprint in private acquisition records.

## CapabilityObservation

feature: baseline-sign-in, baseline-database, delegated-exchange, phone-approval, remediation,
governance or audit-export. state: configured|unverified|supported|unsupported|blocked.
evidence_level: local|advertised|demonstrated. observed_at UTC; fixed reason_code and repair_key;
owner: operator|provider-administrator|integration-owner. No provider message, URL or token fields.
Supported requires demonstrated evidence; advertisement alone is unverified. Bounded reports
contain at most 32 observations; stale observations never authorize execution.

## CredentialOwnership

Versioned journal records kind `native-user-token|database-lease`, operation UUID, route,
private exact handle when known, target/context fingerprint, attempt/cleanup state. Preserve
existing journal identities, anchors and exclusive-effect controls. State transitions:
intent -> issued -> cleanup_pending -> confirmed; lost issuance response -> uncertain;
failed cleanup -> unresolved. Two independently journaled acquisitions are linked by opaque
parent ID. Native service token TTL is positive and at most 300 seconds; lookup-self verifies an explicit
maximum TTL of 1–300 seconds and nonperiodic service type. Renewable may be true/false; no
renewal is performed. Remaining lifetime must exceed operation deadline plus 30 seconds. No completion until both cleanup dispositions are confirmed. Never place native
handles in public projections. Legacy migration is idempotent and cannot infer missing authority.

## PortabilityRun

Run UUID, private deployment identity, product/version, route and context fingerprint,
UTC capture time, actual allow/deny/login/cleanup results, software vs live classification,
private original evidence references and named reviewer. Colleague run adds measured duration,
excluded provider/human time, repeat index and undocumented-assistance count. Public projection
contains sanitized product/version, route, outcomes and limitations only. Baseline observations
never promote delegated or original vendor acceptance criteria.

## Recovery and observation compatibility details

Journal version 3 distinguishes human and actor-bound ownership without manufacturing an actor
for the standard route. Linked acquisitions retain one effect owner through both cleanup workers.
Private bearer material is SecretStr and restricted to protected recovery storage; preserve
original provider/namespace/CA/target context. Version 1/2 migration retains unresolved records.
Receipts and imports are kind-aware; successful token cleanup cannot invent a lease receipt.

Capability demonstration observations expire for readiness after 24 hours; original timestamps
remain historical and cannot be refreshed by copying/importing. Evidence from another context
never counts. Private validation records gain explicit authentication_mode and source product;
legacy delegated records retain their old interpretation. New live-portability scenarios have
no original UC mapping. A private PORTABILITY_DENIED_TOKEN is a separately verified identity
with no database:read scope, used only by the explicit negative live scenario.

Native handle capture precedes other response-property checks. Cleanup has one 30-second total
budget: at most 20 seconds lease cleanup and 10 seconds token self-revocation. Both dispositions
are independently journaled; all public completion views wait for both. Timed-out/draining
workers retain effect ownership and unresolved status until safely drained.

A child lease intent is admissible only under its captured parent token, same live effect owner,
route and deployment context. This exception does not allow unrelated acquisitions while an
intent is unresolved. Closing either child alone never reopens acquisition admission.
