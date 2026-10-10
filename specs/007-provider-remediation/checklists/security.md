# Security design review: Provider detection and remediation

Reviewed 2026-10-10 against constitution 1.2.0, the data model and runtime contract.
Checked means specified in this design, not implemented, externally certified or owner-approved.

- [x] Native source authentication, collector evidence and detection correctness are distinct.
- [x] Native source uses pinned issuer and separate audience/namespace; no browser authority or guessed VIP API.
- [x] Bounded scalar projections cannot execute expressions, fetch URLs or select administrative targets.
- [x] Exact source/rule/resource plus prospective trusted correlation determines a root; policy need not pre-enroll ephemeral root IDs.
- [x] Replay, stale event, changed content, policy races and capacity fail before effects.
- [x] Local/root/definition/subject holds commit before provider dispatch; no network wait holds the control lock.
- [x] Shared registration, user and static controls cannot widen a root-only incident.
- [x] Actor identity is distinct from human subject; external JWTs are not native Vault tokens.
- [x] Accessor ownership is prospective and exclusive; batch/shared/unknown paths remain limitations.
- [x] Provider token cascade and dynamic lease cleanup reconcile without inventing receipts or duplicate effects.
- [x] Verify session deletion, tenant suspension, application logout and upstream IBMid are separate outcomes.
- [x] Direct DB termination is restricted to isolated enrolled static roles, with PID/backend-start rechecks and documented native fencing limits.
- [x] Dynamic lease records never gain guessed DB usernames; existing Vault revocation SQL requires installed-state confirmation.
- [x] Same-JWT/fresh issuance proof has independent healthy controls and uses durable probe intent plus crash-safe adoption for unexpected credential cleanup.
- [x] Independent open-session probes cannot mistake application cancellation for native DB closure.
- [x] Inert proof sessions release effect ownership while awaiting events, preventing responder deadlock.
- [x] Intent, resource generation fences, inherited descriptors and uncertainty survive crashes and lost replies.
- [x] Readiness/status/reconcile cannot rotate, suspend, send, terminate, issue credentials or silently retry.
- [x] Explicit retry creates linked history and rechecks changed sessions/resources; no uncertainty reset.
- [x] Migration atomically preserves original authority/history, and old binaries reject schema 2.
- [x] Secret references/destinations are fixed/private; redirects, raw errors and ambient proxy authority are excluded.
- [x] Teams acceptance and delivery differ; timeout cannot trigger automatic duplicate notices.
- [x] Evidence imports bind digests, environment, implementation, policy, action and review; no automatic acceptance promotion.
- [x] Timing requires bounded clocks and a worst-case interval below baseline, not assumed precision.
- [x] Recovery requires proven old-credential lifetime safety, never unsupported actor-configuration changes; external restoration and local fresh-generation release are separate.
- [x] Session-owned UI, closed telemetry and renamed-private-file publication tests cover new shapes.
- [x] Resource, queue, call, evidence and retention bounds include space reserved for uncertain results.
- [x] Offline tests never require live configuration; live control actions require separate explicit authorization.
- [x] Unavailable audit and absent native enrollment remain capability limitations with concrete instructions.

No constitution exception requested. A trusted local administrator remains an assumption;
file anchors and advisory locks cannot defend against rewriting all application/state files.
Native acceptance and maintainer security review remain separate delivery gates.
