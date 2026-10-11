# Contributing to PoCdantic

PoCdantic is maintained by the project maintainers. Contributions should preserve its reusable,
identity-aware agent harness and keep customer configuration outside the code.

Coding tools should also read [AGENTS.md](AGENTS.md) for repository-specific guidance.

## Before starting

For a bug, describe expected and actual behavior, package/Python versions and a
minimal reproduction using synthetic data. Discuss a substantial feature in an issue
first, including acceptance criteria and compatibility impact. Search existing issues
and PRs. Small documentation fixes can go directly to a PR.

Never include customer documents, tenant identifiers, credentials, tokens, private
traces or live evidence in issues, PRs, screenshots, commits or build artifacts.
Report vulnerabilities privately. If GitHub private vulnerability reporting is enabled,
use **Security → Report a vulnerability**; otherwise agree on a private channel with
the maintainer before sharing sensitive details.

There is currently no LICENSE file. Do not assume an open-source license or a right
to redistribute. Resolve licensing with the maintainer before submitting third-party
material; this guide does not grant additional rights.

## Development environment

Use Python 3.12+ and uv. Fork the repository, clone your fork and create a focused branch
from the default branch. Use your normal Git identity.

~~~sh
uv sync --locked --extra server --extra logfire --extra postgres --group dev --group browser
uv run --group browser playwright install webkit
scripts/install-hooks.sh
uv run agent demo
~~~

Tests and the offline demo need no customer credentials. Install provider extras only
when testing a provider. Use .env.local only for authorized live checks; never commit it.
Do not run live provisioning as part of a normal test or PR.

Use the committed lockfile. For dependency changes, edit pyproject.toml, run
uv lock, and review the diff. Explain the dependency's purpose, optional/base placement,
license and compatibility impact.

## Design and Spec Kit

Behavior changes follow these steps:

1. Describe the problem, acceptance criteria and non-goals.
2. Clarify identity, authorization, data classification and failure behavior.
3. Plan architecture and contracts, including compatibility and migration effects.
4. Review requirements and security checklists.
5. Create tasks that trace to requirements and run consistency analysis.
6. Resolve critical findings before implementation.
7. Implement focused changes, validate and obtain maintainer review.

GitHub Spec Kit artifacts are versioned with the project. The secure-poc workflow includes
requirements, design, analysis and validation review gates. Constitution version 1.2.0
defines project rules. Install the Specify CLI separately and register the shared workflow:

~~~sh
specify workflow add --dev .specify/workflows/secure-poc/workflow.yml
specify workflow run secure-poc --input "spec=Sanitized change description"
~~~

Commit sanitized specifications, plans, contracts, checklists, tasks and ADRs with the
implementation. Keep decisions traceable to acceptance criteria and tests.
Use [docs/adr](docs/adr/README.md) for significant architecture decisions and record
supersession rather than rewriting historical decisions.

Customer documents, .env.local, .local/, raw evidence and machine-local integration
state stay excluded. Do not initialize tooling into tracked paths without reviewing
its output. Documentation-only fixes do not need a full feature specification.

The constitution requires:

- Pydantic AI Slim as the base; integrations added through optional extras.
- Verified identity and deterministic authorization for every effect.
- Narrower child permissions, bounded execution and stable definition identities.
- Credentials confined to trusted adapters, never model messages or telemetry.
- Exact-action, expiring, single-use approvals and reliable lease cleanup.
- Reviewed live evidence before claiming external product enforcement.

## Implementation conventions

### Finding your way through the code

Start with [the offline demo](src/agent/demo.py) and run `uv run agent demo` to
see a task delegate a ticket read without credentials or network access. Then follow
these paths; module and function docstrings explain the local contracts.

| Question | Start here |
| --- | --- |
| How does a task become a bounded agent run? | [CLI](src/agent/cli.py) → [runtime](src/agent/runtime.py) → [capabilities](src/agent/capabilities.py) |
| What grants permission to a tool? | [Verified identity](src/agent/oauth.py), [policy](src/agent/security.py), and [single-use approval](src/agent/approval.py) |
| How does browser sign-in work? | [Workspace routes](src/agent/workspace/app.py) → [login verification](src/agent/workspace/auth.py) → [sessions](src/agent/workspace/sessions.py) |
| What happens during sign-out or an uncertain submission? | [Job manager](src/agent/workspace/runs.py), [HTTP boundary](src/agent/workspace/security.py), and [browser code](src/agent/workspace/static/app.js) |
| Where do database passwords come from, and who cleans them up? | [Delegation broker](src/agent/broker.py) → [Vault lease lifecycle](src/agent/vault.py) |
| How are software checks separated from live proof? | [Scenario runner](src/agent/validation/runner.py), [reports](src/agent/validation/report.py), and [closeout](src/agent/validation/closeout.py) |
| What can leave the process in telemetry or evidence? | [Telemetry filter](src/agent/telemetry.py), [observers](src/agent/observability.py), and [private storage](src/agent/validation/store.py) |

A **principal** is identity derived from a verified token, including its scopes
(granted permissions). A **capability** is a tool made available to a profile; policy
still checks permission at execution. A **lease** is a provider handle for temporary
credentials that must be cleaned up. **Containment** blocks and cancels local work;
it does not by itself revoke a provider's credentials. An acknowledged provider request
is different from independently observed completion.

When changing code, document purpose, meaningful inputs/outputs, side effects, and
failure behavior. Explain why security checks or cleanup must happen in a particular
order. Avoid narrating obvious statements. Registered tool docstrings are also sent
to the model, so editing them changes the model's tool instructions. Document their
implementation with surrounding comments when that contract should stay stable.

Validation revisions hash implementation bytes, including comments. A documentation
change can therefore make old private evidence stale; do not rewrite that evidence
to make it appear current.

Use typed Python, Pydantic boundary models, reviewed capabilities and provider-independent
adapters. Keep tenant settings configurable. Use fixed parameterized SQL and least-privilege
database grants. Return safe error codes; upstream errors can contain secrets.

Behavior changes need meaningful regression and negative-boundary tests. Cover cancellation,
cleanup, denied access and replay when relevant. Deterministic tests must not depend on live
services; mocks establish application contracts, not vendor enforcement.
Live tests require authorized resources and private source-system evidence.

Update README.md and .env.example for changed configuration or behavior.
Describe breaking changes and migration steps. Preserve public contracts unless
the change explicitly calls for a versioned compatibility break.

## Required validation

Run the same software gates as CI:

~~~sh
python3 scripts/check_privacy.py --history
uv run python scripts/check_gates.py --all-features
uv run python scripts/check_gates.py --runtime-only
uv run ruff check .
uv run ruff format --check .
uv run --group browser pytest -q
uv run agent demo
uv build
uv run python scripts/check_distribution.py
~~~

Privacy checks inspect the Git index and tracked history. Review git diff --cached
and rerun the privacy gate after staging. The allowlist in scripts/publish_policy.py
rejects unexpected files even if force-added. Explain and review allowlist changes.

The default local gate selects the current machine-local feature when present.
Use --all-features for CI parity or --feature-directory to select a feature explicitly.
No machine-local pointer is needed in a fresh checkout.
A software pass does not close an external customer acceptance gate.

## Pull requests

Keep PRs focused and use the supplied template. Include the problem, resulting behavior,
related issue, acceptance criteria, validation and compatibility impact. Use synthetic
examples. Explain security-boundary changes and unresolved live integration limitations.
Do not attach confidential source evidence.

Before requesting review, ensure only harness/support files are in the diff and required
checks pass. Address comments and resolve conversations. The maintainer decides readiness
to merge; CI success alone is insufficient. Review new pushes after approval.

Maintainers should configure the default branch to require the validate status check,
code-owner review, dismissed stale approvals and resolved conversations. Block force
pushes and deletion. Local hooks can be bypassed and do not enforce server-side merge
policy. These are operational prerequisites, not a claim that protection is enabled.

## Release and dependency maintenance

Before release, the maintainer reviews dependency/license changes, records a versioned
change summary and migration notes, and verifies wheel/sdist contents.
Use semantic versioning; pre-1.0 consumers should expect explicitly documented compatibility
changes. Publish only after an explicit maintainer decision.

Triage vulnerabilities privately, assess affected versions, rotate exposed credentials
and coordinate remediation/disclosure. Removing a secret from the latest revision
does not remove it from history or invalidate it.

These practices are informed by [NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final),
[GitHub protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
and [GitHub Spec Kit](https://github.com/github/spec-kit).
They do not constitute a compliance certification.

## Validation harness checks

Run `uv run agent validate run` alongside the existing offline demo. CI also exercises ten
consecutive unique runs (at most 30 seconds each), two synthetic profile configurations and
10,000-event report assembly (at most five seconds excluding I/O). Tests deny network with poisoned
provider/OTel environment variables. No live credentials or phone requests belong in CI.

Keep generated source/transaction evidence, journals, reports and review records beneath ignored
`.local/`; publication guards reject these files even when force-added elsewhere. Review only a
sanitized validation ledger and prospective diff. Explicit local reviews are evidence-digest bound
and do not authenticate the reviewer or automatically update acceptance.json. Unsupported native
linkage remains blocked. Changes preserve CLI/runtime contracts; telemetry hosts now inject the
returned provider object rather than depending on global Logfire configuration. No new dependency
is introduced by feature 002. The optional live adapters and exporter still use existing extras.

## Security regression checks

After the locked development sync above, list the reviewed security catalog and run it:

```sh
uv run python scripts/run_security_regression.py list
uv run python scripts/run_security_regression.py run
uv run python scripts/run_security_regression.py run --case approval-effects --profile restricted
uv run python scripts/run_security_regression.py report --run UUID
```

The full command runs both actual fixed policies: baseline permits POC/ALT ticket projects;
restricted permits POC only. Partial selections explicitly leave omitted groups incomplete.
Use the returned UUID to inspect a run. Changed source, tests, policies or lock bytes make
previous evidence historical. Preserve failed and incomplete runs; inspection never resumes
or erases them. Exit 0 means every selected software assertion passed on current bytes;
1 means failure or integrity/drift contradiction; 2 means incomplete or unavailable checks;
130 means interruption after bounded cleanup. Reproduce failures using their compiled commands.

The contributor script adds no installed runtime command, dependency or environment setting.
It snapshots maintained files, disables dotenv and provider dispatch before collection, and
runs only compiled selectors. It bounds execution to 600 seconds with 10 seconds of drain.
The guards protect trusted tests against accidental effects, not malicious Python executing
with your user privileges. Browser and uncontrolled subprocess tests remain in full pytest/CI.
Generated normalized records belong only in ignored `.local/security-regression/`; no raw
pytest logs or parameter strings are retained. Never attach private generated records to a PR.

All ten native checks stay blocked and name their provider owner, missing prerequisite,
concrete action and expected recheck. Follow the existing separately authorized native workflows
linked in [the contract](specs/009-security-regression/contracts/runtime.md#native-function-12-dispositions).
Demo-tier native audit is unavailable; synthetic success cannot promote customer acceptance.
