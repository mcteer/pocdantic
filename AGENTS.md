# Guidance for coding tools

This file applies throughout the repository. Follow explicit task scope and preserve
unrelated work. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[project constitution](.specify/memory/constitution.md) before changing behavior.

## Project map

- `src/agent/`: Python runtime, identity verification, policy, approvals, and trusted adapters.
- `src/agent/workspace/`: local browser workspace; static assets use plain JavaScript and CSS.
- `src/agent/validation/`: deterministic scenarios, private evidence, readiness, and closeout.
- `tests/`: unit and integration checks; `tests/browser/` uses Playwright with WebKit.
- `config/`: sanitized profiles and schemas; tenant settings belong in local configuration.
- `specs/`: versioned requirements, plans, contracts, tasks, and sanitized validation records.
- `docs/adr/`: architecture decisions. `docs/usage.md` and `docs/configuration.md` hold details
  that would make the README too long.
- `scripts/`: quality gates and explicitly invoked local provisioning tools.

Use `agent` for CLI examples and short environment-variable names from `.env.example`.
Preserve documented legacy aliases unless a task explicitly changes compatibility.
Keep examples synthetic and avoid personal names, tenant identifiers, and repeated branding.

## Development

Use Python 3.12+ and the committed `uv.lock`. Install only the extras needed for the task.
The CI environment is reproduced with:

```sh
uv sync --locked --extra server --extra logfire --extra postgres --group dev --group browser
uv run --group browser playwright install webkit
```

Behavior changes follow specification → clarification → plan/research/contracts →
requirements review → tasks → consistency analysis → implementation → validation.
Use the available Spec Kit skills when requested. Select the intended `specs/` feature;
`.specify/feature.json` is an ignored local pointer, not a shared source of truth.
Do not implement when the requested scope ends at planning. Small documentation fixes
need documentation validation rather than a new feature specification.

Use typed Python, strict boundary models, small provider-independent adapters, and the
existing package structure. Add dependencies only with a stated purpose, license review,
and lockfile update. No project license has been selected; do not assume redistribution
rights for third-party material.

Document each maintained source module and function so a contributor unfamiliar with
the system can understand its purpose. Explain inputs, outputs, side effects, and failure
behavior where they are not obvious from the signature. Comment the reasons for security
checks, ordering, cancellation, and cleanup decisions; avoid comments that merely repeat
the next statement. Keep documentation accurate when behavior changes. Use docstrings
for Python and appropriate function/module comments for JavaScript and scripts.

## Security and evidence

- Derive identity from verified credentials and authorize every effect deterministically.
  Model output never grants authority. Child permissions must remain narrower.
- Keep tokens, passwords, native credential handles, and raw provider responses in trusted
  adapters or approved private evidence storage. Never put them in prompts, browser
  responses, exception text, traces, fixtures, or committed documentation.
- Keep `.env.local`, `.local/`, customer documents, browser traces, and source-system
  evidence out of Git and distributions. Use sanitized summaries for review.
- Preserve execution bounds, exact-action approvals, cancellation containment, and cleanup.
  Uncertain issuance or cleanup must not be reported as success. Do not replay effects to
  diagnose failures or bypass blocks by clearing local state.
- Use fixed parameterized SQL and least-privilege grants. Ordinary tests must not call live
  providers, send phone prompts, provision services, or change remote configuration.
- Synthetic tests prove application behavior. Vendor acceptance requires live source
  evidence and explicit review; record unsupported or unavailable checks as blocked.
- For authorized browser work, use Playwright/WebKit. If human authentication or a provider
  action is necessary, give the exact link, steps, and expected result. Reuse existing
  authorization; do not repeatedly ask for permission already granted.

## Validation and delivery

Run focused checks while editing. Behavior changes need meaningful regression tests;
authorization and adapter changes also need negative, cancellation, cleanup, and replay
coverage. Before delivery, run the applicable gates from `.github/workflows/ci.yml`:

```sh
python3 scripts/check_privacy.py --history
uv run python scripts/check_gates.py --all-features
uv run python scripts/check_gates.py --runtime-only
uv run ruff check .
uv run ruff format --check .
uv run --group browser pytest -q
uv run agent validate run
uv run agent demo
uv build
uv run python scripts/check_distribution.py
```

CI includes additional targeted repeatability and readiness/closeout checks; its workflow
is the authoritative command list. Documentation-only work needs artifact, link, and
privacy validation; rerun affected tests if a supporting gate changes.

The privacy gate reads the Git index and history. Inspect `git diff --cached` and rerun
it against the proposed publication tree. `scripts/publish_policy.py` uses an explicit
allowlist; review any expansion and keep it as narrow as the requested artifact.

Trace completion to acceptance criteria and report software results separately from live
limitations. Update public usage/configuration guidance for behavior changes and record
migration steps. Never mark unexecuted tasks or unverified acceptance criteria complete.

PRs need a concise problem/result summary, validation, compatibility impacts, and remaining
live limitations. Follow the constitution's maintainer-review and branch-protection rules;
green CI alone does not authorize merging. Push, merge, publish, or change provider state
only within the user's requested scope.
