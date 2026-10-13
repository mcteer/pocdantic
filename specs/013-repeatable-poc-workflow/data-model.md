# Data Model: Repeatable PoC Workflow

These are planned strict Python/Pydantic boundary models, not a new storage schema. All new
models reject extra fields; catalog definitions are immutable. Reports contain names/codes only,
never configuration values, credential handles, raw exceptions, provider bodies or evidence paths.

## DemoRecipe (compiled, immutable)

- `id`: exactly `offline`, `workspace-read` or `workspace-analysis`.
- `profile`: null, `database-reader` or `database-analyst`, respectively.
- `extras`: unique ordered subset of `server`, `postgres`, `sandbox`, `google`, `openai`, `anthropic`;
  selected model extra is resolved separately for live recipes. At most six entries.
- `required_capabilities`: fixed catalog strings, at most four entries.
- `steps`: fixed ActionId sequence, at most sixteen entries.
- `proof_scope`: `synthetic` or `live-baseline`; no recipe can assert native vendor acceptance.

Offline does not inspect live settings/enrollment. workspace-analysis includes all read-route
prerequisites plus sandbox availability and the exact analyst profile; it does not grant a new
permission or replace the query compiler/broker.

## ModelDescriptor (compiled, immutable)

- `provider`: `google`, `openai`, `anthropic`.
- `prefixes`: reviewed model-prefix strings from research R3, not arbitrary plugin code.
- `extra`, `package_probes`, `credential_setting`: literal catalog entries.
- `model_kind`: preserves Google, OpenAI chat/responses, or Anthropic constructor choice.

Secrets remain in Settings SecretStr fields and are passed only into trusted constructors.
Descriptor lookup never constructs a provider. Unknown prefixes produce a guided limitation,
not a rewrite of legacy direct model resolution. No persistent credential record is added.

## PrerequisiteFinding (ephemeral)

- `id`: closed code from the compiled check catalog; stable for a given boundary/failure.
- `boundary`: `project`, `configuration`, `dependency`, `identity`, `model`, `database`,
  `sandbox`, `recovery`, `response` or `workspace`.
- `state`: `ready`, `missing`, `invalid`, `blocked` or `unverified`.
- `setting_names`: unique short names matching `[A-Z][A-Z0-9_]{0,63}`, at most 32 entries;
  only allowlisted Settings/provider/dependency names, not arbitrary input strings.
- `owner`: `operator`, `identity-administrator`, `vault-administrator`,
  `database-administrator`, `integration-owner` or `human-reviewer`.
- `action_id`: a member of ActionId below.

No free-form provider diagnostics. Human explanation is rendered from fixed catalog text.
A model key's presence is a local prerequisite, not proof that it is valid or funded.

## DeploymentObservation (ephemeral projection)

- `root_state`: `valid`, `wrong-directory` or `unavailable`.
- `recovery_state`: `not-applicable`, `absent`, `clear`, `busy`, `blocked`, `mismatch` or `invalid`.
- `response_state`: `not-applicable`, `absent`, `draft`, `enrolled`, `busy`, `held`, `mismatch` or `invalid`.

Source of truth remains the existing stores. Treat exceptions conservatively: an unreadable,
partial or unsafe store is invalid, not absent. A draft means an existing valid draft consistent
with the current deployment; it says nothing about whether a human has reviewed it. Private
incident-specific instructions stay in existing status commands, not this guide's output.

## SetupAction (ephemeral)

- `id`: one of `use-root`, `install-extras`, `edit-settings`, `check-local`, `check-network`,
  `init-recovery`, `inspect-recovery`, `prepare-policy`, `review-policy`, `enroll-response`,
  `inspect-response`, `launch-workspace`, `sign-in`, `validate-allow-deny`, `check-cleanup`,
  `run-offline`, `integration-review`.
- `effect`: `none`, `local-install`, `local-configuration`, `local-enrollment`,
  `public-network`, `live-read-and-cleanup` or `human-action`.
- `disposition`: `available`, `after-prerequisites` or `blocked`.
- `requires`: unique ActionId dependencies, at most sixteen, no self-reference or cycle.
- `owner`: same closed owner set as findings.
- `command_id`: nullable fixed command catalog ID; rendered commands contain only compiled
  literals and reviewed recipe/provider selections. Human actions need not have a command.

A guide contains at most sixteen actions even though the catalog has seventeen possible IDs.
It emits only applicable actions, e.g. offline excludes enrollment, root failure excludes launch.
No arbitrary interpolation, command text ingestion, shell dispatch or action execution exists.

## SetupGuide (public, ephemeral)

- `schema_version`: 1, distinct from existing SetupReport v1.
- `recipe`: DemoRecipe ID.
- `state`: `needs-input`, `needs-enrollment`, `needs-review`, `ready-to-launch`,
  `blocked`, or `offline-ready`.
- `proof_scope`: as above; local observation is never live proof.
- `findings`: at most 32 PrerequisiteFinding records with unique IDs.
- `actions`: at most 16 SetupAction records, unique IDs in deterministic order.
- `exit_code`: 0, 2 or 3 using the existing setup precedence: configuration/dependency/root
  repair is 2; otherwise missing/blocked enrollment/recovery/review is 3; otherwise 0.

`ready-to-launch` means local prerequisites pass, not successful sign-in/read/cleanup.
Network checks remain explicit in setup check; guide never performs them. Renderer output is
bounded to 32 KiB for either text or JSON, with fixed explanations and no raw truncation payload.
Budget exhaustion returns a closed blocked finding; it cannot manufacture readiness.

## WalkthroughMeasurement (validation record, not new runtime model)

Retain existing private validation/evidence storage practices. A sanitized summary records recipe,
software revision, environment class (synthetic/live), setup kind (fresh/repeat), actual start/end,
active elapsed duration, each excluded wait and reason, observed milestones, assistance/source
edits, software versus live outcome and review disposition. No tenant IDs or private values enter
committed summaries. Real results remain pending until a participant and original evidence exist.

## Derived state transitions and concurrency

Typical absent live installation:

`needs-input → needs-enrollment → needs-review → needs-enrollment → ready-to-launch`

The arrows describe new observations after separately executed existing commands; the guide does
not cause transitions or retain checkpoints. Busy/held/invalid/mismatch observations override
launch eligibility and offer inspection, never reset. Repeating a read-only guide cannot make a
blocked state clear. A stale guide is not authorization: each existing effect rechecks its actual
state and ownership under current locks. Offline-ready has no dependency on this state machine.
