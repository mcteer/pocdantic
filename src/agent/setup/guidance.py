"""Ephemeral state-aware setup suggestions; never execute, approve, persist or repair."""

import stat
import time
from itertools import islice
from pathlib import Path

from agent.model_config import descriptor
from agent.recovery.store import RecoveryStore
from agent.response.store import ResponseStore
from agent.settings import Settings

from .models import DeploymentObservation, PrerequisiteFinding, SetupGuide
from .recipes import ACTIONS, command


def absent(path: Path) -> bool:
    """Prove absence by lstat; errors or symlinks must not invite initialization."""
    from agent.validation.store import no_symlinks

    no_symlinks(path)
    try:
        path.lstat()
        return False
    except FileNotFoundError:
        return True


def observe(settings: Settings, *, project: Path | None = None) -> DeploymentObservation:
    """Read verified existing stores, distinguishing wholly absent, draft and damaged.

    Locks are nonblocking and already-existing. No lock or journal is created. Unknown
    failures conservatively become invalid; they are never a claim of missing state.
    """
    recovery = RecoveryStore(settings, project=project)
    response = ResponseStore(settings, project=project, recovery=recovery)
    recovery_state, response_state = "invalid", "invalid"
    try:
        if absent(recovery.root):
            recovery_state = "absent"
        else:
            # A workspace owner may be live even when its journal has no held attempts.
            with recovery._lock("workspace.lock"), recovery._lock("effect.lock"):
                view = recovery.status()
                recovery_state = "clear" if view.recovery == "clear" else "blocked"
                if view.recovery in {"storage_error", "uninitialized"}:
                    recovery_state = (
                        "mismatch"
                        if view.reason_code == "recovery_environment_mismatch"
                        else "invalid"
                    )
    except Exception as error:
        recovery_state = "busy" if str(error) == "recovery_busy" else "invalid"
    try:
        if absent(response.root):
            response_state = "absent"
        elif stat.S_ISDIR(response.root.lstat().st_mode) and {
            p.name for p in islice(response.root.iterdir(), 2)
        } == {"policy.json"}:
            response.policy()
            response_state = "draft"
        else:
            with (
                response._lock("workspace.lock"),
                response._lock("worker.lock"),
                response._lock("effect.lock"),
            ):
                state = response.read()
                held = state.holds or state.root_holds or getattr(state, "subject_holds", ())
                response_state = (
                    "held"
                    if held or any(i.phase != "settled" for i in state.incidents)
                    else "enrolled"
                )
    except Exception as error:
        code = str(error)
        response_state = (
            "busy"
            if code in {"recovery_busy", "response_busy"}
            else "mismatch"
            if code == "response_policy_changed"
            else "invalid"
        )
    return DeploymentObservation(recovery_state=recovery_state, response_state=response_state)


def guide(
    settings: Settings | None, *, recipe: str = "workspace-read", project: Path | None = None
) -> SetupGuide:
    """Return deterministic bounded suggestions from current observations, with no effects."""
    if recipe == "offline":
        return SetupGuide(
            recipe=recipe,
            state="offline-ready",
            proof_scope="synthetic",
            actions=(ACTIONS["run-offline"],),
        )
    from .readiness import local_check

    started = time.monotonic()
    report = local_check(settings, project=project, recipe=recipe)
    observation = observe(settings, project=project)
    findings, actions = [], []
    gateway_review_needed = False
    if settings.model_mode == "gateway":
        from agent.gateway.config import bindings, route_policy
        from agent.gateway.review import ReviewStore

        try:
            from pathlib import Path

            ReviewStore(Path(project or Path.cwd()).absolute()).admit(
                bindings(settings, route_policy(settings))
            )
        except Exception:
            gateway_review_needed = True

    def add(identifier, *, requires=(), owner=None):
        """Append a compiled suggestion with explicit future prerequisites."""
        updates = {
            "requires": requires,
            "disposition": "after-prerequisites" if requires else "available",
        }
        if owner:
            updates["owner"] = owner
        actions.append(ACTIONS[identifier].model_copy(update=updates))

    if report.exit_code == 2:
        names = tuple(report.missing_settings)
        unsupported = "MODEL" in names
        groups = {}
        for name in names:
            if name == "MODEL":
                key = ("model-unsupported", "model", "integration-owner", "integration-review")
            elif name.endswith("_EXTRA"):
                key = ("dependency-missing", "dependency", "operator", "install-extras")
            elif name.startswith("GATEWAY_"):
                key = ("configuration-missing", "model", "gateway-administrator", "edit-settings")
            elif name.endswith("_API_KEY"):
                key = ("model-missing", "model", "operator", "edit-settings")
            elif name.startswith(("OAUTH_", "LOGIN_")):
                key = ("identity-missing", "identity", "identity-administrator", "edit-settings")
            elif name.startswith("VAULT_"):
                key = ("vault-missing", "database", "vault-administrator", "edit-settings")
            elif name.startswith("DATABASE_"):
                key = ("database-missing", "database", "database-administrator", "edit-settings")
            else:
                key = ("configuration-missing", "configuration", "operator", "edit-settings")
            groups.setdefault(key, []).append(name)
        for (identifier, boundary, owner, action), setting_names in groups.items():
            findings.append(
                PrerequisiteFinding(
                    id=identifier,
                    boundary=boundary,
                    owner=owner,
                    state="blocked" if identifier == "model-unsupported" else "missing",
                    setting_names=tuple(setting_names),
                    action_id=action,
                )
            )
        if not findings:
            findings.append(
                PrerequisiteFinding(
                    id="configuration-invalid",
                    boundary="configuration",
                    state="invalid",
                    action_id="edit-settings",
                )
            )
        if any(name.endswith("_EXTRA") for name in names):
            add("install-extras")
        if unsupported:
            add("integration-review")
        # A model migration can coexist with missing inputs. Keep both repairs
        # visible and make the recheck depend on every required prerequisite.
        if not unsupported or any(f.action_id == "edit-settings" for f in findings):
            add("edit-settings")
        add("check-local", requires=tuple(a.id for a in actions))
        state, exit_code = "needs-input", 2
    elif observation.recovery_state not in {"clear", "absent"} or observation.response_state in {
        "busy",
        "held",
        "mismatch",
        "invalid",
    }:
        add("inspect-recovery")
        add("inspect-response")
        findings.append(
            PrerequisiteFinding(
                id="recovery-state",
                boundary="recovery",
                state="blocked",
                action_id="inspect-recovery",
            )
        )
        state, exit_code = "blocked", 3
    elif gateway_review_needed:
        add("gateway-review")
        findings.append(
            PrerequisiteFinding(
                id="gateway-review",
                boundary="model",
                state="unverified",
                owner="gateway-administrator",
                action_id="gateway-review",
            )
        )
        state, exit_code = "needs-review", 3
    else:
        if observation.response_state in {"absent", "draft"}:
            add("check-network")
            if observation.recovery_state == "absent":
                add("init-recovery", requires=("check-network",))
            dependency = (
                ("init-recovery",) if observation.recovery_state == "absent" else ("check-network",)
            )
            if observation.response_state == "absent":
                add("prepare-policy", requires=dependency)
                dependency = ("prepare-policy",)
            add("review-policy", requires=dependency)
            add("enroll-response", requires=("review-policy",))
            add("check-local", requires=("enroll-response",))
            state = (
                "needs-review"
                if observation.response_state == "draft" and observation.recovery_state == "clear"
                else "needs-enrollment"
            )
            exit_code = 3
        else:
            add(
                "check-local",
                requires=("init-recovery",) if observation.recovery_state == "absent" else (),
            )
            add("check-network", requires=("check-local",))
            add("launch-workspace", requires=("check-network",))
            add("sign-in", requires=("launch-workspace",))
            add("validate-allow-deny", requires=("sign-in",))
            add("check-cleanup", requires=("validate-allow-deny",))
            state, exit_code = "ready-to-launch", 0
    if time.monotonic() - started > 2:
        return SetupGuide(
            recipe=recipe,
            state="blocked",
            proof_scope="live-baseline",
            exit_code=2,
            findings=(
                PrerequisiteFinding(
                    id="budget-exhausted",
                    boundary="configuration",
                    state="blocked",
                    action_id="check-local",
                ),
            ),
        )
    return SetupGuide(
        recipe=recipe,
        state=state,
        proof_scope="live-baseline",
        findings=tuple(findings),
        actions=tuple(actions),
        exit_code=exit_code,
    )


def render(result: SetupGuide, *, format: str = "text", settings: Settings | None = None) -> str:
    """Render bounded literal commands; never interpolate private values or raw errors."""
    if format == "json":
        output = result.model_dump_json()
    elif format == "text":
        info = descriptor(settings.model) if settings else None
        provider = info.provider if info else None
        lines = [f"Recipe: {result.recipe}; state: {result.state}; proof: {result.proof_scope}"]
        from .prerequisites import setting_source

        for finding in result.findings:
            names = (
                tuple(
                    name + " [" + setting_source(settings, name) + "]"
                    for name in finding.setting_names
                )
                if settings
                else finding.setting_names
            )
            lines.append(f"{finding.id} (owner: {finding.owner}): " + ", ".join(names))
        for action in result.actions:
            value = (
                command(action.command_id, recipe=result.recipe, provider=provider)
                if action.command_id
                else action.id
            )
            lines.append(
                f"{action.disposition}: {value} (owner: {action.owner}; effect: {action.effect})"
            )
        output = "\n".join(lines)
    else:
        raise ValueError("invalid_guide_format")
    if len(output.encode()) > 32768:
        raise ValueError("guide_output_exceeded")
    return output
