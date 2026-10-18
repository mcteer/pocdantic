"""Immutable reviewed recipes and literal commands; this module never dispatches effects."""

from types import MappingProxyType

from .models import DemoRecipe, SetupAction

RECIPES = MappingProxyType(
    {
        "offline": DemoRecipe(id="offline", steps=("run-offline",)),
        "workspace-read": DemoRecipe(
            id="workspace-read",
            profile="database-reader",
            extras=("server", "postgres"),
            required_capabilities=("database-read",),
            steps=(
                "install-extras",
                "edit-settings",
                "check-local",
                "check-network",
                "init-recovery",
                "prepare-policy",
                "review-policy",
                "enroll-response",
                "launch-workspace",
                "sign-in",
                "validate-allow-deny",
                "check-cleanup",
            ),
            proof_scope="live-baseline",
        ),
        "workspace-analysis": DemoRecipe(
            id="workspace-analysis",
            profile="database-analyst",
            extras=("server", "postgres", "sandbox"),
            required_capabilities=("sandbox-python",),
            steps=(
                "install-extras",
                "edit-settings",
                "check-local",
                "check-network",
                "init-recovery",
                "prepare-policy",
                "review-policy",
                "enroll-response",
                "launch-workspace",
                "sign-in",
                "validate-allow-deny",
                "check-cleanup",
            ),
            proof_scope="live-baseline",
        ),
    }
)
COMMANDS = MappingProxyType(
    {
        "offline": "uv run --no-sync agent demo",
        "check-local": "uv run --no-sync agent setup check",
        "check-network": "uv run --no-sync agent setup check --network",
        "init-recovery": "uv run --no-sync agent recover init",
        "inspect-recovery": "uv run --no-sync agent recover status",
        "prepare-policy": "uv run --no-sync agent respond init --prepare",
        "enroll-response": "uv run --no-sync agent respond init",
        "inspect-response": "uv run --no-sync agent respond status",
        "launch-workspace": "uv run --no-sync agent workspace",
        "check-cleanup": "uv run --no-sync agent recover status",
    }
)
ACTIONS = MappingProxyType(
    {
        identifier: SetupAction(id=identifier, command_id=identifier, effect=effect)
        for identifier, effect in (
            ("check-local", "none"),
            ("check-network", "public-network"),
            ("init-recovery", "local-enrollment"),
            ("inspect-recovery", "none"),
            ("prepare-policy", "local-configuration"),
            ("enroll-response", "local-enrollment"),
            ("inspect-response", "none"),
            ("launch-workspace", "live-read-and-cleanup"),
            ("check-cleanup", "none"),
        )
    }
    | {
        "run-offline": SetupAction(id="run-offline", command_id="offline"),
        "use-root": SetupAction(id="use-root"),
        "edit-settings": SetupAction(id="edit-settings", effect="local-configuration"),
        "install-extras": SetupAction(
            id="install-extras", command_id="install-extras", effect="local-install"
        ),
        "review-policy": SetupAction(
            id="review-policy", effect="human-action", owner="human-reviewer"
        ),
        "sign-in": SetupAction(id="sign-in", effect="human-action", owner="human-reviewer"),
        "validate-allow-deny": SetupAction(
            id="validate-allow-deny", effect="live-read-and-cleanup"
        ),
        "gateway-review": SetupAction(
            id="gateway-review", effect="human-action", owner="gateway-administrator"
        ),
        "integration-review": SetupAction(
            id="integration-review", effect="human-action", owner="integration-owner"
        ),
    }
)


def command(
    identifier: str, *, recipe: str = "workspace-read", provider: str | None = "google"
) -> str:
    """Render only catalog literals after closed recipe/provider selection validation."""
    selected = RECIPES[recipe]
    if provider not in {None, "google", "openai", "anthropic"}:
        raise KeyError(provider)
    if identifier == "install-extras":
        extras = selected.extras + (
            (provider,) if recipe != "offline" and provider is not None else ()
        )
        return "uv sync --locked --no-dev" + "".join(" --extra " + extra for extra in extras)
    value = COMMANDS[identifier]
    if identifier in {"check-local", "check-network"}:
        value += " --recipe " + selected.id
    return value
