"""Closed ephemeral contracts prevent guidance from acquiring arbitrary authority."""

import pytest
from pydantic import ValidationError

from agent.setup.models import DemoRecipe, SetupAction, SetupGuide, SetupReport
from agent.setup.recipes import RECIPES, command


def test_catalog_is_closed_and_immutable():
    """Only the three reviewed recipes and literal command IDs are accepted."""
    assert tuple(RECIPES) == ("offline", "workspace-read", "workspace-analysis")
    with pytest.raises(TypeError):
        RECIPES["other"] = RECIPES["offline"]
    with pytest.raises(ValidationError):
        DemoRecipe(id="other")
    with pytest.raises(KeyError):
        command("echo-secret")


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": 2},
        {"extra": "private"},
        {"actions": [{"id": "run-offline", "requires": ["run-offline"]}]},
        {"actions": [{"id": "run-offline"}, {"id": "run-offline"}]},
        {
            "actions": [
                {"id": "run-offline", "requires": ["check-local"]},
                {"id": "check-local", "requires": ["run-offline"]},
            ]
        },
        {
            "findings": [
                {
                    "id": "configuration-missing",
                    "boundary": "configuration",
                    "state": "missing",
                    "setting_names": ["SECRET_VALUE"],
                    "action_id": "edit-settings",
                }
            ]
        },
    ],
)
def test_guide_rejects_untrusted_structure(change):
    """Invalid schemas, duplicate IDs, cycles and unreviewed names fail validation."""
    with pytest.raises(ValidationError):
        SetupGuide(recipe="offline", state="offline-ready", proof_scope="synthetic", **change)


def test_existing_report_stays_v1():
    """The additive guide cannot change the established setup report wire schema."""
    assert SetupReport(observations=()).model_dump() == {
        "schema_version": 1,
        "observations": (),
        "missing_settings": (),
        "instructions": (),
        "exit_code": 0,
    }
    with pytest.raises(ValidationError):
        SetupAction(id="run-offline", command_id="arbitrary")


@pytest.mark.parametrize("timeout,expected", [(0.5, True), (1, False), (180, False), (181, True)])
def test_prerequisite_timeout(timeout, expected):
    """Workspace timeout admission uses the same closed bounds as launch."""
    from agent.settings import synthetic_settings
    from agent.setup.prerequisites import common

    settings = synthetic_settings().model_copy(
        update={"timeout_seconds": timeout, "model": "custom:x"}
    )
    assert ("TIMEOUT_SECONDS" in common(settings, supplied_model=True)) is expected


def test_missing_selected_key_and_unsupported_model():
    """Guidance cannot promote an unknown integration or empty selected key."""
    from pydantic import SecretStr

    from agent.settings import synthetic_settings
    from agent.setup.prerequisites import common

    settings = synthetic_settings().model_copy(
        update={"model": "openai:synthetic", "openai_api_key": SecretStr("")}
    )
    assert "OPENAI_API_KEY" in common(settings)
    assert "MODEL" in common(settings.model_copy(update={"model": "custom:x"}), guided=True)
    assert "MODEL" not in common(settings.model_copy(update={"model": "custom:x"}))


@pytest.mark.parametrize(
    "extra,package",
    [
        ("server", "fastapi"),
        ("postgres", "psycopg"),
        ("openai", "openai"),
        ("sandbox", "pydantic_monty"),
    ],
)
def test_recipe_dependency_matrix(extra, package, monkeypatch):
    """A selected missing package blocks preflight; optional sandbox leaves reads alone."""
    from pydantic import SecretStr

    from agent.settings import synthetic_settings
    from agent.setup import prerequisites

    settings = synthetic_settings().model_copy(
        update={
            "model": "openai:synthetic",
            "openai_api_key": SecretStr("synthetic"),
        }
    )
    monkeypatch.setattr(prerequisites, "package_present", lambda name: name != package)
    analysis = prerequisites.recipe_missing(settings, "workspace-analysis")
    assert extra.upper() + "_EXTRA" in analysis
    reads = prerequisites.recipe_missing(settings, "workspace-read")
    assert ("SANDBOX_EXTRA" in reads) is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("extras", ["server"] * 7),
        ("required_capabilities", ["database-read"] * 5),
        ("steps", ["check-local"] * 17),
    ],
)
def test_recipe_collection_bounds(field, value):
    """Oversized and duplicate collections never enter compiled recipe definitions."""
    with pytest.raises(ValidationError):
        DemoRecipe(id="workspace-read", **{field: value})


def test_guide_and_action_collection_limits():
    """Both record collections and dependency arrays retain their advertised ceilings."""
    from agent.setup.models import PrerequisiteFinding

    finding = PrerequisiteFinding(
        id="local-ready", boundary="workspace", state="ready", action_id="check-local"
    )
    for change in ({"findings": [finding] * 33}, {"actions": [SetupAction(id="check-local")] * 17}):
        with pytest.raises(ValidationError):
            SetupGuide(recipe="offline", state="offline-ready", proof_scope="synthetic", **change)
    with pytest.raises(ValidationError):
        SetupAction(id="check-local", requires=["run-offline"] * 17)
    with pytest.raises(ValidationError):
        SetupReport(observations=(), extra="unreviewed")


def test_catalog_commands_are_complete_and_only_compiled():
    """Every action references either a literal command or an explicit human handoff."""
    from agent.setup.recipes import ACTIONS

    assert len(ACTIONS) == 18
    for action in ACTIONS.values():
        if action.command_id:
            for recipe in RECIPES:
                for provider in ("google", "openai", "anthropic"):
                    text = command(action.command_id, recipe=recipe, provider=provider)
                    assert text.startswith(("uv run --no-sync agent ", "uv sync --locked --no-dev"))
                    assert "\n" not in text and ";" not in text
