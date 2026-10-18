"""Gateway configuration cannot silently recover through ambient provider authority."""

import pytest

from agent.gateway.config import route_policy
from agent.gateway.models import GatewayError
from agent.settings import Settings


def test_mode_required():
    """Absent mode must never authorize direct provider inference."""
    with pytest.raises(GatewayError, match="model_mode_required"):
        route_policy(Settings(_env_file=None))


@pytest.mark.parametrize("model", ["google-gla:synthetic", "custom:synthetic", "openai-chat:../x"])
def test_unreviewed_gateway_model(model):
    """A protocol-qualified string is not a grant of model authority."""
    with pytest.raises(GatewayError):
        route_policy(
            Settings(
                _env_file=None,
                model_mode="gateway",
                model=model,
                gateway_region="us",
                gateway_route="synthetic",
                gateway_models=("openai-chat:synthetic",),
                gateway_api_key="synthetic-private-key",
            )
        )


def test_private_key_alias_precedence_and_closed_conflict(tmp_path, monkeypatch):
    """An environment alias wins over a file; conflicting process keys expose no values."""
    from agent.security import SecurityError

    path = tmp_path / ".env.local"
    path.write_text("GATEWAY_API_KEY=synthetic-file-key\n")
    monkeypatch.delenv("GATEWAY_API_KEY", raising=False)
    monkeypatch.setenv("LOGFIRE_GATEWAY_API_KEY", "synthetic-environment-key")
    assert (
        Settings(_env_file=path).gateway_api_key.get_secret_value() == "synthetic-environment-key"
    )
    monkeypatch.setenv("GATEWAY_API_KEY", "synthetic-conflicting-key")
    with pytest.raises(SecurityError) as error:
        Settings(_env_file=path)
    assert str(error.value) == "gateway_configuration_invalid"


def test_offline_ignores_conflicting_gateway_aliases(monkeypatch):
    """An ambient configuration conflict is not authority to break offline rehearsal."""
    from agent.settings import synthetic_settings

    monkeypatch.setenv("GATEWAY_API_KEY", "synthetic-a")
    monkeypatch.setenv("LOGFIRE_GATEWAY_API_KEY", "synthetic-b")
    assert synthetic_settings().gateway_api_key is None


def test_shared_project_key_requires_explicit_dotenv_binding(tmp_path, monkeypatch):
    """A shared project key is opt-in; telemetry configuration alone cannot select Gateway auth."""
    for name in ("GATEWAY_API_KEY", "LOGFIRE_GATEWAY_API_KEY", "LOGFIRE_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / ".env.local"
    path.write_text("LOGFIRE_TOKEN=synthetic-project-key\n")
    assert Settings(_env_file=path).gateway_api_key is None
    path.write_text("LOGFIRE_TOKEN=synthetic-project-key\nGATEWAY_API_KEY=${LOGFIRE_TOKEN}\n")
    settings = Settings(_env_file=path)
    assert settings.gateway_api_key.get_secret_value() == settings.logfire_token.get_secret_value()
    assert "synthetic-project-key" not in repr(settings)
