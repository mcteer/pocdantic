"""Selected private-file credentials must reach only the trusted selected constructor."""

import pytest
from pydantic import SecretStr

from agent.model_config import descriptor, selected_model
from agent.settings import Settings


@pytest.mark.parametrize(
    "prefix,provider,kind,key",
    [
        ("google-gla", "google", "google", "GOOGLE_API_KEY"),
        ("openai", "openai", "chat", "OPENAI_API_KEY"),
        ("openai-chat", "openai", "chat", "OPENAI_API_KEY"),
        ("openai-responses", "openai", "responses", "OPENAI_API_KEY"),
        ("anthropic", "anthropic", "anthropic", "ANTHROPIC_API_KEY"),
    ],
)
def test_selected_private_key(tmp_path, monkeypatch, prefix, provider, kind, key):
    """Keys supplied in dotenv need no duplicate shell export; no network is performed."""
    for name in ("GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / ".env.local"
    path.write_text(f"MODEL={prefix}:synthetic\n{key}=synthetic-private-key\n")
    settings = Settings(_env_file=path)
    info = descriptor(settings.model)
    assert (info.provider, info.model_kind, info.credential_setting) == (provider, kind, key)
    assert isinstance(getattr(settings, key.lower()), SecretStr)
    model = selected_model(settings)
    assert model.model_name == "synthetic"
    assert "synthetic-private-key" not in repr(settings)
    monkeypatch.setenv(key, "synthetic-environment-key")
    assert (
        getattr(Settings(_env_file=path), key.lower()).get_secret_value()
        == "synthetic-environment-key"
    )


def test_unknown_legacy_resolution():
    """Custom direct runtime resolution is preserved but guidance has no descriptor."""
    settings = Settings(_env_file=None, model="custom:example")
    assert descriptor(settings.model) is None
    assert selected_model(settings) == "custom:example"


def test_names_only_source_diagnostics(tmp_path, monkeypatch):
    """Source labels contain no input value and flag multiple legacy environment names."""
    from agent.setup.prerequisites import setting_source

    path = tmp_path / ".env.local"
    path.write_text("OPENAI_API_KEY=synthetic-private-key\n")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = Settings(_env_file=path)
    assert setting_source(settings, "OPENAI_API_KEY") == "local-input"
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-environment-key")
    assert setting_source(settings, "OPENAI_API_KEY") == "environment"
    monkeypatch.setenv("TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("POCDANTIC_TIMEOUT_SECONDS", "50")
    assert setting_source(settings, "TIMEOUT_SECONDS") == "multiple-environment-aliases"
    with pytest.raises(ValueError, match="invalid_setting_name"):
        setting_source(settings, "untrusted-value")
