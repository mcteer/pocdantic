from agent.settings import Settings


def test_short_names_precede_legacy_names(monkeypatch):
    monkeypatch.setenv("MODEL", "short-model")
    monkeypatch.setenv("POCDANTIC_MODEL", "legacy-model")
    monkeypatch.setenv("OAUTH_CLIENT_ID", "short-client")
    monkeypatch.setenv("POCDANTIC_OAUTH_CLIENT_ID", "legacy-client")
    monkeypatch.setenv("DATABASE_HOST", "short-host")
    settings = Settings(_env_file=None)
    assert settings.model == "short-model"
    assert settings.oauth_client_id == "short-client"
    assert settings.database_host == "short-host"


def test_legacy_names_remain_supported(monkeypatch):
    monkeypatch.delenv("MODEL", raising=False)
    monkeypatch.delenv("OAUTH_CLIENT_ID", raising=False)
    monkeypatch.setenv("POCDANTIC_MODEL", "legacy-model")
    monkeypatch.setenv("POCDANTIC_OAUTH_CLIENT_ID", "legacy-client")
    settings = Settings(_env_file=None)
    assert settings.model == "legacy-model"
    assert settings.oauth_client_id == "legacy-client"


def test_environment_overrides_file_across_aliases(tmp_path, monkeypatch):
    env_file = tmp_path / ".env.local"
    env_file.write_text("MODEL=file-model\nOAUTH_CLIENT_ID=file-client\n")
    monkeypatch.delenv("MODEL", raising=False)
    monkeypatch.delenv("OAUTH_CLIENT_ID", raising=False)
    monkeypatch.setenv("POCDANTIC_MODEL", "environment-model")
    monkeypatch.setenv("POCDANTIC_OAUTH_CLIENT_ID", "environment-client")
    settings = Settings(_env_file=env_file)
    assert settings.model == "environment-model"
    assert settings.oauth_client_id == "environment-client"


def test_login_client_is_separate_and_scopes_are_bounded(monkeypatch):
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("LOGIN_CLIENT_ID", "short-login")
    monkeypatch.setenv("POCDANTIC_LOGIN_CLIENT_ID", "legacy-login")
    s = Settings(_env_file=None, oauth_client_id="actor")
    assert s.login_client_id == "short-login" and s.oauth_client_id == "actor"
    for scopes in ("database:read", "openid openid", "openid\x00", "openid " + "x" * 129):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, login_scopes=scopes)
