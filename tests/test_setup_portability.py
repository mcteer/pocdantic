"""Two independent synthetic deployments exercise provider and target differences."""

import pytest

from tests.portability_support import deployment


@pytest.mark.parametrize("provider", ["generic", "verify"])
async def test_two_provider_baselines(tmp_path, monkeypatch, provider):
    """Separate keys, subjects, metadata and storage verify the selected provider route."""

    async def read(lease, **kwargs):
        return [{"id": kwargs["record_id"]}]

    monkeypatch.setattr("agent.broker.read_postgres", read)
    settings, store, _, factory, http = deployment(tmp_path, provider=provider)
    async with http:
        assert await factory()(1) == [{"id": 1}]
    assert all(a.state == "resolved" for a in store.read().attempts)
    assert not settings.oauth_client_id and not settings.verify_api_client_id


def test_resolved_v2_history_survives_route_adoption(tmp_path):
    """Offline migration pins old resolved history while enrolling the selected new context."""
    from agent.recovery.lifecycle import CredentialLifecycle
    from agent.recovery.store import RecoveryStore

    (tmp_path / "fresh").mkdir()
    settings, _, _, factory, _ = deployment(tmp_path / "fresh")
    legacy = settings.model_copy(
        update={
            "database_auth_mode": "delegated-exchange",
            "vault_audience": "vault",
            "oauth_client_id": "actor",
        }
    )
    project = tmp_path / "legacy"
    project.mkdir()
    old = RecoveryStore(legacy, project=project)
    old.initialize()
    with old.effect() as owner:
        owner.binding = factory().run_guard.ownership()
        lifecycle = CredentialLifecycle(old, owner)
        lifecycle.start()
        lifecycle.acquired(legacy.vault_read_path + "/synthetic")
        lifecycle.pending()
        lifecycle.completed()
    history = old.read().attempts[0]
    current = RecoveryStore(settings, project=project)
    assert current.migrate() is True
    assert current.read().schema_version == 3
    assert current.read().attempts[0] == history
    assert current.read().environment_digest != history.environment_digest
    assert current.migrate() is False


async def test_live_denial_route_rejects_before_adapter(tmp_path, monkeypatch):
    """The fixed denied-token scenario does not dispatch Vault or database effects."""
    from pydantic import SecretStr

    import agent.validation.scenarios as scenarios
    from agent.schemas import Principal

    settings, _, _, _, _ = deployment(tmp_path)
    settings = settings.model_copy(
        update={"portability_denied_token": SecretStr("synthetic-denied")}
    )
    monkeypatch.setattr(scenarios, "live_preflight", lambda *args: None)

    async def principal(selected):
        assert selected.bearer_token.get_secret_value() == "synthetic-denied"
        return Principal(issuer=settings.oauth_issuer, subject="colleague", scopes=["tickets:read"])

    monkeypatch.setattr("agent.cli.authenticated_principal", principal)
    result = await scenarios.live_scenario("user-jwt-denial", settings=settings)
    assert result.outcome == "pass" and result.effect_attempts == result.forbidden_effects == 0
