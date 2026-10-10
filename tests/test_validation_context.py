import pytest
from pydantic import SecretStr, ValidationError

from agent.settings import Settings
from agent.validation.context import capture_context
from agent.validation.models import DeploymentContext
from agent.validation.runner import run_suite
from agent.validation.store import PrivateStore


def test_context_excludes_credentials_and_changes_with_selectors():
    s = Settings.model_construct(
        bearer_token=SecretStr("secret-canary"), logfire_project="private-project"
    )
    context = capture_context(s)
    assert "canary" not in context.model_dump_json()
    assert (
        context.digest
        == capture_context(s.model_copy(update={"bearer_token": SecretStr("rotated")})).digest
    )
    for field in ("database_host", "verify_user_id", "oauth_client_id", "logfire_project"):
        assert (
            capture_context(s.model_copy(update={field: "another-private-value"})).digest
            != context.digest
        )
    with pytest.raises(ValidationError):
        DeploymentContext.model_validate(context.model_dump() | {"schema_version": True})
    with pytest.raises(ValidationError):
        DeploymentContext.model_validate(context.model_dump() | {"unexpected": "secret"})


def test_context_tracks_profile_and_ca_bytes(tmp_path):
    profiles = tmp_path / "profiles.json"
    profiles.write_text("[]")
    ca = tmp_path / "ca.pem"
    ca.write_text("synthetic-ca")
    s = Settings.model_construct(profiles_file=str(profiles), database_sslrootcert=str(ca))
    before = capture_context(s).digest
    ca.write_text("another-ca")
    assert before != capture_context(s).digest
    before = capture_context(s).digest
    profiles.write_text("[{}]")
    assert before != capture_context(s).digest


async def test_live_context_is_sealed_before_factory(tmp_path):
    store = PrivateStore(tmp_path / ".local/validation", project=tmp_path)
    from agent.validation.scenarios import EffectResult

    async def factory(label, **kwargs):
        writer = kwargs["runtime_options"]["event_sink"].writer
        assert writer.read_json("context.json")["digest"]
        return EffectResult("blocked")

    report = await run_suite(
        store=store,
        mode="live",
        suite_label="live-database",
        settings=Settings.model_construct(),
        factory=factory,
    )
    with store.open(report.validation_id) as writer:
        assert "context.json" in writer.read_json("integrity.json")
