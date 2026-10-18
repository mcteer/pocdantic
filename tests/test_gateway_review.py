"""Review rejection must not depend on functioning Gateway or live evidence."""

import os
from datetime import timedelta

import pytest

from agent.gateway.models import ControlReview, GatewayError, now
from agent.gateway.review import ReviewStore


def test_reject_without_configuration_or_evidence(tmp_path):
    """A rejection takes effect immediately and persists without expiry evidence."""
    store = ReviewStore(tmp_path)
    review = store.reject("operator")
    assert store.current().review_id == review.review_id
    assert store.current().decision == "rejected"
    with pytest.raises(GatewayError, match="gateway_review_required"):
        store.admit({})
    assert (tmp_path / ".local/gateway/current.json").stat().st_mode & 0o777 == 0o600


def test_status_read_does_not_create_state(tmp_path):
    """A read-only status cannot prepare enrollment or create control state."""
    with pytest.raises(GatewayError):
        ReviewStore(tmp_path).current()
    assert not (tmp_path / ".local").exists()


def test_linked_pointer_rejected(tmp_path):
    """Even owner-only hard-linked or symbolic control files are inadmissible."""
    store = ReviewStore(tmp_path)
    store.reject("operator")
    path = tmp_path / ".local/gateway/current.json"
    os.link(path, path.with_name("linked.json"))
    with pytest.raises(GatewayError):
        store.current()


def test_approval_needs_complete_bindings():
    """No configuration switch or future-dated review can fabricate approval."""
    with pytest.raises(ValueError):
        ControlReview(decision="approved", reviewer="operator")
    with pytest.raises(ValueError):
        ControlReview(
            decision="rejected", reviewer="operator", reviewed_at=now() + timedelta(days=1)
        )


def test_approval_detects_drift_and_rejects_missing_evidence(tmp_path):
    """A current review cannot survive changes to a private source or require it to reject."""
    from tests.gateway_support import approval, configuration

    store, folder, expected = approval(tmp_path, configuration())
    store.admit(expected)
    (folder / "synthetic.txt").write_bytes(b"changed synthetic source")
    with pytest.raises(GatewayError):
        store.admit(expected)
    store.reject("operator")
    assert store.current().decision == "rejected"


def test_synthetic_bundle_cannot_approve(tmp_path):
    """The same passing observations without live-source attestation remain blocked."""
    from agent.gateway.probes import cases
    from tests.gateway_support import approval, configuration

    store, folder, expected = approval(tmp_path, configuration(), source="synthetic")
    with pytest.raises(GatewayError):
        store.approve(folder.name, "operator", expected, cases("openai-chat"))


def test_review_rechecks_key_expiry_and_current_pointer(tmp_path):
    """A changed key, expired record or replaced pointer cannot keep dispatch authority."""
    from tests.gateway_support import approval, configuration

    store, _, expected = approval(tmp_path, configuration())
    with pytest.raises(GatewayError):
        store.admit(expected | {"credential_digest": "1" * 64})
    current = store.current()
    from uuid import uuid4

    expired = current.model_copy(
        update={
            "review_id": uuid4(),
            "observed_at": now() - timedelta(days=2),
            "reviewed_at": now() - timedelta(days=2),
            "expires_at": now() - timedelta(days=1, hours=1),
        }
    )
    store.commit(expired)
    with pytest.raises(GatewayError):
        store.admit(expected)


def test_rejection_wins_a_concurrent_approval_race(tmp_path):
    """An approval prepared against an old pointer cannot overwrite a new rejection."""
    from uuid import uuid4

    from tests.gateway_support import approval, configuration

    store, _, _ = approval(tmp_path, configuration())
    old = store.current()
    store.reject("operator")
    candidate = old.model_copy(update={"review_id": uuid4()})
    with pytest.raises(GatewayError):
        store.commit(candidate, expected=old.review_id)
    assert store.current().decision == "rejected"


def test_unfinished_attempt_is_unknown_without_replay(tmp_path):
    """A persisted dispatch without a terminal event is never inferred successful."""
    from uuid import uuid4

    from agent.gateway.models import ModelAttempt

    event = ModelAttempt(
        run_id=uuid4(),
        request_id=uuid4(),
        definition_ref=uuid4(),
        workload_ref=uuid4(),
        sequence=1,
        route_ref=uuid4(),
        model_ref=uuid4(),
        protocol="openai-chat",
        stage="dispatched",
    )
    store = ReviewStore(tmp_path)
    store.record(event)
    before = sorted((tmp_path / ".local/gateway").iterdir())
    assert store.attempts()[0].stage == "unknown"
    assert store.attempts()[0].cost_usd is None
    assert sorted((tmp_path / ".local/gateway").iterdir()) == before
    store.record(event.model_copy(update={"stage": "completed"}))
    assert store.attempts()[0].stage == "completed"
    store.record(event.model_copy(update={"stage": "failed"}))
    with pytest.raises(GatewayError, match="gateway_observation_failed"):
        store.attempts()


@pytest.mark.parametrize("change", ["permissions", "symlink", "oversize"])
def test_unsafe_review_sources_block_admission(tmp_path, change):
    """Admission rechecks source access, kind and size rather than trusting prior review."""
    from tests.gateway_support import approval, configuration

    store, folder, expected = approval(tmp_path, configuration())
    source = folder / "synthetic.txt"
    if change == "permissions":
        source.chmod(0o644)
    elif change == "symlink":
        source.rename(folder / "other.txt")
        source.symlink_to("other.txt")
    else:
        with source.open("wb") as output:
            output.truncate(8 * 1024 * 1024 + 1)
    with pytest.raises(GatewayError):
        store.admit(expected)


def test_transport_changes_invalidate_validation_without_rebinding_recovery():
    """Model routing drift changes validation context while database ownership stays stable."""
    from agent.recovery.store import environment_digest
    from agent.validation.context import capture_context
    from tests.gateway_support import configuration

    original = configuration()
    routed = original.model_copy(update={"gateway_route": "other"})
    assert capture_context(original).digest != capture_context(routed).digest
    assert environment_digest(original) == environment_digest(routed)
    target = original.model_copy(update={"database_host": "other.example"})
    assert environment_digest(original) != environment_digest(target)


def test_explicit_operator_owned_review_keeps_administration_unverified(tmp_path):
    """A reviewed scope change never fabricates caps or removes core control evidence."""
    from tests.gateway_support import approval, configuration

    store, folder, expected = approval(tmp_path, configuration(), administration="operator-owned")
    review = store.admit(expected)
    bundle, _ = store.evidence(folder.name)
    assert review.administration == "operator-owned"
    assert bundle.spend is None
    assert set(bundle.controls) == {"routing", "protection", "privacy"}
    assert store.current().administration == "operator-owned"


@pytest.mark.parametrize("control", ["routing", "protection", "privacy"])
def test_operator_owned_scope_still_blocks_missing_core_evidence(tmp_path, control):
    """Operator administration is never permission to omit routing, blocking or privacy."""
    import json

    from tests.gateway_support import approval, configuration

    store, folder, expected = approval(tmp_path, configuration(), administration="operator-owned")
    path = folder / "bundle.json"
    data = json.loads(path.read_text())
    del data["controls"][control]
    path.write_text(json.dumps(data))
    with pytest.raises(GatewayError):
        store.admit(expected)


@pytest.mark.parametrize("mutation", ["omit_scope", "fake_spend", "failed_control", "synthetic"])
def test_operator_scope_cannot_be_inferred_or_fake_acceptance(tmp_path, mutation):
    """Scope is explicit, retains strict defaults and never promotes failed/synthetic source."""
    import json

    from agent.gateway.probes import cases
    from tests.gateway_support import approval, configuration

    store, folder, expected = approval(tmp_path, configuration(), administration="operator-owned")
    path = folder / "bundle.json"
    data = json.loads(path.read_text())
    if mutation == "omit_scope":
        del data["administration"]
    elif mutation == "fake_spend":
        data["spend"] = {
            "daily_usd": 0,
            "monthly_usd": 0,
            "require_pricing": True,
            "blocking": True,
            "currency": "USD",
        }
    elif mutation == "failed_control":
        data["controls"]["privacy"]["disposition"] = "unknown"
    else:
        data["source"] = "synthetic"
    path.write_text(json.dumps(data))
    with pytest.raises(GatewayError):
        store.approve(folder.name, "operator", expected, cases("openai-chat"))


def test_legacy_full_review_remains_default(tmp_path):
    """Existing full-attestation bundles remain valid and need their spend evidence."""
    import json

    from tests.gateway_support import approval, configuration

    store, folder, expected = approval(tmp_path, configuration())
    assert store.admit(expected).administration == "reviewed"
    path = folder / "bundle.json"
    data = json.loads(path.read_text())
    del data["administration"]
    data["spend"] = None
    path.write_text(json.dumps(data))
    with pytest.raises(GatewayError):
        store.admit(expected)


def test_review_scope_mismatch_blocks_admission(tmp_path):
    """The selected immutable review cannot relabel its bound source scope."""
    import json

    from tests.gateway_support import approval, configuration

    store, _, expected = approval(tmp_path, configuration(), administration="operator-owned")
    record = store.current()
    path = tmp_path / ".local/gateway" / f"{record.review_id}.json"
    data = json.loads(path.read_text())
    data["administration"] = "reviewed"
    path.write_text(json.dumps(data))
    with pytest.raises(GatewayError):
        store.admit(expected)


@pytest.mark.asyncio
async def test_status_names_operator_ownership(tmp_path, monkeypatch, capsys):
    """CLI status reports ownership without claiming budgets or revealing source values."""
    import json
    from types import SimpleNamespace

    from agent.gateway.commands import execute_gateway
    from tests.gateway_support import approval, configuration

    settings = configuration()
    store, _, _ = approval(tmp_path, settings, administration="operator-owned")
    monkeypatch.setattr("agent.gateway.commands.ReviewStore", lambda: store)
    monkeypatch.setattr("agent.settings.Settings", lambda: settings)
    assert await execute_gateway(SimpleNamespace(gateway_command="status")) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "protected-reviewed"
    assert result["administration"] == "operator-owned"
    assert "daily_usd" not in result
