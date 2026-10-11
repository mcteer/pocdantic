"""Canary and renamed-artifact checks protect logs, telemetry and publication."""

import json

import pytest

from scripts.publish_policy import private_content


async def test_unified_canaries(recovery_store, caplog, capsys):
    """Compose actual private-source reduction and telemetry assertions without native inputs."""
    from test_recovery_privacy import test_native_secrets_discarded_from_derived_state
    from test_telemetry import test_instrumentation_omits_prompts_arguments_and_results

    test_native_secrets_discarded_from_derived_state(recovery_store, False, caplog, capsys)
    await test_instrumentation_omits_prompts_arguments_and_results()
    assert "SEEDED-PRIVATE" not in caplog.text + capsys.readouterr().out


@pytest.mark.parametrize(
    "shape",
    [
        {
            "run_id": "fixture",
            "content_digest": "0" * 64,
            "selection_digest": "1" * 64,
            "cases": ["authority"],
        },
        {
            "run_id": "fixture",
            "content_digest": "0" * 64,
            "selection_digest": "1" * 64,
            "kind": "item",
        },
        {"profile": "baseline", "frames": [], "cleanup": "drained"},
        {"run_id": "fixture", "artifacts": {}, "profile_digests": {}, "cleanup": "drained"},
    ],
)
def test_renamed_private_records(shape):
    """Content signatures must reject private metadata even under a publishable new name."""
    assert private_content("config/renamed.json", json.dumps(shape).encode())


def test_damaged_private_fragment_stays_private():
    """Malformed protocol JSON is rejected without exposing its canary to scanner output."""
    raw = b'{"run_id":"fixture","content_digest":"PRIVATE","selection_digest":'
    assert private_content("config/renamed.json", raw)
