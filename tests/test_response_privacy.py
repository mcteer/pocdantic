"""Publication boundaries recognize private response artifacts under arbitrary names."""

import importlib.util
import json
from pathlib import Path

import pytest

from agent.telemetry import safe_attributes

_policy_spec = importlib.util.spec_from_file_location(
    "publish_policy", Path("scripts/publish_policy.py")
)
_policy = importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(_policy)
private_content = _policy.private_content


@pytest.mark.parametrize(
    "record",
    [
        {"installation_id": "fixture", "policy_digest": "0" * 64, "incidents": []},
        {
            "installation_id": "fixture",
            "recovery_mode": "configured",
            "recovery_installation_id": "fixture",
        },
        {"intake_mode": "relay", "sources": [], "audience": "private", "automatic_cleanup": False},
        {
            "kind": "bound",
            "root_run_id": "fixture",
            "request_id": "fixture",
            "issuer": "canary",
            "subject": "canary",
        },
        {"incident_id": "fixture", "source": "private", "event_id": "private", "instructions": []},
    ],
)
def test_renamed_private_json_and_jsonl(record):
    """The shared detector protects staged/history and distribution callers alike."""
    for name in ("config/renamed.json", "specs/renamed.jsonl"):
        assert private_content(name, json.dumps(record).encode())


def test_example_exemption_is_exact_and_cannot_hide_real_policy():
    """Only the maintained all-synthetic draft is publishable, never a live mapping."""
    name = "config/response.example.json"
    raw = Path(name).read_bytes()
    assert not private_content(name, raw)
    assert not private_content("pocdantic-0.1.0/config/response.example.json", raw)
    assert private_content("config/copied.json", raw)
    value = json.loads(raw)
    value["issuer"] = "https://customer.example"
    assert private_content(name, json.dumps(value).encode())


def test_response_telemetry_drops_canaries():
    """Neither public IDs nor private values are response action metadata."""
    assert safe_attributes(
        {
            "response_action": "revoke_exact",
            "response_status": "confirmed",
            "source": "canary",
            "incident_id": "canary",
            "subject": "canary",
            "response_reason": "canary",
            "raw_body": "canary",
        }
    ) == {"response_action": "revoke_exact", "response_status": "confirmed"}
    assert safe_attributes({"response_action": "canary", "response_status": "canary"}) == {}
