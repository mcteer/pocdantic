"""Publication rejects renamed private provider authority, evidence and capability secrets."""

import importlib.util
import json
from pathlib import Path

import pytest

_policy_spec = importlib.util.spec_from_file_location(
    "provider_privacy", Path("scripts/publish_policy.py")
)
_policy = importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(_policy)
private_content, publishable = _policy.private_content, _policy.publishable


@pytest.mark.parametrize(
    "value",
    [
        {"installation_id": "opaque", "source_policy_digest": "digest", "bindings": []},
        {"action_id": "opaque", "binding": {}, "enrollment_digest": "digest"},
        {"observation_id": "opaque", "binding_id": "opaque", "source_digest": "digest"},
        {"acquisition_id": "opaque", "ownership": {}, "credential_path": "fixed"},
        {"notice_id": "opaque", "notice_revision": 1, "resource_generation": 1},
        {"hook-alias": "https://workflow.example/trigger?sig=synthetic"},
        {"database-alias": "host=database.example dbname=fixture password=synthetic"},
    ],
)
def test_renamed_private_provider_shapes(value):
    """Renaming a private data file inside config never makes it publishable."""
    assert private_content("config/renamed.json", json.dumps(value).encode())


@pytest.mark.parametrize(
    "name", ["providers.draft.json", "providers.readiness.json", "provider-secrets.json"]
)
def test_private_provider_filenames(name):
    """Fixed private artifacts are rejected even without readable content."""
    assert not publishable("config/" + name)


def test_only_exact_synthetic_example_is_exempt():
    """The published demo is allowed; edits and renaming cannot turn real authority into a demo."""
    raw = Path("config/providers.example.json").read_bytes()
    assert not private_content("config/providers.example.json", raw)
    assert private_content("config/renamed.json", raw)
    assert private_content("config/providers.example.json", raw + b" ")
