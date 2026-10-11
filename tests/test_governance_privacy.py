"""Renaming private governance authority, state or credentials never permits publication."""

import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "governance_privacy", Path("scripts/publish_policy.py")
)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


@pytest.mark.parametrize(
    "value",
    [
        {"installation_id": "opaque", "environment": "digest", "candidates": []},
        {"installation_id": "opaque", "state_identity": [1, 2], "state_digest": "digest"},
        {
            "owner_issuer": "https://id.example",
            "actor_subject": "actor",
            "entity_id": "entity",
            "trust": {},
        },
        {"schema_version": 1, "sources": []},
        {"proof_id": "opaque", "token_digest": "digest", "trust_digest": "digest"},
        {"binding_digest": "digest", "metadata_digest": "digest", "fingerprints": {}},
        dict.fromkeys(("client_id", "client_secret"), "fixture"),
        {"registry": True, "spiffe": True, "artifact_digest": "digest", "reviewed_by": "fixture"},
        {"captured_evidence_id": "opaque"},
        {"candidate_id": "opaque", "intent_id": "opaque", "profile_digest": "digest"},
        {"challenge_id": "opaque", "nonce_digest": "digest", "candidate_id": "opaque"},
        {"evidence_id": "opaque", "case_id": "opaque", "artifact_digest": "digest"},
        {"token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.synthetic"},
    ],
)
def test_private_governance_content_is_rejected(value):
    assert policy.private_content("config/renamed.json", json.dumps(value).encode())


@pytest.mark.parametrize(
    "name",
    [
        "config.draft.json",
        "secrets.json",
        "candidate-00000000-0000-0000-0000-000000000000.draft.json",
    ],
)
def test_private_governance_names(name):
    assert not policy.publishable("config/" + name)


def test_only_exact_inactive_governance_example_is_exempt():
    raw = Path("config/governance.example.json").read_bytes()
    assert not policy.private_content("config/governance.example.json", raw)
    assert policy.private_content("config/renamed.json", raw)
    assert policy.private_content("config/governance.example.json", raw + b" ")


def test_raw_or_scalar_identity_token_is_private():
    token = b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.synthetic"
    assert policy.private_content("config/renamed.json", token)
    assert policy.private_content("config/renamed.json", json.dumps(token.decode()).encode())


def test_governance_telemetry_has_closed_fields_only():
    from uuid import uuid4

    from agent.telemetry import safe_attributes

    candidate = str(uuid4())
    selected = safe_attributes(
        {
            "gov_candidate_id": candidate,
            "gov_outcome": "blocked",
            "gov_provenance": "synthetic",
            "gov_state": "uncertain",
            "gov_observations": 3,
            "gov_operation": "identity",
            "token": "canary",
            "entity_id": "canary",
            "owner": "canary",
            "gov_reason": "canary",
        }
    )
    assert selected == {
        "gov_candidate_id": candidate,
        "gov_outcome": "blocked",
        "gov_provenance": "synthetic",
        "gov_state": "uncertain",
        "gov_observations": 3,
        "gov_operation": "identity",
    }
