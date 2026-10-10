"""Seeded provider secrets never enter recovery projections, errors, logs, or receipts."""

import json

import pytest
from test_recovery_proof import pair, source, unresolved

from agent.recovery.proof import verify_sources
from agent.recovery.store import RecoveryError


@pytest.mark.parametrize("damage", [False, True])
def test_native_secrets_discarded_from_derived_state(recovery_store, damage, caplog, capsys):
    item = unresolved(recovery_store)
    data = pair(recovery_store, item)
    seed = "SEEDED-PRIVATE-CREDENTIAL-AND-PROMPT"
    data["records"][1]["response"]["data"]["password"] = seed
    data["records"][0]["auth"]["client_token"] = seed
    data["records"][1]["response"]["data"]["username"] = seed
    if damage:
        data["records"][1]["request"]["id"] = seed
        with pytest.raises(RecoveryError) as error:
            verify_sources(recovery_store, item, [source(recovery_store, data)], "operator")
        assert seed not in str(error.value)
    else:
        proof = verify_sources(recovery_store, item, [source(recovery_store, data)], "operator")
        recovery_store.update(
            item.incident_id,
            item.revision,
            state="unresolved",
            lease_handle=proof.lease_handle,
            receipt=proof.receipt,
        )
    assert seed not in (recovery_store.root / "state.json").read_text()
    assert seed not in recovery_store.status(owned=[item.incident_id]).model_dump_json()
    assert seed not in caplog.text + capsys.readouterr().out
    assert (
        "database/creds/read/native"
        not in recovery_store.status(owned=[item.incident_id]).model_dump_json()
    )


def test_public_projection_excludes_all_private_binding_fields(recovery_store):
    item = unresolved(recovery_store)
    view = json.loads(recovery_store.status(owned=[item.incident_id]).model_dump_json())
    encoded = json.dumps(view)
    for forbidden in (
        "environment_digest",
        "lease_handle",
        "native_request_id",
        "password",
        "source_digests",
        "reviewer_label",
        "vault.example",
        str(item.operation_id),
    ):
        assert forbidden not in encoded
