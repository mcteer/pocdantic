import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from agent.validation.importers import import_source, normalize
from agent.validation.models import ImportManifest
from agent.validation.store import PrivateStore, StoreError


def manifest(source="vault", **changes):
    now = datetime.now(UTC)
    return ImportManifest(
        source_kind=source,
        format_label={"vault": "vault-jsonl", "verify": "verify-events", "logfire": "logfire-rows"}[
            source
        ],
        source_instance="private-source",
        window_start=now - timedelta(seconds=10),
        window_end=now + timedelta(seconds=10),
        completeness="partial",
        **changes,
    )


def test_vault_fixed_fields_and_duplicate_conflict():
    m = manifest()
    record = {
        "type": "request",
        "time": m.window_start.isoformat(),
        "request": {
            "id": "private-request",
            "path": "database/creds/read",
            "headers": {"x-correlation-id": [str(uuid4())]},
        },
        "secret": "private-canary",
    }
    raw = json.dumps(record).encode()
    events = normalize(raw + b"\n" + raw, m)
    assert len(events) == 1 and events[0].native_request_id == "private-request"
    assert "private-canary" not in events[0].model_dump_json()
    with pytest.raises(StoreError):
        normalize(raw + b"\n" + json.dumps(record | {"time": m.window_end.isoformat()}).encode(), m)


def test_native_verify_ids_are_not_assumed_transaction_ids():
    m = manifest("verify")
    raw = json.dumps(
        {
            "response": {
                "events": {
                    "events": [
                        {
                            "id": "private-event",
                            "correlationid": "private-flow",
                            "time": int(m.window_start.timestamp() * 1000),
                            "data": {"transactionid": "unsupported-canary"},
                            "secret": "canary",
                        }
                    ]
                }
            }
        }
    ).encode()
    event = normalize(raw, m)[0]
    assert event.native_transaction_id is None and event.native_correlation_id == "private-flow"
    assert "canary" not in event.model_dump_json()


@pytest.mark.parametrize("raw", [b"\xff", b'{"rows":[],"rows":[]}', b"PK\x03\x04", b"{}"])
def test_malformed_or_unsupported(raw):
    with pytest.raises(StoreError):
        normalize(raw, manifest("logfire"))


def test_import_is_private_immutable_and_rechecks_digest(tmp_path):
    store = PrivateStore(tmp_path / ".local/validation", project=tmp_path)
    m = manifest()
    raw = json.dumps(
        {"type": "request", "time": m.window_start.isoformat(), "request": {"id": "private-native"}}
    ).encode()
    input_file = tmp_path / "input.jsonl"
    input_file.write_bytes(raw)
    with store.create(uuid4()) as writer:
        artifact = import_source(writer, "vault", input_file, m)
        assert writer.read_bytes(f"source-{artifact.artifact_id}.raw") == raw
        assert artifact.event_count == 1
        assert (writer.path / f"source-{artifact.artifact_id}.raw").stat().st_mode & 0o777 == 0o600


def test_native_v2_vault_lease_and_conflict():
    m = manifest(format_version=2)
    row = {
        "type": "response",
        "time": m.window_start.isoformat(),
        "request": {"id": "request", "path": "database/creds/read"},
        "response": {"secret": {"lease_id": "native-lease"}},
    }
    assert normalize(json.dumps(row).encode(), m)[0].native_lease_id == "native-lease"
    row["response"]["lease_id"] = "different"
    with pytest.raises(StoreError, match="evidence_contradicted"):
        normalize(json.dumps(row).encode(), m)


def test_native_v2_logfire_envelopes_and_project_kinds():
    m = manifest("logfire", format_version=2)
    row = {
        "trace_id": "a" * 32,
        "span_id": "b" * 16,
        "start_timestamp": m.window_start.isoformat(),
        "attributes": {},
    }
    expected = normalize(json.dumps([row]).encode(), m)
    schema = {"fields": [{"name": k, "data_type": "Utf8", "nullable": True} for k in row]}
    for envelope in ({"rows": [row]}, {"schema": schema, "data": [row]}):
        assert normalize(json.dumps(envelope).encode(), m) == expected
    with pytest.raises(StoreError):
        normalize(json.dumps({"schema": schema, "data": [row], "rows": [row]}).encode(), m)
    with pytest.raises(StoreError, match="source_unsupported"):
        normalize(json.dumps([row | {"project_id": "native-id"}]).encode(), m)
    m = m.model_copy(update={"native_project_id": "native-id"})
    normalize(
        json.dumps([row | {"project_id": "native-id", "project_name": "private-source"}]).encode(),
        m,
    )
    with pytest.raises(StoreError, match="evidence_contradicted"):
        normalize(
            json.dumps([row | {"project_id": "native-id", "project_name": "wrong"}]).encode(), m
        )
