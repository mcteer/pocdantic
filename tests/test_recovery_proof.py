"""Exact native linkage and reviewed provenance are required to resolve an incident."""

import copy
import json
from uuid import uuid4

import pytest

from agent.recovery.proof import verify_sources
from agent.recovery.store import RecoveryError


def pair(store, item, *, denied=False, cleanup=False):
    """Build a minimal supported native pair with explicit environment provenance."""
    request = {
        "id": str(uuid4()),
        "operation": "update" if cleanup else "read",
        "path": "sys/leases/revoke" if cleanup else item.credential_path,
        "namespace": {"path": store.settings.vault_namespace},
        "headers": {"x-correlation-id": [str(item.operation_id)]},
        "data": {"lease_id": item.lease_handle, "sync": True} if cleanup else {},
    }
    response = {
        "type": "response",
        "request": copy.deepcopy(request),
        "response": {}
        if denied or cleanup
        else {"data": {"lease_id": "database/creds/read/native"}},
        "auth": {"policy_results": {"allowed": not denied}},
    }
    if denied:
        response["error"] = "permission denied"
    return {
        "schema_version": 1,
        "environment_digest": item.environment_digest,
        "source_instance": store.settings.vault_addr,
        "records": [
            {
                "type": "request",
                "request": request,
                "auth": {"policy_results": {"allowed": not denied}},
            },
            response,
        ],
    }


def source(store, data, name="native.json"):
    """Keep a synthetic native export private without copying it into the journal."""
    p = store.root.parent / name
    p.write_text(json.dumps(data))
    p.chmod(0o600)
    return p


def unresolved(store):
    """Leave a durable unknown acquisition to be reconciled by reviewed native proof."""
    with store.effect() as owner:
        item = store.begin(owner)
        return store.update(item.incident_id, item.revision, state="unresolved")


@pytest.mark.parametrize("denied", [False, True])
def test_exact_pair_identifies_or_proves_no_issuance(recovery_store, denied):
    item = unresolved(recovery_store)
    candidate = verify_sources(
        recovery_store,
        item,
        [source(recovery_store, pair(recovery_store, item, denied=denied))],
        "operator",
    )
    assert candidate.receipt.outcome == ("not_issued" if denied else "lease_identified")
    assert candidate.receipt.source_digests and candidate.receipt.incident_revision == item.revision
    assert (candidate.lease_handle is None) == denied


@pytest.mark.parametrize(
    "damage",
    [
        "environment",
        "source",
        "namespace",
        "path",
        "correlation",
        "native_id",
        "generic_error",
        "hmac",
        "duplicate",
        "lease_conflict",
        "unknown_field",
    ],
)
def test_ambiguous_foreign_or_generic_records_rejected(recovery_store, damage):
    item = unresolved(recovery_store)
    data = pair(recovery_store, item, denied=damage == "generic_error")
    request, response = data["records"]
    if damage == "environment":
        data["environment_digest"] = "b" * 64
    if damage == "source":
        data["source_instance"] = "https://other.example"
    if damage == "namespace":
        response["request"]["namespace"]["path"] = "other"
    if damage == "path":
        response["request"]["path"] = "database/creds/other"
    if damage == "correlation":
        response["request"]["headers"]["x-correlation-id"] = [str(uuid4())]
    if damage == "native_id":
        response["request"]["id"] = str(uuid4())
    if damage == "generic_error":
        response["auth"]["policy_results"]["allowed"] = True
    if damage == "hmac":
        response["response"]["data"]["lease_id"] = "hmac-sha256:value"
    if damage == "duplicate":
        data["records"].append(copy.deepcopy(response))
    if damage == "lease_conflict":
        response["response"]["lease_id"] = "database/creds/read/other"
    if damage == "unknown_field":
        data["authority"] = "clear"
    with pytest.raises(RecoveryError):
        verify_sources(recovery_store, item, [source(recovery_store, data)], "operator")


def test_completed_sync_cleanup_requires_acquisition_link(recovery_store):
    item = unresolved(recovery_store)
    acquisition = pair(recovery_store, item)
    bound = type(item).model_validate(
        item.model_dump() | {"lease_handle": "database/creds/read/native"}
    )
    cleanup = pair(recovery_store, bound, cleanup=True)
    # Cleanup has its own operation correlation; the exact lease links to acquisition.
    cleanup["records"][0]["request"]["headers"]["x-correlation-id"] = [str(uuid4())]
    cleanup["records"][1]["request"]["headers"] = copy.deepcopy(
        cleanup["records"][0]["request"]["headers"]
    )
    candidate = verify_sources(
        recovery_store,
        item,
        [
            source(recovery_store, acquisition, "acquire.json"),
            source(recovery_store, cleanup, "cleanup.json"),
        ],
        "operator",
    )
    assert candidate.receipt.outcome == "revoked"
    cleanup["records"][0]["request"]["data"]["sync"] = 1
    cleanup["records"][1]["request"]["data"]["sync"] = 1
    with pytest.raises(RecoveryError):
        verify_sources(
            recovery_store,
            item,
            [
                source(recovery_store, acquisition, "acquire.json"),
                source(recovery_store, cleanup, "cleanup.json"),
            ],
            "operator",
        )


@pytest.mark.parametrize(
    "damage",
    [
        "outside",
        "hardlink",
        "permissions",
        "oversized",
        "records",
        "depth",
        "duplicate_keys",
        "too_many_sources",
        "reviewer",
    ],
)
def test_import_limits_and_private_paths(recovery_store, damage):
    import os

    item = unresolved(recovery_store)
    data = pair(recovery_store, item)
    path = source(recovery_store, data)
    sources, reviewer = [path], "operator"
    if damage == "outside":
        path = recovery_store.project / "outside.json"
        path.write_text(json.dumps(data))
        path.chmod(0o600)
        sources = [path]
    elif damage == "hardlink":
        os.link(path, path.with_name("link.json"))
    elif damage == "permissions":
        path.chmod(0o644)
    elif damage == "oversized":
        path.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    elif damage == "records":
        data["records"] *= 101
        path.write_text(json.dumps(data))
    elif damage == "depth":
        path.write_text("[" * 18 + "0" + "]" * 18)
    elif damage == "duplicate_keys":
        path.write_text('{"a":1,"a":2}')
    elif damage == "too_many_sources":
        sources *= 3
    elif damage == "reviewer":
        reviewer = " " * 64
    with pytest.raises(RecoveryError):
        verify_sources(recovery_store, item, sources, reviewer)


def test_native_jsonl_envelope_and_stale_revision_rejection(recovery_store):
    item = unresolved(recovery_store)
    data = pair(recovery_store, item)
    records = data.pop("records")
    path = source(recovery_store, {}, "native.jsonl")
    path.write_text("\n".join(json.dumps(v) for v in [data, *records]))
    proof = verify_sources(recovery_store, item, [path], "operator")
    newer = recovery_store.update(item.incident_id, item.revision, state="unresolved")
    with pytest.raises(RecoveryError):
        recovery_store.update(newer.incident_id, newer.revision, receipt=proof.receipt)


def test_response_only_numeric_sync_cannot_equal_true(recovery_store):
    item = unresolved(recovery_store)
    acquisition = pair(recovery_store, item)
    bound = item.model_copy(update={"lease_handle": "database/creds/read/native"})
    cleanup = pair(recovery_store, bound, cleanup=True)
    cleanup["records"][1]["request"]["data"]["sync"] = 1
    with pytest.raises(RecoveryError):
        verify_sources(
            recovery_store,
            item,
            [
                source(recovery_store, acquisition, "acq.json"),
                source(recovery_store, cleanup, "cleanup.json"),
            ],
            "operator",
        )


def test_derived_receipt_cannot_be_reused_across_incidents(recovery_store):
    from agent.recovery.models import Receipt

    item = unresolved(recovery_store)
    proof = verify_sources(
        recovery_store,
        item,
        [source(recovery_store, pair(recovery_store, item, denied=True))],
        "operator",
    )
    recovery_store.update(
        item.incident_id,
        item.revision,
        state="resolved",
        resolution="not_issued",
        receipt=proof.receipt,
    )
    other = unresolved(recovery_store)
    reused = Receipt.model_validate(
        proof.receipt.model_dump()
        | {
            "incident_id": other.incident_id,
            "incident_revision": other.revision,
            "operation_id": other.operation_id,
        }
    )
    with pytest.raises(RecoveryError):
        recovery_store.update(
            other.incident_id,
            other.revision,
            state="resolved",
            resolution="not_issued",
            receipt=reused,
        )
