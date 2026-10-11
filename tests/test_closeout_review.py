"""Review conflict resolution is explicit, digest-bound and independent of timestamps."""

from uuid import uuid4

import pytest
from closeout_support import instant

from agent.closeout.models import CloseoutError, Review, validate
from agent.closeout.review import active_decisions, role_decisions


def decision(kind="package", **changes):
    """Build a synthetic private record without authenticating its reviewer label."""
    return {
        "review_id": str(uuid4()),
        "kind": kind,
        "subject_id": str(uuid4()),
        "expected_digest": "a" * 64,
        "reviewer": "reviewer-canary",
        "role": "customer_security",
        "observed_at": instant(-2),
        "reviewed_at": instant(-1),
        "decision": "approve",
        "rationale": "private-canary",
        "attestations": [str(uuid4())],
        "witnessed": True,
        **changes,
    }


def test_unsuperseded_conflicts_never_latest_wins():
    """A newer approval cannot silently erase an earlier rejection."""
    first = validate(Review, decision(decision="reject"))
    second = validate(Review, decision(subject_id=str(first.subject_id)))
    active = active_decisions([first, second], "package", first.subject_id, first.expected_digest)
    assert role_decisions(active)["customer_security"] == "conflict"
    successor = validate(
        Review, decision(subject_id=str(first.subject_id), supersedes=[str(first.review_id)])
    )
    active = active_decisions(
        [first, successor], "package", first.subject_id, first.expected_digest
    )
    assert role_decisions(active)["customer_security"] == "approve"


def test_wrong_variant_fields_and_future_observation_rejected():
    """A source review cannot masquerade as a witnessed package approval."""
    with pytest.raises(CloseoutError):
        validate(Review, decision(kind="source-profile"))
    with pytest.raises(CloseoutError):
        validate(Review, decision(observed_at=instant(100)))


@pytest.mark.parametrize("defect", ["digest", "role", "witness", "stale", "cleanup"])
def test_review_rejects_unbound_or_unsafe_approval(closeout_project, defect):
    """Labels cannot waive current digest, actual witness or unresolved cleanup requirements."""
    from closeout_support import inventory

    from agent.closeout.assessment import assemble
    from agent.closeout.models import Inventory, byte_digest, digest
    from agent.closeout.package import build
    from agent.closeout.review import record
    from agent.closeout.sources import import_source
    from agent.closeout.store import Store

    store = Store(closeout_project)
    inv = inventory()
    inv["sources"][0]["format"] = "attachment-v1"
    head = store.prepare(validate(Inventory, inv))
    assessed = assemble(store, head)
    core = build(store, store.head(head.dossier_id), assessed.object_id)
    raw = b"Sanitized supporting fixture."
    source = import_source(
        store,
        store.head(head.dossier_id),
        {
            "profile_id": inv["sources"][0]["profile_id"],
            "format": "attachment-v1",
            "provenance": "operator",
            "input_digest": byte_digest(raw),
            "observed_at": instant(-1),
            "environment_digest": digest(store.inventory(head)),
            "scope": str(uuid4()),
            "media_type": "text/plain",
        },
        raw,
    )
    value = decision(
        subject_id=str(core.object_id),
        expected_digest=core.seal_digest,
        attestations=[str(source.object_id)],
    )
    value.pop("review_id")
    value.pop("reviewed_at")
    if defect == "digest":
        value["expected_digest"] = "f" * 64
    elif defect == "role":
        value["role"] = "unknown-owner"
    elif defect == "stale":
        inv = store.inventory(store.head(head.dossier_id)).model_copy(
            update={"implementation_digest": "f" * 64}
        )
        store.append(head.dossier_id, store.head(head.dossier_id).revision, "inventory", inv)
    elif defect == "cleanup":
        payload = store.read(head.dossier_id, assessed)
        payload["rows"][0]["unsafe"] = True
        payload["rows"][0]["proof"] = "fail"
        unsafe = store.append(
            head.dossier_id, store.head(head.dossier_id).revision, "assessment", payload
        )
        value.update(
            kind="exception",
            subject_id=str(unsafe.object_id),
            expected_digest=unsafe.seal_digest,
            criterion=payload["rows"][0]["criterion"],
            decision="agree_exception",
            alternative="fixture alternative",
        )
        value.pop("witnessed")
    revision = store.head(head.dossier_id).revision
    with pytest.raises(CloseoutError):
        record(store, store.head(head.dossier_id), value)
    assert store.head(head.dossier_id).revision == revision
