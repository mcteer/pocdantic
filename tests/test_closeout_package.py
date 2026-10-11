"""Sealed blocked-package lifecycle, tamper detection and non-circular review bindings."""

import pytest
from closeout_support import inventory

from agent.closeout.assessment import assemble
from agent.closeout.models import CloseoutError, Inventory, validate
from agent.closeout.package import build, handoff, report
from agent.closeout.store import Store


def test_blocked_package_and_handoff_preserve_core(closeout_project):
    """Missing native proof stays blocked through both separately sealed generations."""
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    assessment = assemble(store, head)
    head = store.head(head.dossier_id)
    core = build(store, head, assessment.object_id)
    before = store.read_files(head.dossier_id, core)
    final = handoff(store, store.head(head.dossier_id), core.object_id)
    assert report(store, store.head(head.dossier_id), final.object_id)["status"] == "blocked"
    assert store.read_files(head.dossier_id, core) == before
    assert "guides.json" in before and "readout.md" in before
    assert not any(name.endswith(".raw") for name in before)


def test_core_extra_file_invalidates_report(closeout_project):
    """A seal verifies the exact set, not just the names it expected to see."""
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    assessed = assemble(store, head)
    core = build(store, store.head(head.dossier_id), assessed.object_id)
    from closeout_support import private_file

    private_file(store.record_path(head.dossier_id, core.object_id) / "extra.txt", b"x")
    with pytest.raises(CloseoutError, match="integrity_failed"):
        report(store, store.head(head.dossier_id), core.object_id)


@pytest.mark.parametrize("mode", ["blocked", "accepted", "accepted_with_exceptions", "failed"])
def test_digest_bound_witness_lifecycle_and_private_role_prose(closeout_project, monkeypatch, mode):
    """Real parsed meeting references permit role records without renewing or mutating a core."""
    import json
    from uuid import uuid4

    from closeout_support import instant, reviewed_facts

    from agent.closeout.models import ROLES, byte_digest, digest
    from agent.closeout.review import record
    from agent.closeout.sources import import_source

    store, head = reviewed_facts(
        closeout_project,
        omit="vault-human-actor-audit" if mode == "accepted_with_exceptions" else None,
    )
    if mode != "blocked":
        # Counting and regression have independent import/measurement tests. Isolate
        # final decision logic here, without pretending these fixtures ran providers.
        import agent.closeout.counting as counting
        import agent.closeout.package as packaging

        monkeypatch.setattr(
            counting,
            "latest_outcomes",
            lambda store, head: {
                s: "pass"
                for s in __import__("agent.closeout.models", fromlist=["SCENARIOS"]).SCENARIOS
            },
        )
        monkeypatch.setattr(packaging, "software_valid", lambda store, head, assessment: True)
    assessed = assemble(store, head)
    if mode != "blocked":
        from agent.closeout.catalog import OWNERS

        payload = store.read(head.dossier_id, assessed)
        attestations = [
            str(ref.object_id)
            for ref in store.head(head.dossier_id).records
            if ref.kind == "source"
        ]
        for row in payload["rows"]:
            exception = row["proof"] != "pass"
            for role in set(OWNERS[row["criterion"]]) | (
                {"customer_security"} if exception else set()
            ):
                value = {
                    "kind": "exception" if exception else "criterion",
                    "subject_id": str(assessed.object_id),
                    "expected_digest": assessed.seal_digest,
                    "criterion": row["criterion"],
                    "reviewer": "fixture-reviewer",
                    "role": role,
                    "observed_at": instant(-1),
                    "decision": "agree_exception" if exception else "approve",
                    "rationale": "reviewed fixture scope",
                    "attestations": attestations,
                }
                if exception:
                    value["alternative"] = (
                        "Customer and vendor accept unavailable audit as a qualified exception."
                    )
                record(store, store.head(head.dossier_id), value)
    core = build(store, store.head(head.dossier_id), assessed.object_id)
    before = store.read_files(head.dossier_id, core)
    profile = next(
        p for p in store.inventory(store.head(head.dossier_id)).sources if p.product == "customer"
    )
    meeting = instant(-1)
    raw = json.dumps(
        [
            {
                "source_event_id": "witness-event",
                "occurred_at": meeting,
                "operation_ref": "meeting",
                "actor": "agent",
                "subject": "human",
                "resource": "resource",
                "generation": 1,
                "obligation": "customer-receipt",
                "fact_kind": "witness",
                "values": {
                    "meeting_at": meeting,
                    "participants": list(ROLES),
                    "witnessed_digest": core.seal_digest,
                    "attestation_ref": "meeting-artifact-private-canary",
                },
            }
        ]
    ).encode()
    head = store.head(head.dossier_id)
    witness = import_source(
        store,
        head,
        {
            "profile_id": str(profile.profile_id),
            "format": "native-facts-v1",
            "provenance": "native",
            "input_digest": byte_digest(raw),
            "observed_at": instant(),
            "environment_digest": digest(store.inventory(head)),
            "scope": str(uuid4()),
            "complete": True,
        },
        raw,
    )
    payload = store.read(head.dossier_id, witness)
    record(
        store,
        store.head(head.dossier_id),
        {
            "kind": "source",
            "subject_id": str(witness.object_id),
            "expected_digest": witness.seal_digest,
            "reviewer": "private-reviewer-canary",
            "role": "customer_security",
            "observed_at": meeting,
            "decision": "approve",
            "rationale": "private-review-prose-canary",
            "attestations": [str(witness.object_id)],
            "extraction_digest": digest(
                {"facts": payload["facts"], "normalized": payload["normalized"]}
            ),
        },
    )
    for role in ROLES:
        record(
            store,
            store.head(head.dossier_id),
            {
                "kind": "package",
                "subject_id": str(core.object_id),
                "expected_digest": core.seal_digest,
                "reviewer": "private-reviewer-canary",
                "role": role,
                "observed_at": meeting,
                "decision": "reject"
                if mode == "failed" and role == "customer_security"
                else "approve",
                "witnessed": True,
                "rationale": "private-review-prose-canary",
                "attestations": [str(witness.object_id)],
            },
        )
    result = report(store, store.head(head.dossier_id), core.object_id)
    assert set(result["roles"].values()) == (
        {"approve", "reject"} if mode == "failed" else {"approve"}
    )
    assert result["applicability"] == "current"
    assert result["status"] == mode
    assert "private-review" not in json.dumps(result)
    assert store.read_files(head.dossier_id, core) == before
    final = handoff(store, store.head(head.dossier_id), core.object_id)
    assert report(store, store.head(head.dossier_id), final.object_id)["recorded_status"] == mode


@pytest.mark.parametrize("reviewed", [False, True])
def test_supporting_attachment_requires_exact_sanitization_review(closeout_project, reviewed):
    """Valid private supporting text is excluded until its exact original bytes are reviewed."""
    from uuid import uuid4

    from closeout_support import instant

    from agent.closeout.models import byte_digest, digest
    from agent.closeout.review import record
    from agent.closeout.sources import import_source

    inv = inventory()
    inv["sources"][0]["format"] = "attachment-v1"
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inv))
    raw = b"Sanitized supporting fixture.\n"
    ref = import_source(
        store,
        head,
        {
            "profile_id": inv["sources"][0]["profile_id"],
            "format": "attachment-v1",
            "provenance": "operator",
            "input_digest": byte_digest(raw),
            "observed_at": instant(),
            "environment_digest": digest(store.inventory(head)),
            "scope": str(uuid4()),
            "media_type": "text/plain",
        },
        raw,
    )
    if reviewed:
        record(
            store,
            store.head(head.dossier_id),
            {
                "kind": "attachment",
                "subject_id": str(ref.object_id),
                "expected_digest": ref.seal_digest,
                "reviewer": "fixture-owner",
                "role": "vault_owner",
                "observed_at": instant(-1),
                "decision": "approve",
                "rationale": "sanitized exact bytes",
                "attestations": [str(ref.object_id)],
                "sanitized": True,
            },
        )
    assessed = assemble(store, store.head(head.dossier_id))
    core = build(store, store.head(head.dossier_id), assessed.object_id)
    files = store.read_files(head.dossier_id, core)
    assert any(name.startswith("attachment-") for name in files) == reviewed
    assert "source.raw" not in files


def test_image_container_integrity_and_polyglot_rejection():
    """A valid PNG works; header-only, checksum damage and appended archive/text fail."""
    import zlib

    from agent.closeout.attachments import jpeg, png

    def chunk(kind, body):
        """Produce a small real synthetic PNG container with standard chunk CRC."""
        return (
            len(body).to_bytes(4, "big") + kind + body + zlib.crc32(kind + body).to_bytes(4, "big")
        )

    raw = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", b"\0\0\0\1\0\0\0\1\x08\x02\0\0\0")
        + chunk(b"IDAT", zlib.compress(b"\0\xff\0\0"))
        + chunk(b"IEND", b"")
    )
    png(raw)
    for bad in (raw + b"<svg>canary</svg>", raw[:-1] + b"x", raw[:8]):
        with pytest.raises(CloseoutError):
            png(bad)
    with pytest.raises(CloseoutError):
        jpeg(b"\xff\xd8\xffnot-jpeg\xff\xd9")


def test_valid_jpeg_container_and_trailing_archive_rejection():
    """A bounded real JPEG framing is accepted, while appended hidden bytes are rejected."""
    from agent.closeout.attachments import jpeg

    def segment(marker, body):
        """Encode one small synthetic JPEG segment with its actual big-endian length."""
        return bytes((255, marker)) + (len(body) + 2).to_bytes(2, "big") + body

    raw = b"\xff\xd8" + segment(219, bytes(65))
    raw += segment(192, bytes((8, 0, 1, 0, 1, 1, 1, 17, 0)))
    raw += segment(196, bytes((0, 1)) + bytes(15) + bytes(1))
    raw += segment(196, bytes((16, 1)) + bytes(15) + bytes(1))
    raw += segment(218, bytes((1, 1, 0, 0, 63, 0))) + b"\x3f\xff\xd9"
    jpeg(raw)
    with pytest.raises(CloseoutError):
        jpeg(raw + b"PK\x03\x04")
