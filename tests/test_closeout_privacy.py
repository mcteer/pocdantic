"""Private canaries never enter safe projections or the publication/distribution allowlist."""

import json

import pytest
from closeout_support import inventory

from agent.closeout.assessment import assemble, report
from agent.closeout.models import CloseoutError, Inventory, byte_digest, digest, validate
from agent.closeout.package import build, handoff
from agent.closeout.sources import import_source, reject_secrets
from agent.closeout.store import Store


def test_native_inventory_canary_absent_from_both_bundles(closeout_project):
    """Generated summaries contain opaque IDs/digests instead of native identifiers."""
    inv = inventory()
    inv["sources"][0]["instance"] = "native-instance-confidential-canary"
    inv["definitions"][0]["reference"] = "human-subject-confidential-canary"
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inv))
    assessment = assemble(store, head)
    public = json.dumps(report(store, store.head(head.dossier_id), assessment.object_id))
    core = build(store, store.head(head.dossier_id), assessment.object_id)
    final = handoff(store, store.head(head.dossier_id), core.object_id)
    for ref in (core, final):
        public += "".join(
            raw.decode(errors="replace") for raw in store.read_files(head.dossier_id, ref).values()
        )
    assert "confidential-canary" not in public


@pytest.mark.parametrize(
    "raw",
    [
        b'{"password":"secret-canary"}',
        b"Bearer private-canary",
        b"-----BEGIN " + b"PRIVATE KEY-----",
    ],
)
def test_known_secret_text_rejected(raw):
    """Safe exceptions contain a reason code and none of the input credential."""
    with pytest.raises(CloseoutError) as caught:
        reject_secrets(raw)
    assert "canary" not in str(caught.value)


@pytest.mark.parametrize(
    "media,raw",
    [("image/png", b"not-png"), ("image/jpeg", b"not-jpeg"), ("text/plain", b"Bearer canary")],
)
def test_attachment_type_and_secret_fail_before_mutation(closeout_project, media, raw):
    """An untrusted extension or sanitizer claim cannot admit invalid source bytes."""
    inv = inventory()
    inv["sources"][0]["format"] = "attachment-v1"
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inv))
    from uuid import uuid4

    manifest = {
        "profile_id": inv["sources"][0]["profile_id"],
        "format": "attachment-v1",
        "provenance": "operator",
        "input_digest": byte_digest(raw),
        "observed_at": __import__("agent.closeout.models", fromlist=["now"]).now().isoformat(),
        "environment_digest": digest(store.inventory(head)),
        "scope": str(uuid4()),
        "media_type": media,
    }
    with pytest.raises(CloseoutError):
        import_source(store, head, manifest, raw)
    assert store.head(head.dossier_id).revision == 1


@pytest.mark.parametrize(
    "name",
    [
        "payload.json",
        "seal.json",
        "dossier-any.json",
        "measurement-any.json",
        "attachment-any.png",
        "core-inventory.json",
        "handoff-any.json",
    ],
)
def test_generated_names_rejected(name):
    """Generated closeout files cannot become distributable by placement in an allowed tree."""
    from scripts.publish_policy import generated_private

    assert generated_private("config/" + name)


@pytest.mark.parametrize(
    "keys",
    [
        ("dossier_id", "inventory_id", "records"),
        ("review_id", "subject_id", "attestations"),
        ("measurement_id", "experiment_id", "dependencies"),
        ("package_id", "assessment_digest", "review_dependencies"),
    ],
)
def test_renamed_damaged_private_shapes_rejected(keys):
    """Recognizable identity/digest relationships survive both renaming and malformed JSON."""
    from scripts.publish_policy import private_content

    data = b"{" + b",".join(json.dumps(key).encode() + b":null" for key in keys)
    assert private_content("config/innocent.json", data)


@pytest.mark.parametrize(
    "raw",
    [
        b"hvs." + b"x" * 24,
        b"ghp_" + b"x" * 32,
        b'{"client_token":"private-canary"}',
        b'{"token":"private-canary"}',
    ],
)
def test_plaintext_provider_credentials_rejected(raw):
    """Provider token shapes and plaintext token fields cannot enter imported source bytes."""
    with pytest.raises(CloseoutError):
        reject_secrets(raw)


def test_masked_vault_audit_client_token_is_not_a_credential():
    """A native audit HMAC remains usable without permitting the original client token."""
    reject_secrets(b'{"client_token":"hmac-sha256:' + b"a" * 64 + b'"}')
