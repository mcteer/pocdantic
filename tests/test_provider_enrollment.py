"""Only explicit quiescent enrollment changes provider authority."""

import os
from uuid import uuid4

import pytest
from provider_support import activate, enrollment, provider_store, resource
from response_support import principal

from agent.response.models import ResponseError


def test_atomic_enrollment_and_stale_revision(tmp_path, workspace_settings):
    """A draft becomes active in one journal commit; stale choices cannot replace it."""
    from agent.response.providers.enrollment import enroll

    store = provider_store(workspace_settings, tmp_path)
    draft = enrollment(store, bindings=(resource(workspace_settings),))
    rev = store.read().revision
    active = activate(store, draft)
    assert active.enrollment == draft
    with pytest.raises(ResponseError, match="revision_conflict"):
        enroll(store, draft, rev)


def test_enrollment_rejects_live_owner(tmp_path, workspace_settings):
    """Changing a resource mapping cannot race active root execution."""
    store = provider_store(workspace_settings, tmp_path)
    draft = enrollment(store)
    run, fd = store.register(uuid4(), uuid4(), principal(workspace_settings))
    try:
        with pytest.raises(ResponseError, match="provider_busy"):
            activate(store, draft)
    finally:
        store.finish(run)
        os.close(fd)


def test_private_draft_no_overwrite_or_unsafe_secret_file(tmp_path, workspace_settings):
    """Preparation is owner-only and refuses symlinks or broad permissions."""
    from agent.response.providers.enrollment import prepare, read_secrets

    store = provider_store(workspace_settings, tmp_path)
    assert prepare(store)
    assert prepare(store) is False
    path = store.root / "provider-secrets.json"
    assert path.stat().st_mode & 0o777 == 0o600
    path.chmod(0o644)
    with pytest.raises(ResponseError):
        read_secrets(store)


def test_same_workflow_different_signature_rejected(tmp_path, workspace_settings):
    """URL signature rotation cannot create a second canonical notification destination."""
    from agent.response.providers.enrollment import digest, enroll, write_private
    from agent.response.providers.models import ReadinessRecord
    from agent.validation.models import canonical

    store = provider_store(workspace_settings, tmp_path)
    bindings = (
        resource(workspace_settings, "teams", alias="notice-one", secret_alias="hook-one"),
        resource(
            workspace_settings,
            "teams",
            alias="notice-two",
            secret_alias="hook-two",
            native_id="other-alias",
        ),
    )
    policy = enrollment(store, bindings=bindings)
    secrets = store.root / "provider-secrets.json"
    secrets.write_bytes(
        canonical(
            {
                "hook-one": "https://provider.example/workflow?sig=one",
                "hook-two": "https://provider.example/workflow?sig=two",
            }
        )
    )
    secrets.chmod(0o600)
    state = store.read()
    write_private(
        store,
        "providers.readiness.json",
        ReadinessRecord(
            installation_id=state.installation_id,
            environment_digest=state.environment_digest,
            draft_digest=digest(policy),
            bindings=bindings,
        ),
    )
    with pytest.raises(ResponseError, match="provider_evidence_invalid"):
        enroll(store, policy, state.revision)
