"""Exact administrative cleanup follows owner drain and cannot borrow delegated authority."""

from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr
from response_support import enrolled, principal, signal

from agent.recovery.store import RecoveryStore
from agent.response.coordinator import Coordinator
from agent.validation.models import canonical


def setup_attempt(tmp_path, settings, *, auto=False, known=True):
    recovery = RecoveryStore(settings, project=tmp_path)
    recovery.initialize()
    response = enrolled(settings, tmp_path, recovery=recovery)
    if auto:
        policy = response.policy().model_copy(update={"automatic_cleanup": True})
        (response.root / "policy.json").write_bytes(canonical(policy))
        # Enrollment fixture changes before any work; production has no policy-reset API.
        import hashlib

        with response._lock("control.lock"), response._directory() as fd:
            from agent.response.providers.journal import parse_journal

            state = parse_journal(response._read_file(fd, "state.json"))
            response._write(
                fd,
                state.model_copy(
                    update={"policy_digest": hashlib.sha256(canonical(policy)).hexdigest()}
                ),
            )
    run, fd = response.register(uuid4(), uuid4(), principal(settings))
    import os

    with recovery.effect() as owner:
        item = recovery.begin(owner, run.ownership())
        if known:
            item = recovery.update(
                item.incident_id,
                item.revision,
                state="acquired",
                lease_handle=settings.vault_read_path + "/lease1",
            )
        item = recovery.update(item.incident_id, item.revision, state="unresolved")
    response.finish(run)
    os.close(fd)
    return response, recovery, run, item


async def test_exact_cleanup_and_duplicate_no_revoke(tmp_path, recovery_settings):
    settings = recovery_settings.model_copy(update={"vault_token": SecretStr("operator-fixture")})
    response, recovery, run, attempt = setup_attempt(tmp_path, settings, auto=True)
    calls = []

    def provider(request):
        calls.append(request)
        assert request.method == "PUT" and request.url.path == "/v1/sys/leases/revoke"
        import json

        assert json.loads(request.content) == {
            "lease_id": settings.vault_read_path + "/lease1",
            "sync": True,
        }
        return httpx.Response(204)

    coordinator = Coordinator(response, transport=httpx.MockTransport(provider))
    event = signal(settings, root=run.root_run_id)
    item, _ = coordinator.submit(event)
    assert (await coordinator.process(item.incident_id)).phase == "settled"
    assert recovery.read().attempts[0].state == "resolved"
    coordinator.submit(event)
    coordinator.reconcile(item.incident_id)
    assert len(calls) == 1


@pytest.mark.parametrize("known", [True, False])
async def test_incomplete_stays_held_without_provider(tmp_path, recovery_settings, known):
    response, recovery, run, attempt = setup_attempt(tmp_path, recovery_settings, known=known)
    coordinator = Coordinator(
        response, transport=httpx.MockTransport(lambda _: pytest.fail("unexpected provider call"))
    )
    item, _ = coordinator.submit(signal(recovery_settings, root=run.root_run_id))
    result = await coordinator.process(item.incident_id)
    assert result.phase == "partial" and response.read().root_holds
    assert result.reason_code == ("cleanup_denied" if known else "acquisition_uncertain")


async def test_non_database_settles_and_releases(tmp_path, workspace_settings):
    response = enrolled(workspace_settings, tmp_path)
    coordinator = Coordinator(response)
    item, _ = coordinator.submit(signal(workspace_settings))
    assert (await coordinator.process(item.incident_id)).phase == "settled"
    coordinator.release(
        workspace_settings.workload_definition,
        [item.incident_id],
        response.read().revision,
        "fixture",
    )
    assert not response.read().holds


async def test_overlap_does_not_repeat_uncertain_revoke(tmp_path, recovery_settings):
    """A second incident cannot turn an earlier submitted cleanup into retry authority."""
    settings = recovery_settings.model_copy(update={"vault_token": SecretStr("fixture")})
    response, recovery, run, attempt = setup_attempt(tmp_path, settings, auto=True)
    calls = []

    def lost_response(request):
        """Simulate an effect whose provider acknowledgement is lost."""
        calls.append(request)
        raise httpx.ReadError("private canary", request=request)

    coordinator = Coordinator(response, transport=httpx.MockTransport(lost_response))
    one, _ = coordinator.submit(signal(settings, root=run.root_run_id))
    assert (await coordinator.process(one.incident_id)).phase == "partial"
    two, _ = coordinator.submit(signal(settings, root=run.root_run_id, event="event-002"))
    assert (await coordinator.process(two.incident_id)).phase == "partial"
    assert len(calls) == 1 and response.read().root_holds


async def test_release_rejects_stale_revision_and_incomplete_set(tmp_path, workspace_settings):
    """Release names every current definition incident and compares the current journal."""
    from agent.response.models import ResponseError

    response = enrolled(workspace_settings, tmp_path)
    coordinator = Coordinator(response)
    one, _ = coordinator.submit(signal(workspace_settings))
    two, _ = coordinator.submit(signal(workspace_settings, event="event-002"))
    await coordinator.process(one.incident_id)
    await coordinator.process(two.incident_id)
    revision = response.read().revision
    with pytest.raises(ResponseError, match="release_unsafe"):
        coordinator.release(
            workspace_settings.workload_definition, [one.incident_id], revision, "fixture"
        )
    with pytest.raises(ResponseError, match="revision_conflict"):
        coordinator.release(
            workspace_settings.workload_definition,
            [one.incident_id, two.incident_id],
            revision - 1,
            "fixture",
        )
    assert response.read().holds


async def test_ordinary_cleanup_receipt_is_joined_without_second_revoke(
    tmp_path, recovery_settings
):
    """The ordinary owner remains authoritative through cleanup; response joins its proof."""
    from agent.recovery.models import Receipt

    response, recovery, run, attempt = setup_attempt(tmp_path, recovery_settings)
    coordinator = Coordinator(
        response, transport=httpx.MockTransport(lambda _: pytest.fail("second revoke"))
    )
    item, _ = coordinator.submit(signal(recovery_settings, root=run.root_run_id))
    pending = recovery.update(attempt.incident_id, attempt.revision, state="cleanup_pending")
    receipt = Receipt(
        outcome="revoked",
        incident_id=pending.incident_id,
        incident_revision=pending.revision,
        operation_id=pending.operation_id,
        environment_digest=pending.environment_digest,
    )
    recovery.update(
        pending.incident_id,
        pending.revision,
        state="resolved",
        resolution="revoked",
        receipt=receipt,
    )
    result = await coordinator.process(item.incident_id)
    assert result.phase == "settled" and all(a.status == "confirmed" for a in result.actions)


async def test_only_target_lease_selected_and_legacy_prevents_completion(
    tmp_path, recovery_settings
):
    """Sibling attribution stays untouched; legacy uncertainty is an explicit shared block."""
    import os
    from uuid import uuid4

    from agent.recovery.models import AttemptV2, LegacyOwnership

    response, recovery, run, attempt = setup_attempt(tmp_path, recovery_settings)
    sibling, fd = response.register(uuid4(), uuid4(), principal(recovery_settings))
    # Native effects remain globally serialized. Inject two valid historical records
    # to test attribution without claiming concurrent native acquisitions.
    other = AttemptV2(
        incident_id=uuid4(),
        operation_id=uuid4(),
        environment_digest=recovery.read().environment_digest,
        credential_path=recovery_settings.vault_read_path,
        state="unresolved",
        ownership=sibling.ownership(),
    )
    with recovery._lock("journal.lock"), recovery._directory() as directory:
        journal = recovery._read(directory)
        recovery._write(
            directory,
            type(journal).model_validate(
                journal.model_dump() | {"attempts": (*journal.attempts, other)}
            ),
        )
    response.finish(sibling)
    os.close(fd)
    coordinator = Coordinator(response)
    incident, _ = coordinator.submit(signal(recovery_settings, root=run.root_run_id))
    coordinator.reconcile(incident.incident_id)
    ids = {
        a.target_id
        for a in coordinator.get(incident.incident_id).actions
        if a.kind == "revoke_exact"
    }
    assert ids == {attempt.incident_id}
    journal = recovery.read()
    legacy = AttemptV2.model_validate(other.model_dump() | {"ownership": LegacyOwnership()})
    with recovery._lock("journal.lock"), recovery._directory() as directory:
        recovery._write(
            directory,
            type(journal).model_validate(
                journal.model_dump()
                | {
                    "attempts": tuple(
                        legacy if a.incident_id == other.incident_id else a
                        for a in journal.attempts
                    )
                }
            ),
        )
    result = coordinator.reconcile(incident.incident_id)
    assert result.phase == "partial" and result.reason_code == "legacy_unattributed"


async def test_worker_budget_exhaustion_preserves_owner_hold(tmp_path, workspace_settings):
    """A live lifetime lock keeps cancellation unconfirmed when the bounded worker exits."""
    import os
    import time

    response = enrolled(workspace_settings, tmp_path)
    run, fd = response.register(uuid4(), uuid4(), principal(workspace_settings))
    coordinator = Coordinator(response, work_budget=0.01)
    incident, _ = coordinator.submit(signal(workspace_settings, root=run.root_run_id))
    start = time.monotonic()
    result = await coordinator.process(incident.incident_id)
    assert time.monotonic() - start < 2
    assert result.phase == "partial" and result.reason_code == "owner_draining"
    assert result.actions[0].status == "planned"
    response.finish(run)
    os.close(fd)
    assert coordinator.reconcile(incident.incident_id).phase == "settled"
