"""Local recovery commands use no user authentication or implicit provider effects."""

import argparse
import json

import pytest

from agent.recovery.commands import add_recovery_parser, execute_recovery


def args(*words):
    """Parse the same command contract registered by the main CLI."""
    parser = argparse.ArgumentParser()
    add_recovery_parser(parser.add_subparsers(dest="command", required=True))
    return parser.parse_args(["recover", *words])


async def test_init_status_repeat_and_no_reset(tmp_path, recovery_settings, capsys):
    assert await execute_recovery(args("status"), settings=recovery_settings, project=tmp_path) == 2
    assert json.loads(capsys.readouterr().out)["reason_code"] == "recovery_uninitialized"
    assert await execute_recovery(args("init"), settings=recovery_settings, project=tmp_path) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "initialized"
    assert await execute_recovery(args("init"), settings=recovery_settings, project=tmp_path) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "unchanged"
    assert await execute_recovery(args("status"), settings=recovery_settings, project=tmp_path) == 0
    with pytest.raises(SystemExit):
        args("reset")


async def test_partial_state_and_changed_environment_fail(
    recovery_store, recovery_settings, tmp_path, capsys
):
    (recovery_store.root / "anchor.json").unlink()
    assert await execute_recovery(args("init"), settings=recovery_settings, project=tmp_path) == 1
    output = capsys.readouterr().out
    assert "recovery_storage_error" in output and "vault.example" not in output


async def test_review_import_and_repeat_are_private(recovery_store, tmp_path, capsys):
    from test_recovery_proof import pair, source, unresolved

    item = unresolved(recovery_store)
    evidence = source(recovery_store, pair(recovery_store, item, denied=True))
    command = args(
        "import",
        "--incident",
        str(item.incident_id),
        "--source",
        str(evidence),
        "--reviewer",
        "operator",
    )
    assert await execute_recovery(command, settings=recovery_store.settings, project=tmp_path) == 0
    first = recovery_store.read().attempts[0]
    assert first.resolution == "not_issued"
    assert await execute_recovery(command, settings=recovery_store.settings, project=tmp_path) == 0
    assert recovery_store.read().attempts[0].revision == first.revision
    output = capsys.readouterr().out
    assert str(evidence) not in output and "vault.example" not in output
    evidence.write_text("{}")
    assert await execute_recovery(command, settings=recovery_store.settings, project=tmp_path) == 1


async def test_exact_revoke_no_issuance_repeat_and_contention(recovery_store, tmp_path, capsys):
    import httpx
    from pydantic import SecretStr
    from test_recovery_proof import pair, source, unresolved

    item = unresolved(recovery_store)
    evidence = source(recovery_store, pair(recovery_store, item))
    assert (
        await execute_recovery(
            args(
                "import",
                "--incident",
                str(item.incident_id),
                "--source",
                str(evidence),
                "--reviewer",
                "operator",
            ),
            settings=recovery_store.settings,
            project=tmp_path,
        )
        == 0
    )
    command = args("revoke", "--incident", str(item.incident_id))
    assert await execute_recovery(command, settings=recovery_store.settings, project=tmp_path) == 2
    settings = recovery_store.settings.model_copy(
        update={"vault_token": SecretStr("PRIVATE TOKEN")}
    )
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "PUT" and request.url.path == "/v1/sys/leases/revoke"
        assert json.loads(request.content) == {
            "lease_id": "database/creds/read/native",
            "sync": True,
        }
        return httpx.Response(204)

    with recovery_store.effect():
        assert (
            await execute_recovery(
                command, settings=settings, project=tmp_path, transport=httpx.MockTransport(handler)
            )
            == 2
        )
    assert not calls
    assert (
        await execute_recovery(
            command, settings=settings, project=tmp_path, transport=httpx.MockTransport(handler)
        )
        == 0
    )
    assert (
        await execute_recovery(
            command, settings=settings, project=tmp_path, transport=httpx.MockTransport(handler)
        )
        == 0
    )
    assert len(calls) == 1 and "PRIVATE" not in capsys.readouterr().out


@pytest.mark.parametrize("failure", ["denied", "timeout", "queued"])
async def test_failed_operator_cleanup_remains_blocked_no_retry(
    recovery_store, tmp_path, failure, capsys
):
    import httpx
    from pydantic import SecretStr
    from test_recovery_proof import unresolved

    item = unresolved(recovery_store)
    recovery_store.update(
        item.incident_id, item.revision, lease_handle=item.credential_path + "/native"
    )
    calls = []

    def handler(request):
        calls.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("PRIVATE SOURCE ERROR")
        return httpx.Response(403 if failure == "denied" else 202, json={})

    config = recovery_store.settings.model_copy(update={"vault_token": SecretStr("PRIVATE TOKEN")})
    assert await execute_recovery(
        args("revoke", "--incident", str(item.incident_id)),
        settings=config,
        project=tmp_path,
        transport=httpx.MockTransport(handler),
    ) in {1, 2}
    assert len(calls) == 1 and recovery_store.read().attempts[0].state == "unresolved"
    assert "PRIVATE" not in capsys.readouterr().out


async def test_canceled_operator_keeps_effect_lock_until_cleanup_worker_stops(
    recovery_store, tmp_path
):
    import asyncio

    import httpx
    from pydantic import SecretStr
    from test_recovery_proof import unresolved

    from agent.recovery.store import RecoveryError

    item = unresolved(recovery_store)
    recovery_store.update(
        item.incident_id, item.revision, lease_handle=item.credential_path + "/native"
    )
    entered, release, canceled = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def handler(request):
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            canceled.set()
            await release.wait()
        return httpx.Response(204)

    settings = recovery_store.settings.model_copy(update={"vault_token": SecretStr("private")})
    operation = asyncio.create_task(
        execute_recovery(
            args("revoke", "--incident", str(item.incident_id)),
            settings=settings,
            project=tmp_path,
            transport=httpx.MockTransport(handler),
        )
    )
    await entered.wait()
    operation.cancel()
    await canceled.wait()
    with pytest.raises(RecoveryError, match="recovery_busy"):
        with recovery_store.effect():
            pass
    assert not operation.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await operation
    with recovery_store.effect():
        assert recovery_store.read().attempts[0].state == "unresolved"
