"""Provider commands expose fixed private enrollment and disk-only inspection."""

import argparse
import json

from provider_support import provider_store

from agent.response.commands import add_response_parser, execute_response


def arguments(*values):
    """Parse the public CLI hierarchy independently from ambient Settings."""
    parser = argparse.ArgumentParser()
    add_response_parser(parser.add_subparsers(dest="command", required=True))
    return parser.parse_args(["respond", *values])


async def test_prepare_status_enroll_without_network(tmp_path, workspace_settings, capsys):
    """Draft creation and safe status never dispatch provider requests."""
    store = provider_store(workspace_settings, tmp_path)
    assert await execute_response(arguments("providers", "prepare"), store=store) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "prepared"
    assert await execute_response(arguments("providers", "status"), store=store) == 0
    capsys.readouterr()
    revision = store.read().revision
    assert (
        await execute_response(
            arguments("providers", "enroll", "--revision", str(revision)), store=store
        )
        == 0
    )
    capsys.readouterr()
    assert await execute_response(arguments("providers", "status"), store=store) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["enrolled"] and "bindings" not in status


async def test_migration_idempotent(tmp_path, workspace_settings, capsys):
    """Migrating an initialized v2 store preserves authority and returns current."""
    store = provider_store(workspace_settings, tmp_path)
    assert await execute_response(arguments("migrate"), store=store) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "current"


def test_provider_operator_commands_parse():
    """Each operator command has explicit correlation and no secret-bearing flags."""
    from uuid import uuid4

    incident = str(uuid4())
    assert arguments("providers", "status", "--incident", incident).incident
    for command in ("reconcile", "import"):
        flags = ("--file", "evidence.json", "--operator", "reviewer") if command == "import" else ()
        args = arguments("providers", command, "--incident", incident, "--revision", "1", *flags)
        assert args.provider_command == command
    assert arguments(
        "providers", "retry", "--action", incident, "--revision", "1", "--operator", "reviewer"
    ).action


async def test_explicit_retry_runs_linked_attempt_once(tmp_path, workspace_settings, capsys):
    """An operator retry reads first, keeps predecessor history and dispatches one new action."""
    import httpx
    from pydantic import SecretStr
    from test_provider_worker import planned

    from agent.response.providers.worker import change

    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    store, _ = planned(settings, tmp_path)
    action = store.read().provider_actions[0]
    change(store, action.action_id, state="denied", reason="provider_denied")
    calls = []

    def handle(request):
        """Read current presence, then acknowledge the requested exact deletion."""
        calls.append(request.method)
        return (
            httpx.Response(200, json={"data": {"id": action.binding.native_id}})
            if request.method == "GET"
            else httpx.Response(204)
        )

    code = await execute_response(
        arguments(
            "providers",
            "retry",
            "--action",
            str(action.action_id),
            "--revision",
            str(store.read().revision),
            "--operator",
            "reviewer",
        ),
        store=store,
        transport=httpx.MockTransport(handle),
    )
    output = json.loads(capsys.readouterr().out)
    assert code == 0 and calls == ["GET", "DELETE"] and output["state"] == "acknowledged"
    assert store.read().provider_actions[0].state == "denied"


async def test_busy_probe_has_closed_error(tmp_path, workspace_settings, capsys):
    """A retained proof owner produces actionable closed output, never a filesystem traceback."""
    import pytest

    from agent.response.models import ResponseError
    from agent.response.providers.models import ProofInput
    from agent.response.providers.workflow import isolated_probe

    store = provider_store(workspace_settings, tmp_path)
    with store._lock("probe.lock"):
        with pytest.raises(ResponseError, match="provider_busy"):
            await isolated_probe(store, inputs=ProofInput())
