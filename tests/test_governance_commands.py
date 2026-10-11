"""CLI boundary keeps credentials private and exposes every compiled operator command."""

import argparse
import asyncio
import json

import pytest
from governance_support import installed, source

from agent.governance.commands import add_governance_parser, execute_governance


def parser():
    """Construct only the additive governance parser without loading live settings."""
    root = argparse.ArgumentParser()
    add_governance_parser(root.add_subparsers(dest="command"))
    return root


@pytest.mark.parametrize("command", ["status", "serve", "relying serve"])
def test_compiled_readonly_commands_are_registered(command):
    assert parser().parse_args(["govern", *command.split()]).govern_command


def test_status_lists_retained_attempt_ids_without_native_values(tmp_path, capsys):
    store = installed(tmp_path)
    store.configure((source(),), 1)
    item = store.case("fixture")
    intent = store.intent(item.candidate_id, "actor_oauth")
    args = parser().parse_args(["govern", "status"])
    assert asyncio.run(execute_governance(args, store=store)) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["attempts"][0]["attempt_id"] == str(intent.intent_id)
    assert result["candidates"][0]["reason_code"] == "issuance_unresolved"
    assert "collector" not in str(result)
    assert "poison-unused" not in str(result)


def test_local_close_exit_reports_unknown_issuance(tmp_path, capsys):
    store = installed(tmp_path)
    store.configure((source(),), 1)
    item = store.case("fixture")
    store.intent(item.candidate_id, "svid")
    args = parser().parse_args(
        [
            "govern",
            "close",
            "--candidate",
            str(item.candidate_id),
            "--revision",
            str(store.read().revision),
            "--operator",
            "reviewer",
        ]
    )
    assert asyncio.run(execute_governance(args, store=store)) == 3
    assert json.loads(capsys.readouterr().out)["reason_code"] == "issuance_unresolved"


def test_non_tty_redirected_file_is_supported_without_exporting_token(tmp_path, monkeypatch):
    """Regular stdin works on Linux epoll as well as macOS kqueue."""
    import sys

    from agent.governance.commands import human_input

    path = tmp_path / "human.json"
    path.touch(mode=0o600)
    path.write_text(json.dumps({"schema_version": 1, "human_token": "ephemeral-fixture"}))
    with path.open() as file:
        monkeypatch.setattr(sys, "stdin", file)
        assert asyncio.run(human_input()) == "ephemeral-fixture"
