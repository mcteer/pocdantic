"""Zero-effect closeout command flows and useful safe operator outcomes."""

import argparse
import asyncio
import json

import pytest
from closeout_support import inventory, private_file

from agent.cli import execute
from agent.closeout.commands import add_closeout_parser


def parser():
    """Register the actual closeout argument surface for dispatcher integration tests."""
    result = argparse.ArgumentParser()
    add_closeout_parser(result.add_subparsers(dest="command", required=True))
    return result


def command(capsys, *args):
    """Execute the actual CLI parser/dispatcher and decode its safe JSON projection."""
    code = asyncio.run(execute(parser().parse_args(["closeout", *map(str, args)])))
    return code, json.loads(capsys.readouterr().out)


def prepare_cli(project, capsys):
    """Prepare a structural synthetic dossier via the installed command interface."""
    path = private_file(project / "inventory-input", inventory())
    code, value = command(capsys, "prepare", "--inventory", path)
    assert code == 0
    return value["dossier_id"]


def test_empty_dossier_guides_and_stale_amend(closeout_project, capsys):
    """Missing native proof remains actionable while ordinary local commands complete."""
    did = prepare_cli(closeout_project, capsys)
    code, output = command(capsys, "guide", "--dossier", did)
    assert code == 0 and len(output["guides"]) == 8
    assert output["status"] == "blocked"
    code, output = command(capsys, "inspect", "--dossier", did)
    assert code == 0 and output["revision"] == 1 and len(output["criteria"]) == 15
    path = private_file(closeout_project / "amend-input", inventory())
    assert command(capsys, "amend", "--dossier", did, "--revision", 1, "--inventory", path)[0] == 0
    code, output = command(capsys, "amend", "--dossier", did, "--revision", 1, "--inventory", path)
    assert code == 2 and output["reason"] == "revision_conflict"


def test_invalid_selector_not_a_command(capsys):
    """Argparse rejects command-shaped selectors before storage or effects."""
    with pytest.raises(SystemExit):
        parser().parse_args(["closeout", "guide", "--dossier", "x", "--use-case", "UC1;echo"])


def test_complete_blocked_lifecycle_and_readonly_reports(closeout_project, capsys):
    """Every installed closeout lifecycle command dispatches without provider initialization."""
    did = prepare_cli(closeout_project, capsys)
    _, assessed = command(capsys, "assess", "--dossier", did, "--revision", 1)
    assert assessed["revision"] == 2
    code, report = command(
        capsys, "report", "--dossier", did, "--assessment", assessed["object_id"]
    )
    assert code == 2 and report["status"] == "blocked" and len(report["criteria"]) == 15
    _, core = command(
        capsys, "package", "--dossier", did, "--revision", 2, "--assessment", assessed["object_id"]
    )
    assert core["revision"] == 3
    _, final = command(
        capsys, "handoff", "--dossier", did, "--revision", 3, "--package", core["object_id"]
    )
    assert final["revision"] == 4
    code, report = command(capsys, "report", "--dossier", did, "--package", final["object_id"])
    assert code == 2 and report["applicability"] == "current" and report["status"] == "blocked"
    assert command(capsys, "inspect", "--dossier", did)[1]["revision"] == 4


def test_private_invalid_argument_is_not_echoed(capsys):
    """Parser diagnostics never expose an invalid identifier or hostile trailing text."""
    from uuid import uuid4

    for args in (
        ["guide", "--dossier", "native-private-canary"],
        ["guide", "--dossier", str(uuid4()), "native-private-canary"],
    ):
        with pytest.raises(SystemExit):
            parser().parse_args(["closeout", *args])
        output = capsys.readouterr()
        assert "native-private-canary" not in output.out + output.err


@pytest.mark.parametrize(
    "scenario,total",
    [("agent-repeat", 1), ("agent-only-users", 1), ("agent-obo-users", 101), ("direct-users", 100)],
)
def test_four_experiment_cli_flows(closeout_project, monkeypatch, capsys, scenario, total):
    """The installed dispatcher preserves all four exact scenario counts."""
    from test_closeout_counting import measurement_lifecycle

    measurement = measurement_lifecycle(closeout_project, monkeypatch, scenario, capsys=capsys)
    assert measurement["counts"]["scenario"] == total
    assert measurement["outcome"] == "pass"
