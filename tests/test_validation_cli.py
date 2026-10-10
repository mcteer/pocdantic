import argparse
import json

from agent.validation.commands import add_validation_parser, execute_validation


def parse(*arguments):
    parser = argparse.ArgumentParser()
    add_validation_parser(parser.add_subparsers(dest="command", required=True))
    return parser.parse_args(["validate", *arguments])


async def test_list_is_safe(capsys):
    assert await execute_validation(parse("list", "--mode", "offline")) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["suites"]) == 1
    assert data["suites"][0]["label"] == "offline-security"


async def test_run_and_invalid_selection(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert await execute_validation(parse("run", "--scenario", "delegated-read")) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["scenarios"]) == 1 and len(data["acceptance"]) == 15
    for args in [
        ("run", "--scenario", "missing"),
        ("run", "--scenario", "policy-denial", "--scenario", "policy-denial"),
        ("run", "--suite", "live-phone", "--mode", "live", "--interactive"),
        ("run", "--suite", "live-phone", "--mode", "live", "--scenario", "phone-denied"),
        ("run", "--root", str(tmp_path / "outside")),
    ]:
        assert await execute_validation(parse(*args)) == 2
        assert "private" not in capsys.readouterr().out


async def test_cli_import_review_report_without_provider_requests(tmp_path, monkeypatch, capsys):
    import socket
    from datetime import UTC, datetime, timedelta
    from pathlib import Path

    monkeypatch.chdir(tmp_path)

    def denied(*args, **kwargs):
        raise AssertionError("provider requests forbidden")

    monkeypatch.setattr(socket.socket, "connect", denied)
    assert await execute_validation(parse("run", "--scenario", "delegated-read")) == 0
    first = json.loads(capsys.readouterr().out)
    run = first["validation_id"]
    time = datetime.now(UTC)
    raw = {"type": "request", "time": time.isoformat(), "request": {"id": "synthetic-native"}}
    Path("input.jsonl").write_text(json.dumps(raw))
    Path("manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_kind": "vault",
                "format_label": "vault-jsonl",
                "format_version": 1,
                "source_instance": "private-source-canary",
                "window_start": (time - timedelta(seconds=1)).isoformat(),
                "window_end": (time + timedelta(seconds=1)).isoformat(),
                "completeness": "partial",
                "provenance": "operator_export",
            }
        )
    )
    assert (
        await execute_validation(
            parse(
                "import",
                "--run",
                run,
                "--source",
                "vault",
                "--input",
                "input.jsonl",
                "--manifest",
                "manifest.json",
            )
        )
        == 0
    )
    imported = json.loads(capsys.readouterr().out)
    assert set(imported) == {"artifact_id", "status"}
    assert await execute_validation(parse("report", "--run", run)) == 0
    report = json.loads(capsys.readouterr().out)
    Path("review.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "reviewer": "private-reviewer-canary",
                "rationale": "private-rationale-canary",
                "observed_at": time.isoformat(),
                "expected_revision": report["acceptance"][0]["evidence_revision"],
                "references": [],
            }
        )
    )
    assert (
        await execute_validation(
            parse(
                "review",
                "--run",
                run,
                "--criterion",
                "UC1-01",
                "--decision",
                "blocked",
                "--review-file",
                "review.json",
            )
        )
        == 0
    )
    assert "canary" not in capsys.readouterr().out
    assert await execute_validation(parse("report", "--run", run)) == 0
    final = json.loads(capsys.readouterr().out)
    assert len(final["acceptance"]) == 15
    assert "canary" not in json.dumps(final)
