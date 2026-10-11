"""Integrity, group aggregation and inspection never rewrite a run or promote native proof."""

import hashlib
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.security_regression.catalog import CASES, policies, selection_digest
from scripts.security_regression.isolation import content_digest
from scripts.security_regression.models import Frame, Integrity, Manifest, Seal, digest, now
from scripts.security_regression.report import inspect, native, precedence, reconstruct
from scripts.security_regression.store import Store


def seed(project, count=1, failure=False, profile="baseline", seal=True, case_id="policy-delta"):
    """Build strictly normalized disposable evidence for one actual compiled selector."""
    case = next(c for c in CASES if c.case_id == case_id)
    count = max(count, len(case.selectors))
    identifier = str(uuid4())
    manifest = Manifest(
        run_id=identifier,
        content_digest=content_digest(project),
        selection_digest=selection_digest([case], [profile]),
        started_at=now(),
        deadline_at=now(),
        cases=[case.case_id],
        profiles=[profile],
        complete_catalog=False,
        catalog_digest=digest([c.model_dump() for c in CASES]),
        profile_digests={profile: digest(policies()[profile])},
        versions={"python": "3.12"},
        base_digest="0" * 64,
        platform="macOS",
    )
    with Store(project).create(identifier) as writer:
        artifacts = {"manifest.json": writer.write("manifest.json", manifest)}
        if not seal:
            return identifier
        identity = {
            k: getattr(manifest, k) for k in ("run_id", "content_digest", "selection_digest")
        }
        identity["profile"] = profile
        inventory = [
            [
                case.selectors[i % len(case.selectors)],
                hashlib.sha256(str(i).encode()).hexdigest(),
                i + 1,
            ]
            for i in range(count)
        ]
        frames = []

        def emit(kind, **values):
            """Append a strict bounded frame with the correct monotonic sequence."""
            frame = Frame(**identity, seq=len(frames) + 1, kind=kind, **values)
            frames.append(frame.model_dump(mode="json", exclude_none=True, exclude_defaults=True))

        for selector, node, ordinal in inventory:
            emit("collection", selector=selector, node_digest=node, ordinal=ordinal)
        emit("collection", count=count, inventory_digest=digest(inventory))
        for selector, node, ordinal in inventory:
            emit(
                "item",
                selector=selector,
                node_digest=node,
                ordinal=ordinal,
                phases=["pass", "fail" if failure else "pass", "pass"],
            )
        emit(
            "terminal",
            count=count,
            inventory_digest=digest(inventory),
            exit_code=1 if failure else 0,
        )
        artifacts[f"{profile}.json"] = writer.write(
            f"{profile}.json",
            {
                "profile": profile,
                "frames": frames,
                "reason": "test_failed" if failure else None,
                "cleanup": "drained",
                "exit_code": 1 if failure else 0,
            },
        )
        writer.write(
            "seal.json",
            Seal(
                **{
                    k: getattr(manifest, k)
                    for k in ("run_id", "content_digest", "selection_digest")
                },
                artifacts=artifacts,
                profile_digests=manifest.profile_digests,
                count=count,
                state="failed" if failure else "completed",
                finished_at=now(),
                exit_code=1 if failure else 0,
                cleanup="drained",
                reason="test_failed" if failure else None,
            ),
        )
        report, _ = reconstruct(project, writer)
        report_digest = writer.write("report.json", report)
        writer.write(
            "integrity.json",
            Integrity(
                run_id=identifier,
                content_digest=manifest.content_digest,
                selection_digest=manifest.selection_digest,
                artifacts={
                    "seal.json": digest(writer.read("seal.json")),
                    "report.json": report_digest,
                },
            ),
        )
    return identifier


def test_all_native_rows_blocked():
    """Every native group names an owner, prerequisite, concrete action and recheck."""
    rows = native()
    assert len(rows) == 10
    assert {r["outcome"] for r in rows} == {"blocked"}
    assert all(
        all(0 < len(r[k]) <= 512 for k in ("prerequisite", "action", "recheck")) for r in rows
    )
    assert precedence(["pass", "blocked", "incomplete", "fail"]) == "fail"


def test_partial_report_and_immutable_failure(tmp_path):
    """Later passing UUIDs preserve failed runs and omitted groups remain incomplete."""
    old = seed(tmp_path, failure=True)
    new = seed(tmp_path)
    before = (tmp_path / ".local/security-regression" / old / "seal.json").read_bytes()
    failed, code = inspect(tmp_path, old)
    assert code == 1 and failed["state"] == "failed"
    passed, code = inspect(tmp_path, new)
    assert code == 0 and passed["scope"] == "partial"
    assert passed["groups"][7]["outcome"] == "pass"
    assert sum(g["reason"] == "not_selected" for g in passed["groups"]) == 9
    assert before == (tmp_path / ".local/security-regression" / old / "seal.json").read_bytes()


def test_unsealed_and_busy(tmp_path):
    """Active inspection is busy; abandoned manifests are incomplete and remain unmodified."""
    from scripts.security_regression.models import RegressionError

    run = seed(tmp_path, seal=False)
    result, code = inspect(tmp_path, run)
    assert code == 2 and result["reason"] == "incomplete_run"
    with Store(tmp_path).open(run):
        with pytest.raises(RegressionError, match="run_busy"):
            inspect(tmp_path, run)


@pytest.mark.parametrize("damage", ["missing", "extra", "corrupt", "copied"])
def test_integrity_damage(tmp_path, damage):
    """Missing, changed, additional and copied artifacts cannot produce a passing report."""
    import shutil

    from scripts.security_regression.models import RegressionError

    run = seed(tmp_path)
    root = tmp_path / ".local/security-regression" / run
    if damage == "missing":
        (root / "baseline.json").unlink()
    elif damage == "extra":
        path = root / "extra.json"
        path.write_text("{}")
        path.chmod(0o600)
    elif damage == "corrupt":
        (root / "baseline.json").write_text("{}")
    else:
        copied = str(uuid4())
        shutil.copytree(root, root.parent / copied)
        run = copied
    with pytest.raises(RegressionError):
        inspect(tmp_path, run)


@pytest.mark.parametrize(
    "relative",
    ["src/agent/new.py", "tests/test_new.py", "scripts/new.py", "config/policy.json", "uv.lock"],
)
def test_content_drift_is_historical(tmp_path, relative):
    """Source, tests, policy and lock changes make the old immutable result historical."""
    run = seed(tmp_path)
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("changed")
    result, code = inspect(tmp_path, run)
    assert code == 1 and result["freshness"] == "historical"


def test_real_repeated_partial_run(tmp_path):
    """Two guarded actual runs produce independent IDs and identical policy classifications."""
    from scripts.security_regression.catalog import select
    from scripts.security_regression.isolation import snapshot
    from scripts.security_regression.runner import run

    with snapshot(Path(__file__).resolve().parents[1]) as (project, _):
        cases, profiles = select(identifiers=["policy-delta"])
        first, code = run(project, cases, profiles)
        assert code == 0
        second, code = run(project, cases, profiles)
        assert code == 0
        assert first["run_id"] != second["run_id"]
        assert [(r["profile"], r["outcome"]) for r in first["cases"]] == [
            (r["profile"], r["outcome"]) for r in second["cases"]
        ]
        assert first["content_digest"] == second["content_digest"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.case_id)
def test_every_group_aggregates_independently(tmp_path, case):
    """Each reviewed group derives its own selected results and retains native blockers."""
    run = seed(tmp_path, case_id=case.case_id)
    report, code = inspect(tmp_path, run)
    assert code == 0
    assert [g["group"] for g in report["groups"] if g["outcome"] == "pass"] == case.groups
    assert all(n["outcome"] == "blocked" for n in report["native"])


def test_cli_list_run_report(tmp_path, capsys):
    """Exercise the same public commands against isolated maintained content and private storage."""
    import json

    from scripts.security_regression.isolation import snapshot
    from scripts.security_regression.runner import main

    with snapshot(Path(__file__).resolve().parents[1]) as (project, _):
        assert main(["list"], project=project) == 0
        listing = json.loads(capsys.readouterr().out)
        assert len(listing["cases"]) == len(CASES)
        assert not (project / ".local").exists()
        assert (
            main(["run", "--case", "policy-delta", "--profile", "restricted"], project=project) == 0
        )
        result = json.loads(capsys.readouterr().out)
        assert result["scope"] == "partial"
        assert main(["report", "--run", result["run_id"]], project=project) == 0
        assert json.loads(capsys.readouterr().out) == result
