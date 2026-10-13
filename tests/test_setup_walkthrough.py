"""Maintained instructions and fixed-case walkthroughs agree with actual parser/catalog behavior."""

import argparse
from pathlib import Path

import pytest

from agent.setup.commands import add_setup_parser, initialize
from agent.setup.guidance import guide
from agent.setup.recipes import RECIPES, command

ROOT = Path(__file__).resolve().parents[1]


def test_instruction_contract():
    """The actual harness instructions contain recipes, base inputs and real handoffs."""
    text = (ROOT / "AGENTS.md").read_text()
    runbook = (ROOT / "docs/setup.md").read_text()
    for term in (
        *RECIPES,
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "LOGIN_SCOPES",
        "Playwright/WebKit",
        "after-prerequisites",
        "Exit 2",
        "exit 3",
        "review",
        "sign-in",
        "cleanup",
        "--no-sync",
        "--locked",
    ):
        assert term.lower() in text.lower(), term
    for recipe in RECIPES:
        assert recipe in runbook
        parser = argparse.ArgumentParser()
        add_setup_parser(parser.add_subparsers(dest="command"))
        args = parser.parse_args(["setup", "guide", "--recipe", recipe, "--format", "json"])
        assert args.recipe == recipe
        assert "--recipe " + recipe in command("check-local", recipe=recipe)

    import re

    from agent.settings import Settings

    settings = {name.upper() for name in Settings.model_fields}
    for line in text.splitlines():
        if line.startswith("| "):
            for name in re.findall(r"`([A-Z][A-Z0-9_]*)`", line):
                assert name in settings, name
    for recipe in ("workspace-read", "workspace-analysis"):
        for provider in ("google", "openai", "anthropic"):
            install = command("install-extras", recipe=recipe, provider=provider)
            assert "--extra server" in install and "--extra postgres" in install
            assert "--extra " + provider in install
            assert ("--extra sandbox" in install) is (recipe == "workspace-analysis")


def test_fresh_repeat_two_directory_walkthrough(tmp_path):
    """Preparation is non-overwriting and separate deployments do not share state."""
    from agent.settings import Settings

    roots = [tmp_path / "first", tmp_path / "second"]
    for root in roots:
        root.mkdir()
        initialize("user-jwt", project=root)
        path = root / ".env.local"
        original = path.read_bytes()
        settings = Settings(_env_file=path)
        for _ in range(3):
            assert initialize("delegated-exchange", project=root)["status"] == "unchanged"
            result = guide(settings, project=root)
            assert result.state == "needs-input" and result.exit_code == 2
            assert path.read_bytes() == original
            assert not (root / ".local").exists()
    assert roots[0] / ".env.local" != roots[1] / ".env.local"


def test_onboarding_accepts_only_fixed_cases():
    """The contributor helper does not admit arbitrary shell/test selection input."""
    from scripts.check_onboarding import parser

    for case in ("offline", "guided", "installed"):
        assert parser().parse_args(["--case", case]).case == case
    with pytest.raises(SystemExit):
        parser().parse_args(["--case", "echo private"])


def test_installed_probe_is_valid_fixed_python():
    """Catch quoting errors in the literal artifact probe before environment installation."""
    import ast

    from scripts.check_onboarding import INSTALLED_PROBE

    ast.parse(INSTALLED_PROBE)


def test_installed_case_refuses_editable_source(tmp_path):
    """A smoke check cannot declare an editable source import an artifact-install pass."""
    import os
    import time

    from scripts.check_onboarding import installed

    assert installed(os.environ.copy(), tmp_path, time.monotonic() + 30) == 2


def test_build_excludes_synthetic_private_canaries(tmp_path):
    """Both artifact formats exclude private bytes even when deployment files exist."""
    import os
    import shutil
    import subprocess
    import tarfile
    import zipfile

    for name in ("src", "config", "scripts"):
        shutil.copytree(ROOT / name, tmp_path / name, ignore=shutil.ignore_patterns("__pycache__"))
    for name in (
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "CONTRIBUTING.md",
        "compose.yaml",
        ".gitignore",
    ):
        shutil.copyfile(ROOT / name, tmp_path / name)
    canary = b"synthetic-private-artifact-canary"
    (tmp_path / ".env.local").write_bytes(canary)
    (tmp_path / ".local").mkdir()
    (tmp_path / ".local/enrollment").write_bytes(canary)
    env = {
        name: value
        for name, value in os.environ.items()
        if name in {"PATH", "HOME", "TMPDIR", "UV_CACHE_DIR"}
    }
    result = subprocess.run(
        ["uv", "build", "--offline"], cwd=tmp_path, env=env, capture_output=True, timeout=30
    )
    assert result.returncode == 0
    artifacts = [path for path in (tmp_path / "dist").iterdir() if path.suffix in {".whl", ".gz"}]
    assert len(artifacts) == 2
    for artifact in artifacts:
        if artifact.suffix == ".whl":
            with zipfile.ZipFile(artifact) as archive:
                contents = [(name, archive.read(name)) for name in archive.namelist()]
        else:
            with tarfile.open(artifact) as archive:
                contents = [
                    (member.name, archive.extractfile(member).read())
                    for member in archive.getmembers()
                    if member.isfile()
                ]
        assert contents
        for name, content in contents:
            assert ".env.local" not in name and "/.local/" not in name
            assert canary not in content
