"""Root discovery must refuse ambiguity before private configuration dispatch."""

import subprocess

import pytest

from agent.project import require_root
from agent.security import SecurityError


def test_root_and_nested_checkout(tmp_path, monkeypatch):
    """A checkout root is valid; nested Git paths fail instead of mixing stores."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.chdir(tmp_path)
    assert require_root() == tmp_path.resolve()
    child = tmp_path / "nested"
    child.mkdir()
    monkeypatch.chdir(child)
    with pytest.raises(SecurityError, match="deployment_root_required"):
        require_root()


def test_installed_outside_git(tmp_path, monkeypatch):
    """Installed operation anchors consistently to the explicitly chosen directory."""
    monkeypatch.chdir(tmp_path)
    assert require_root() == tmp_path.resolve()


@pytest.mark.parametrize("failure", ["missing", "timeout", "malformed", "error"])
def test_discovery_failure_is_not_outside_git(tmp_path, monkeypatch, failure):
    """Broken Git is not evidence that it is safe to fall back to a fresh state root."""
    monkeypatch.chdir(tmp_path)

    def run(*args, **kwargs):
        """Simulate unavailable discovery without touching deployment files."""
        if failure == "missing":
            raise FileNotFoundError()
        if failure == "timeout":
            raise subprocess.TimeoutExpired("git", 1)
        return subprocess.CompletedProcess(
            args, 0 if failure == "malformed" else 128, stdout="ambiguous\n", stderr="other failure"
        )

    monkeypatch.setattr("agent.project.subprocess.run", run)
    with pytest.raises(SecurityError, match="deployment_root_unavailable"):
        require_root()


def test_worktree_and_two_deployment_roots(tmp_path, monkeypatch):
    """Independent worktrees remain separate canonical deployment directories."""
    first, second = tmp_path / "first", tmp_path / "second"
    subprocess.run(["git", "init", "-q", str(first)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(first),
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(first), "worktree", "add", "-qb", "second", str(second)], check=True
    )
    for root in (first, second):
        monkeypatch.chdir(root)
        assert require_root() == root.resolve()


def test_linked_logical_root_refused(tmp_path, monkeypatch):
    """A linked logical cwd cannot bypass the canonical-root safety rule."""
    real, link = tmp_path / "real", tmp_path / "link"
    real.mkdir()
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.chdir(link)
    monkeypatch.setenv("PWD", str(link))
    with pytest.raises(SecurityError, match="deployment_root_required"):
        require_root()


def test_cli_refuses_nested_before_invalid_private_settings(tmp_path):
    """Root denial must happen before poisonous dotenv can affect any stateful command."""
    import os
    import sys
    from pathlib import Path

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / ".env.local").write_text("TIMEOUT_SECONDS=invalid\n")
    env = os.environ | {"PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]}
    for arguments in (["setup", "check"], ["setup", "guide"], ["recover", "status"], ["workspace"]):
        result = subprocess.run(
            ["agent", *arguments], cwd=nested, env=env, text=True, capture_output=True, timeout=30
        )
        assert result.returncode != 0
        output = result.stdout + result.stderr
        assert "deployment_root_required" in output or "root-invalid" in output
        assert not (tmp_path / ".local").exists()
        assert not (nested / ".local").exists()
