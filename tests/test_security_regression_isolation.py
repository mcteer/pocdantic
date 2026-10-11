"""Snapshot identity includes maintained files but excludes private ambient state."""

import pytest
from test_security_regression_execution import isolated_probe as isolated_probe

from scripts.security_regression.isolation import content_digest, snapshot
from scripts.security_regression.models import RegressionError


def test_snapshot_includes_new_files_and_excludes_private(tmp_path):
    """New maintained bytes change identity; private dotenv files never enter a child."""
    project = tmp_path / "project"
    (project / "tests").mkdir(parents=True)
    (project / "tests/test_new.py").write_text("x=1")
    (project / ".env.local").write_text("private")
    before = content_digest(project)
    with snapshot(project) as (root, identity):
        assert identity == before
        assert (root / "tests/test_new.py").read_text() == "x=1"
        assert not (root / ".env.local").exists()
    (project / "tests/test_new.py").write_text("x=2")
    assert content_digest(project) != before


def test_snapshot_rejects_symlink(tmp_path):
    """Eligible symlinks cannot import code or secrets from outside the snapshot."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_link.py").symlink_to("/etc/passwd")
    with pytest.raises(RegressionError, match="unsafe_path"):
        content_digest(tmp_path)


def test_environment_has_no_provider_or_plugin_values(monkeypatch):
    """The child environment is constructed explicitly rather than filtered by a denylist."""
    from scripts.security_regression.isolation import environment

    monkeypatch.setenv("VAULT_TOKEN", "PRIVATE_AMBIENT")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("PYTHONPATH", "/private/host")
    values = environment("baseline")
    assert not {"VAULT_TOKEN", "PYTEST_ADDOPTS", "PYTHONPATH", "HOME"}.intersection(values)
    assert values["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"


def test_settings_and_import_origin_before_collection(isolated_probe):
    """Default dotenv is disabled and editable agent imports resolve into the owned snapshot."""
    from test_security_regression_execution import probe

    (isolated_probe / ".env.local").write_text("MODEL=PRIVATE_AMBIENT")
    source = (
        "from pathlib import Path\nimport agent\nfrom agent.settings import Settings\n"
        "assert Path(agent.__file__).resolve().is_relative_to(Path.cwd()/'src')\n"
        "assert Settings.model_config['env_file'] is None\n"
        "assert Settings().model != 'PRIVATE_AMBIENT'\n"
        "def test_probe(): assert True"
    )
    result = probe(isolated_probe, source)
    assert result["reason"] is None
