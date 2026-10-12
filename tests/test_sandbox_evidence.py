"""Source drift invalidates sandbox evidence; native catalog linkage stays separate."""

import shutil
from pathlib import Path

from agent.validation import models
from agent.validation.catalog import load_catalog


def test_sandbox_source_drift_and_original_catalog(tmp_path, monkeypatch):
    """Changing only the sandbox source changes the implementation-bound evidence revision."""
    root = tmp_path / "agent"
    shutil.copytree(Path("src/agent"), root, ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setattr(models, "files", lambda _: root)
    models.implementation_revision.cache_clear()
    try:
        before = models.implementation_revision()
        file = root / "sandbox/runner.py"
        file.write_text(file.read_text() + "\n# Changed reviewed sandbox boundary.\n")
        models.implementation_revision.cache_clear()
        assert models.implementation_revision() != before
    finally:
        models.implementation_revision.cache_clear()
    catalog = load_catalog()
    assert "user-jwt-read" in {q.label for s in catalog.suites for q in s.scenarios}
    assert not any(q.label.startswith("sandbox") for s in catalog.suites for q in s.scenarios)
