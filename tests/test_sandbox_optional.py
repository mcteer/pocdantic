"""Optional dependency detection must not disturb unrelated profiles."""

from agent.sandbox import available


def test_missing_optional_distribution(monkeypatch):
    import importlib.metadata

    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)
    assert not available()


def test_package_import_has_no_engine_side_effect():
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import agent.sandbox,sys; assert 'pydantic_monty' not in sys.modules",
        ],
        check=False,
    )
    assert result.returncode == 0
