"""Optional dependency detection must not disturb unrelated profiles."""

from agent.sandbox import available


def test_reviewed_versions_match_declared_pins(monkeypatch):
    """Dependency updates must keep the fail-closed runtime check aligned with pins."""
    import tomllib
    from pathlib import Path

    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    pins = dict(item.split("==") for item in project["project"]["optional-dependencies"]["sandbox"])
    pins["pydantic-monty-client"] = pins["pydantic-monty"]
    pins["pydantic-monty-runtime"] = pins["pydantic-monty"]
    monkeypatch.setattr("importlib.metadata.version", pins.__getitem__)
    monkeypatch.setattr("importlib.util.find_spec", lambda _: object())
    assert available()
    pins["sqlglot"] = "0.0.0"
    assert not available()


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
