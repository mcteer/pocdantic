"""Optional sandbox integration; importing this package never starts a worker."""

import importlib.metadata
import importlib.util

INSTALL = (
    "uv sync --locked --extra sandbox --extra server --extra postgres --extra google --group dev"
)


def available():
    """Report matching optional packages without importing or executing the engine."""
    try:
        return (
            all(
                importlib.metadata.version(name) == version
                for name, version in (
                    ("pydantic-monty", "1.1.0"),
                    ("pydantic-monty-client", "1.1.0"),
                    ("pydantic-monty-runtime", "1.1.0"),
                    ("sqlglot", "30.22.0"),
                )
            )
            and importlib.util.find_spec("pydantic_monty") is not None
        )
    except (ImportError, importlib.metadata.PackageNotFoundError):
        return False
