# Validation quickstart

uv sync --locked --extra google --extra logfire --extra server --extra postgres --group dev
uv run agent demo
uv run pytest
uv run ruff check .
uv run python scripts/check_gates.py --all-features
uv run agent probe

Demo uses synthetic identity/tools and no external calls. Probe uses local credentials, emits only
status/capability metadata and does not provision resources. See README for live configuration.
Live phase acceptance requires independently reviewed source-system evidence.
