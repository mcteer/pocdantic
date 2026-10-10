"""Synthetic recovery settings and explicit subprocess crash checkpoints."""

import os
from pathlib import Path

from agent.settings import Settings


def settings(project: Path):
    """Build an isolated target without environment or customer credentials."""
    profiles = project / "profiles.json"
    profiles.write_bytes(Path("config/agents.json").read_bytes())
    return Settings.model_construct(
        profiles_file=str(profiles),
        vault_addr="https://vault.example",
        vault_namespace="fixture",
        vault_read_path="database/creds/read",
        vault_audience="vault",
        oauth_audience="resource",
        oauth_client_id="actor",
        oauth_issuer="https://id.example",
        oauth_discovery_url="https://id.example/discovery",
        database_host="database.example",
        database_name="fixture",
    )


def crash_checkpoint(name, destination):
    """Signal a controlled boundary, then await an external process termination."""
    Path(destination).write_text(name)
    os.kill(os.getpid(), __import__("signal").SIGSTOP)
