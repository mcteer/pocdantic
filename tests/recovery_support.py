"""Synthetic recovery settings and explicit subprocess crash checkpoints."""

import os
from pathlib import Path

from agent.recovery.store import RecoveryStore as DurableRecoveryStore
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


class SyntheticRecoveryStore(DurableRecoveryStore):
    """Add explicit synthetic attribution only to legacy recovery unit fixtures."""

    def begin(self, owner, binding=None):
        from uuid import uuid4

        from agent.recovery.models import BoundOwnership

        return super().begin(
            owner,
            binding
            or owner.binding
            or BoundOwnership(
                root_run_id=uuid4(),
                request_id=uuid4(),
                generation=1,
                workload_definition=self.settings.workload_definition,
                issuer=self.settings.oauth_issuer or "offline",
                subject="fixture-user",
            ),
        )
