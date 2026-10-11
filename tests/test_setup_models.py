"""Deployment configuration rejects ambiguous targets and expands only explicit trust."""

import pytest
from pydantic import ValidationError

from agent.settings import Settings


def test_custom_target_resolves_without_legacy_conflict():
    """A custom mount needs no source or legacy-path edit."""
    s = Settings(_env_file=None, vault_database_mount="team/postgres", vault_database_role="reader")
    assert s.vault_read_path == "team/postgres/creds/reader"


def test_explicit_conflicting_targets_fail():
    """Contradictory inputs cannot select a different credential role accidentally."""
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            vault_database_mount="team",
            vault_database_role="reader",
            vault_read_path="database/creds/old",
        )


@pytest.mark.parametrize(
    "hosts", [["*.example.com"], ["https://id.example"], ["id.example/path"], ["id.example"] * 17]
)
def test_host_trust_is_bounded_and_explicit(hosts):
    """Host wildcards, URLs, paths and oversized lists never broaden token destinations."""
    with pytest.raises(ValidationError):
        Settings(_env_file=None, oauth_trusted_hosts=hosts)
