"""The analysis role cannot acquire remote-command or infrastructure authority."""

import pytest

from agent.schemas import Action, Principal
from agent.security import Policy, SecurityError


def test_explicit_analysis_role():
    principal = Principal(
        issuer="https://identity.example", subject="fixture", scopes=frozenset({"database:read"})
    )
    policy = Policy()
    policy.authorize(
        principal,
        "database-analyst",
        Action(operation="sandbox.execute", resource="database-analysis"),
    )
    policy.authorize(
        principal, "database-analyst", Action(operation="database.read", resource="poc-records")
    )
    for role, action in [
        ("parent", Action(operation="sandbox.execute", resource="database-analysis")),
        ("database-analyst", Action(operation="remote.execute", resource="linux")),
        ("database-analyst", Action(operation="infra.write", resource="sandbox/demo")),
        ("database-analyst", Action(operation="database.read", resource="other")),
    ]:
        with pytest.raises(SecurityError):
            policy.authorize(principal, role, action)
