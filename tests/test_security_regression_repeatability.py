"""Both actual policies produce the intended permission delta and unchanged control."""

import pytest
from security_regression_support import PROFILES, selected_policy

from agent.schemas import Action, Principal
from agent.security import SecurityError


def test_policy_change_is_observed():
    """ALT changes authorization; POC stays permitted under both actual fixed Policy objects."""
    user = Principal(issuer="fixture", subject="verified", scopes=frozenset({"tickets:read"}))
    for name, policy in PROFILES.items():
        policy.authorize(user, "ticket-reader", Action(operation="ticket.read", resource="POC-1"))
        if name == "baseline":
            policy.authorize(
                user, "ticket-reader", Action(operation="ticket.read", resource="ALT-1")
            )
        else:
            with pytest.raises(SecurityError):
                policy.authorize(
                    user, "ticket-reader", Action(operation="ticket.read", resource="ALT-1")
                )
    selected_policy().authorize(
        user, "ticket-reader", Action(operation="ticket.read", resource="POC-1")
    )


def test_authority_set_serialization_is_stable():
    """Unordered required-control sets cannot change an enrollment digest on JSON roundtrip."""
    import itertools

    from agent.response.providers.enrollment import digest
    from agent.response.providers.models import Rule

    kinds = ("rotate_static", "terminate_static_sessions", "suspend_user", "block_registration")
    for pair in itertools.combinations(kinds, 2):
        rule = Rule(alias="fixture-rule", actions=pair, required=frozenset(pair))
        encoded = rule.model_dump(mode="json")
        assert encoded["required"] == sorted(pair)
        assert digest(rule) == digest(Rule.model_validate_json(rule.model_dump_json()))
