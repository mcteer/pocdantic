"""Recovery contracts reject coercion, authority payloads, and invalid projections."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agent.recovery.models import Attempt, Journal, OperationalView, Receipt


def attempt(**changes):
    """Construct the minimum unresolved synthetic acquisition record."""
    return Attempt(
        **(
            {
                "incident_id": uuid4(),
                "operation_id": uuid4(),
                "environment_digest": "a" * 64,
                "credential_path": "database/creds/read",
            }
            | changes
        )
    )


@pytest.mark.parametrize("value", [True, "1", 2, 1.0])
def test_strict_version(value):
    with pytest.raises(ValidationError):
        attempt(schema_version=value)


@pytest.mark.parametrize(
    "changes",
    [
        {"revision": True},
        {"revision": 0},
        {"environment_digest": "A" * 64},
        {"created_at": datetime.now()},
        {"created_at": datetime.fromisoformat("2026-01-01T00:00:00+01:00")},
        {"credential_path": "database/creds/../read"},
        {"lease_handle": "database/creds/other/x"},
        {"state": "resolved"},
        {"resolution": "revoked"},
        {"token": "private"},
    ],
)
def test_invalid_attempt(changes):
    with pytest.raises(ValidationError):
        attempt(**changes)


def test_private_repr_and_public_projection():
    item = attempt(lease_handle="database/creds/read/private", state="unresolved")
    assert "database/creds/read/private" not in repr(item)
    view = item.summary().model_dump_json()
    assert "database/" not in view and "environment_digest" not in view
    assert str(item.incident_id) in view


def test_resolution_requires_bound_receipt():
    item = attempt(lease_handle="database/creds/read/native")
    receipt = Receipt(
        outcome="revoked",
        incident_id=item.incident_id,
        operation_id=item.operation_id,
        environment_digest=item.environment_digest,
        incident_revision=1,
    )
    resolved = item.model_copy(
        update={"state": "resolved", "resolution": "revoked", "receipt": receipt}
    )
    assert Attempt.model_validate(resolved.model_dump()).resolution == "revoked"
    with pytest.raises(ValidationError):
        Attempt.model_validate(resolved.model_dump() | {"resolution": "not_issued"})


def test_journal_limits_and_unique_attempts():
    item = attempt()
    with pytest.raises(ValidationError):
        Journal(installation_id=uuid4(), environment_digest="a" * 64, attempts=(item, item))
    with pytest.raises(ValidationError):
        Journal(
            installation_id=uuid4(),
            environment_digest="a" * 64,
            attempts=tuple(attempt() for _ in range(101)),
        )


def test_closed_operational_mapping_and_counts():
    assert OperationalView(authentication=False).checked_at is None
    for changes in [
        {"recovery": "yes"},
        {"blocked_count": -1},
        {"active_work": 1},
        {"reason_code": "PRIVATE"},
        {"next_action": "clear"},
        {"checked_at": datetime.now()},
    ]:
        with pytest.raises(ValidationError):
            OperationalView(authentication=False, **changes)
    assert OperationalView(authentication=False, checked_at=datetime.now(UTC)).checked_at
