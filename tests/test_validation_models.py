from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agent.validation.catalog import load_catalog, select_suite
from agent.validation.models import Bounds, LifecycleEvent, ValidationRun


def test_catalog_and_selection():
    catalog = load_catalog()
    assert [len(s.scenarios) for s in catalog.suites] == [9, 2, 2]
    suite, selected = select_suite(catalog, "offline-security", None, "offline", False)
    assert len(selected) == 9 and len(suite.revision) == 64
    for names, mode in [
        (["missing"], "offline"),
        (["policy-denial"] * 2, "offline"),
        (None, "live"),
    ]:
        with pytest.raises(ValueError):
            select_suite(catalog, "offline-security", names, mode, False)
    for names, interactive in [
        (None, True),
        (["phone-approved", "phone-denied"], True),
        (["phone-approved"], False),
    ]:
        with pytest.raises(ValueError):
            select_suite(catalog, "live-phone", names, "live", interactive)


@pytest.mark.parametrize(
    "data",
    [
        {"scenario_timeout": 181},
        {"suite_timeout": 1801},
        {"cleanup_timeout": 31},
        {"cleanup_timeout": 0},
        {"schema_version": 2},
        {"extra": "canary"},
    ],
)
def test_strict_bounds(data):
    with pytest.raises(ValidationError):
        Bounds(**data)


def event(**updates):
    return LifecycleEvent(
        request_id=uuid4(),
        run_id=uuid4(),
        agent_ref=uuid4(),
        workload_ref=uuid4(),
        phase="run",
        detail="started",
        **updates,
    )


@pytest.mark.parametrize(
    "data",
    [
        {"reason": "secret"},
        {"trace_id": "a"},
        {"span_id": "Z" * 16},
        {"native_id": "secret"},
        {"duration": -1},
        {"created_at": datetime.now()},
        {"created_at": datetime.now(timezone(timedelta(hours=1)))},
    ],
)
def test_public_events_reject_unsafe_metadata(data):
    with pytest.raises(ValidationError):
        event(**data)


def test_ids_are_distinct_and_nullable_lineage():
    e = event(trace_id="a" * 32, span_id="b" * 16)
    assert e.parent_run_id is None and e.created_at.tzinfo == UTC
    run = ValidationRun(
        suite="offline-security",
        suite_revision="a" * 64,
        configuration_fingerprint="b" * 64,
        selected=("delegated-read",),
        mode="offline",
    )
    assert run.validation_id not in {e.run_id, e.request_id, e.event_id}
    assert run.completed_at is None
