"""Synthetic incident fixtures; no provider resources or customer configuration."""

from uuid import uuid4

from agent.response.models import RiskSignal, RunBinding
from agent.response.store import ResponseStore
from agent.schemas import Principal


def enrolled(settings, project, *, recovery=None):
    """Enroll a temporary local-only control store using trusted synthetic settings."""
    store = ResponseStore(settings, project=project, recovery=recovery)
    store.prepare()
    store.initialize()
    return store


def binding(settings, **changes):
    """Build a synthetic verified root binding for strict boundary tests."""
    return RunBinding(
        root_run_id=uuid4(),
        request_id=uuid4(),
        workload_definition=settings.workload_definition,
        generation=1,
        issuer=settings.oauth_issuer or "offline",
        subject="fixture-user",
        **changes,
    )


def signal(settings, *, root=None, event="event-001"):
    """Create a fresh signal for an exact root or configured definition."""
    from agent.recovery.models import now

    return RiskSignal(
        event_id=event,
        occurred_at=now(),
        reason="suspected_compromise",
        target={"kind": "root_run", "root_run_id": root}
        if root
        else {"kind": "definition", "workload_definition": settings.workload_definition},
    )


def principal(settings):
    """Return a nonsecret synthetic principal for host-derived ownership tests."""
    return Principal(issuer=settings.oauth_issuer or "offline", subject="fixture-user")
