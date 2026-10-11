"""Bounded controlled activity before enrollment, with no synthetic discovery claims.

A prepared case is only a correlation target. Valid actor credentials, exact authorized
registry absence and a distinct healthy read establish the attempted activity; the
separate collector must still observe and notify before enrollment can be reviewed.
"""

from .bootstrap import acquire, details_for
from .config import binding_digest
from .models import require
from .permissions import read


async def observe(
    store,
    candidate,
    binding,
    *,
    registry,
    oauth,
    verifier,
    healthy_oauth,
    healthy_verifier,
    healthy_binding,
    audience,
    http,
    check,
):
    """Capture absence then one dedicated KV read and its independent healthy control.

    Returns private digest-only facts. A denial is attributable only while metadata
    remains exact and the healthy actor can read the very same harmless resource.
    """
    require(
        candidate.state in {"prepared", "observed"} and candidate.binding == binding,
        "configuration_changed",
    )
    require(healthy_binding.actor_subject != binding.actor_subject, "bootstrap_mismatch")
    check()
    metadata = await registry.metadata(binding)
    check()
    absence = await registry.absence(binding)
    check()
    details = details_for(binding.paths["preregistration"])
    control = await acquire(
        store, candidate, healthy_binding, healthy_oauth, healthy_verifier, audience, details, check
    )
    token = await acquire(store, candidate, binding, oauth, verifier, audience, details, check)
    check()
    healthy = await read(http, binding, "preregistration", control)
    check()
    decision = await read(http, binding, "preregistration", token)
    check()
    current = await registry.metadata(binding)
    check()
    attributed = decision["status"] == 403 and healthy["status"] == 200 and current == metadata
    return {
        "status": decision["status"],
        "control_status": healthy["status"],
        "absence": absence["digest"],
        "digest": binding_digest([metadata, absence, healthy, decision]),
        "healthy": healthy["status"] == 200,
        "attributed": attributed,
        "outcome": "pass" if attributed else "inconclusive",
    }
