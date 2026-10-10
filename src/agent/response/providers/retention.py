"""Compute conservative retention closure without deleting unresolved private authority.

Age applies only after effects and their independent observations settle. Linked retries,
shared actions, trusted acquisition roots and observation correlations form one closure;
pruning any member alone could erase the evidence needed to recover another member.
"""

from .proof import complete


def acquisition_roots(state):
    """Pin unknown issuance and bound native tokens until exact independent revocation proof."""
    if state.schema_version != 2:
        return set()
    roots = set()
    for acquisition in state.native_acquisitions:
        resolved = acquisition.state == "denied" or (
            acquisition.state == "bound"
            and any(
                a.kind == "revoke_native_token"
                and acquisition.binding is not None
                and a.binding.key() == acquisition.binding.key()
                and a.binding.generation == acquisition.binding.generation
                and complete(a)
                for a in state.provider_actions
            )
        )
        if not resolved:
            roots.add(acquisition.ownership.root_run_id)
    roots.update(
        a.ownership.root_run_id
        for a in state.probe_acquisitions
        if a.state not in {"denied_no_issuance", "cleaned"}
    )
    return roots


def incident_pins(state):
    """Return provider incidents whose effects or referenced evidence remain unresolved."""
    if state.schema_version != 2:
        return set()
    pinned = set()
    current = {ref for p in state.provider_plans for ref in p.action_ids}
    for action in state.provider_actions:
        if action.state in {"planned", "submitted", "uncertain"} or (
            action.action_id in current and action.required and not complete(action)
        ):
            pinned.update(action.incidents)
    for plan in state.provider_plans:
        if plan.missing_controls:
            pinned.add(plan.incident_id)
    roots = acquisition_roots(state)
    for incident in state.incidents:
        if any(incident.matches(run) and run.root_run_id in roots for run in state.runs):
            pinned.add(incident.incident_id)
    return pinned


def closure(state, incident_ids):
    """Extend incident retention through shared effects, dependencies and evidence IDs."""
    if state.schema_version != 2:
        return set(incident_ids), set()
    incidents, actions = set(incident_ids), set()
    by_id = {a.action_id: a for a in state.provider_actions}
    changed = True
    while changed:
        before = (len(incidents), len(actions))
        for plan in state.provider_plans:
            if plan.incident_id in incidents:
                actions.update(plan.action_ids)
        for action in state.provider_actions:
            if set(action.incidents) & incidents:
                actions.add(action.action_id)
        for aid in tuple(actions):
            action = by_id[aid]
            actions.update(action.dependencies)
            if action.predecessor:
                actions.add(action.predecessor)
            incidents.update(action.incidents)
            incidents.update(o.incident_id for o in action.observations)
        changed = before != (len(incidents), len(actions))
    return incidents, actions


def prune_fields(state, incident_ids, root_ids, cutoff):
    """Remove only settled provider records whose entire reference closure aged out."""
    if state.schema_version != 2:
        return {}
    _, actions = closure(state, incident_ids)
    return {
        "provider_plans": tuple(p for p in state.provider_plans if p.incident_id in incident_ids),
        "provider_actions": tuple(a for a in state.provider_actions if a.action_id in actions),
        "provider_decisions": tuple(
            d
            for d in state.provider_decisions
            if d.predecessor in actions or d.successor in actions
        ),
        "subject_holds": tuple(h for h in state.subject_holds if h.incident_id in incident_ids),
        "native_acquisitions": tuple(
            a
            for a in state.native_acquisitions
            if a.ownership.root_run_id in root_ids
            or a.created_at >= cutoff
            or a.state in {"intent", "submitted", "uncertain"}
        ),
        "probe_acquisitions": tuple(
            a
            for a in state.probe_acquisitions
            if a.ownership.root_run_id in root_ids
            or a.created_at >= cutoff
            or a.state not in {"denied_no_issuance", "cleaned"}
        ),
    }


def recent_incidents(state, cutoff):
    """Retain thirty days after the latest effect/proof, rather than only after intake."""
    if state.schema_version != 2:
        return set()
    result = set()
    for action in state.provider_actions:
        times = [
            action.created_at,
            *(o.observed_at for o in action.observations),
            *(o.reviewed_at for o in action.observations if o.reviewed_at),
        ]
        if action.completed_at:
            times.append(action.completed_at)
        if max(times) >= cutoff:
            result.update(action.incidents)
    active = {r.root_run_id for r in state.runs if r.state == "active"}
    for probe in state.probe_acquisitions:
        if (
            probe.ownership.root_run_id in active
            or probe.created_at >= cutoff
            or any(
                o.observed_at >= cutoff or o.reviewed_at and o.reviewed_at >= cutoff
                for o in probe.observations
            )
        ):
            result.update(o.incident_id for o in probe.observations)
    return result
