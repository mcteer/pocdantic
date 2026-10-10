"""Credential-free per-control projections and concrete operator recovery guidance.

Reports are disk-only. They preserve independent paths and provenance; neither HTTP
acceptance nor local cancellation fills a missing native outcome or timing interval.
"""

from .proof import PATHS, READBACKS


def controls(state, incident_id):
    """Project only opaque action IDs and closed kind/state/proof codes for an owned incident."""
    if state.schema_version != 2:
        return ()
    plan = next((p for p in state.provider_plans if p.incident_id == incident_id), None)
    if plan is None:
        return ()
    result = []
    for action in state.provider_actions:
        if action.action_id not in plan.action_ids:
            continue
        paths = {}
        for path in sorted(PATHS[action.kind] | READBACKS.get(action.kind, set())):
            matches = [o for o in action.observations if o.path == path]
            latest = max(matches, key=lambda o: o.observed_at) if matches else None
            paths[path] = latest.result if latest else "not_run"
        result.append(
            {
                "action_id": action.action_id,
                "attempt_ms": action.attempt_ms,
                "source_to_loss": loss_interval(state, plan, action),
                "kind": action.kind,
                "state": action.state,
                "required": action.required,
                "reason_code": action.reason,
                "paths": paths,
                "provenance": plan.mode,
            }
        )
    return tuple(result)


REPAIR = {
    "block_registration": "Vault operator: check the draft's registration ID and actor entity; "
    "grant read/delete for that ID and verify the enrolled OAuth profile and issuer alias.",
    "revoke_native_token": "Vault operator: grant lookup-accessor/revoke-accessor to the control "
    "identity; retain the exact service accessor and exclusive root ownership record.",
    "suspend_user": "Verify administrator: verify the tenant user ID/issuer/subject; grant "
    "the configured API client user-update authority. Upstream IBMid is outside this control.",
    "revoke_user_sessions": "Verify administrator: grant session-list/revoke authority for the "
    "mapped test user; review current sessions before retry, which can affect newer logins.",
    "rotate_static": "Vault/database operator: check the isolated role and rotation schedule; "
    "grant metadata-read/rotate-role. An uncertain rotation cannot be retried from metadata.",
    "terminate_static_sessions": "Database operator: check the isolated role, direct control DSN, "
    "activity visibility and signal/execute grants. Supply a distinct healthy proof role.",
    "notify_teams": "Workflow owner: check the URL-only trigger and posting connection in the "
    "test channel; import the correlated message receipt. Explicit resend uses a new notice.",
}


def instructions(state, incident_id):
    """Explain exact actor roles and bounded rerun commands without native target values."""
    output = []
    for action in state.provider_actions:
        if incident_id not in action.incidents:
            continue
        owner = (
            "Verify administrator"
            if action.kind in {"suspend_user", "revoke_user_sessions"}
            else (
                "Teams workflow owner"
                if action.kind == "notify_teams"
                else "Vault/database operator"
            )
        )
        output.append(
            {
                "action_id": str(action.action_id),
                "reason_code": action.reason,
                "owner_role": owner,
                "next_action": (
                    REPAIR[action.kind]
                    + " Import reviewed independent proof; preserve local state."
                ),
                "rerun_command": (
                    f"agent respond providers reconcile --incident {incident_id} "
                    f"--revision {state.revision}"
                ),
            }
        )
    return output


def interval(start, end, start_bound, end_bound):
    """Return an uncertainty interval only for valid bounded UTC clocks and positive ordering."""
    if (
        start_bound is None
        or end_bound is None
        or not (0 <= start_bound <= 5 and 0 <= end_bound <= 5)
    ):
        return None
    seconds = (end - start).total_seconds()
    if seconds < 0:
        return None
    uncertainty = start_bound + end_bound
    return {
        "lower_ms": max(0, int((seconds - uncertainty) * 1000)),
        "upper_ms": int((seconds + uncertainty) * 1000),
        "uncertainty_ms": uncertainty * 1000,
    }


def loss_interval(state, plan, action):
    """Publish no source-to-loss number unless every independent path has bounded fresh proof."""
    from agent.recovery.models import now

    from .proof import complete

    if not complete(action, live=True, fresh=True):
        return None
    observations = []
    for path in PATHS[action.kind]:
        values = [o for o in action.observations if o.path == path and o.source != "synthetic"]
        if not values:
            return None
        latest = max(values, key=lambda o: o.observed_at)
        if latest.clock_bound_seconds is None or (
            latest.credential_expires_at is not None and latest.credential_expires_at <= now()
        ):
            return None
        observations.append(latest)
    incident = next(i for i in state.incidents if i.incident_id == plan.incident_id)
    latest = max(observations, key=lambda o: o.observed_at)
    return interval(
        incident.source_at,
        latest.observed_at,
        plan.source_clock_bound_seconds,
        max(o.clock_bound_seconds for o in observations),
    )


def database_checks(state, incident_id):
    """Aggregate only prospective exact-cleanup observations; never infer legacy DB identity."""
    if state.schema_version != 2:
        return {}
    output = {}
    for path in ("dynamic_fresh", "dynamic_session"):
        observations = [
            o
            for p in state.probe_acquisitions
            for o in p.observations
            if o.incident_id == incident_id and o.path == path
        ]
        if observations:
            output[path] = max(observations, key=lambda o: o.observed_at).result
    return output
