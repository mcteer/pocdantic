"""Deterministic exact response plans, built in the same transaction as the hold.

Canonical native resource fences join overlapping security actions. Notifications
instead belong to one incident/revision so a shared workflow cannot suppress alerts.
"""

from .enrollment import digest
from .models import IncidentPlan, ProviderAction, SubjectHold, require

COMPATIBLE = {
    "block_registration": "registration",
    "revoke_native_token": "native_token",
    "suspend_user": "user",
    "revoke_user_sessions": "user",
    "rotate_static": "static_role",
    "terminate_static_sessions": "static_role",
    "notify_teams": "teams",
}
ORDER = {
    k: i
    for i, k in enumerate(
        (
            "block_registration",
            "suspend_user",
            "revoke_native_token",
            "revoke_user_sessions",
            "rotate_static",
            "terminate_static_sessions",
            "notify_teams",
        )
    )
}


def build(
    state,
    incident,
    *,
    rule_alias=None,
    mode="local_only",
    reason="suspected_compromise",
    source_clock_bound_seconds=None,
):
    """Return complete ledger changes; caller must persist them atomically with containment."""
    policy = state.enrollment
    if policy is None:
        return {}
    fingerprint = digest(policy)
    rules = [
        r
        for r in policy.rules
        if r.source == incident.source
        and r.scope == incident.target.kind
        and r.reason == reason
        and (rule_alias is None or r.alias == rule_alias)
    ]
    # Incident.reason_code is a lifecycle code; native/local selection passes the fixed
    # source reason explicitly via the caller's selected rule alias.
    if rule_alias is not None:
        rules = [
            r
            for r in policy.rules
            if r.alias == rule_alias
            and r.source == incident.source
            and r.scope == incident.target.kind
        ]
    actions = list(state.provider_actions)
    refs, subjects = [], list(state.subject_holds)
    missing = set()
    for rule in rules:
        bindings = [b for b in policy.bindings if b.binding_id in rule.bindings]
        bindings += [
            a.binding
            for a in state.native_acquisitions
            if a.state == "bound"
            and a.binding
            and "revoke_native_token" in rule.actions
            and (
                incident.target.kind == "definition"
                or a.ownership.root_run_id == incident.target.root_run_id
            )
        ]
        for kind in sorted(rule.actions, key=ORDER.get):
            if (
                kind in rule.required
                and kind != "revoke_native_token"
                and not any(b.kind == COMPATIBLE[kind] for b in bindings)
            ):
                missing.add(kind)
            for binding in bindings:
                if binding.kind != COMPATIBLE[kind]:
                    continue
                if incident.target.kind == "root_run" and kind != "notify_teams":
                    require(
                        kind == "revoke_native_token"
                        and binding.root_run_id == incident.target.root_run_id
                        and binding.exclusive_tree
                        and binding.ownership,
                        "mapping_missing",
                    )
                key = (binding.key(), binding.generation, kind)
                prior = next(
                    (
                        a
                        for a in reversed(actions)
                        if (kind != "notify_teams" or incident.incident_id in a.incidents)
                        and (a.binding.key(), a.binding.generation, a.kind) == key
                    ),
                    None,
                )
                if prior:
                    require(prior.enrollment_digest == fingerprint, "provider_policy_changed")
                    changed = type(prior).model_validate(
                        prior.model_dump()
                        | {
                            "required": prior.required or kind in rule.required,
                            "incidents": tuple(
                                dict.fromkeys((*prior.incidents, incident.incident_id))
                            ),
                        }
                    )
                    actions = [changed if a.action_id == prior.action_id else a for a in actions]
                    refs.append(prior.action_id)
                else:
                    dependencies = tuple(
                        a.action_id
                        for a in actions
                        if incident.incident_id in a.incidents
                        and (
                            a.kind in {"block_registration", "suspend_user"}
                            or kind == "terminate_static_sessions"
                            and a.kind == "rotate_static"
                            and a.binding.key() == binding.key()
                        )
                        and kind not in {"block_registration", "suspend_user", "notify_teams"}
                    )
                    action = ProviderAction(
                        kind=kind,
                        scope=rule.scope,
                        binding=binding,
                        enrollment_digest=fingerprint,
                        required=kind in rule.required,
                        incidents=(incident.incident_id,),
                        dependencies=dependencies,
                        notice_id=incident.incident_id if kind == "notify_teams" else None,
                    )
                    actions.append(action)
                    refs.append(action.action_id)
                if kind in {"suspend_user", "revoke_user_sessions"}:
                    hold = SubjectHold(
                        issuer=binding.user_issuer,
                        subject=binding.user_subject,
                        workload_definition=binding.workload_definition,
                        incident_id=incident.incident_id,
                        generation=incident.generation,
                    )
                    if hold not in subjects:
                        subjects.append(hold)
    require(len(set(refs)) <= 16, "provider_capacity")
    plan = IncidentPlan(
        incident_id=incident.incident_id,
        mode=mode,
        enrollment_digest=fingerprint,
        source_clock_bound_seconds=source_clock_bound_seconds,
        action_ids=tuple(dict.fromkeys(refs)),
        native_token_authorized=any("revoke_native_token" in r.actions for r in rules),
        native_token_required=any("revoke_native_token" in r.required for r in rules),
        missing_controls=tuple(sorted(missing)),
    )
    return dict(
        provider_actions=tuple(actions),
        provider_plans=(*state.provider_plans, plan),
        subject_holds=tuple(subjects),
    )


def bind_pending_native(state, acquisition):
    """Extend only preauthorized plans when an in-flight native issuance finishes late.

    The exact accessor becomes known after containment but before normal owner drain.
    This trusted ownership join preserves the original policy choice and never creates
    broad authority from token response fields or retrospective legacy inference.
    """
    if acquisition.binding is None:
        return {}
    actions, plans = list(state.provider_actions), []
    for plan in state.provider_plans:
        incident = next(i for i in state.incidents if i.incident_id == plan.incident_id)
        if not plan.native_token_authorized or not incident.matches(acquisition.ownership):
            plans.append(plan)
            continue
        require(plan.enrollment_digest == acquisition.enrollment_digest, "provider_policy_changed")
        prior = next(
            (
                a
                for a in actions
                if a.kind == "revoke_native_token"
                and a.binding.key() == acquisition.binding.key()
                and a.binding.generation == acquisition.binding.generation
            ),
            None,
        )
        if prior is None:
            dependencies = tuple(
                a.action_id
                for a in actions
                if incident.incident_id in a.incidents
                and a.kind in {"block_registration", "suspend_user"}
            )
            prior = ProviderAction(
                kind="revoke_native_token",
                scope=incident.target.kind,
                binding=acquisition.binding,
                enrollment_digest=plan.enrollment_digest,
                required=plan.native_token_required,
                incidents=(incident.incident_id,),
                dependencies=dependencies,
            )
            actions.append(prior)
        elif incident.incident_id not in prior.incidents:
            updated = ProviderAction.model_validate(
                prior.model_dump()
                | {
                    "incidents": (*prior.incidents, incident.incident_id),
                    "required": prior.required or plan.native_token_required,
                }
            )
            actions = [updated if a.action_id == prior.action_id else a for a in actions]
        plans.append(
            type(plan).model_validate(
                plan.model_dump()
                | {"action_ids": tuple(dict.fromkeys((*plan.action_ids, prior.action_id)))}
            )
        )
    return {"provider_actions": tuple(actions), "provider_plans": tuple(plans)}
