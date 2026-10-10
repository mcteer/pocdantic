"""Plans deduplicate security controls while retaining incident-specific notices."""

from provider_support import activate, enrollment, provider_store, resource
from response_support import signal

from agent.response.coordinator import Coordinator
from agent.response.providers.models import Rule


def test_security_join_preserves_distinct_notices(tmp_path, workspace_settings):
    """One canonical deletion and two notices serve two held incident generations."""
    store = provider_store(workspace_settings, tmp_path)
    registration = resource(workspace_settings)
    teams = resource(workspace_settings, "teams", alias="teams-fixture")
    rule = Rule(
        alias="response-rule",
        actions=("block_registration", "notify_teams"),
        bindings=(registration.binding_id, teams.binding_id),
        required=frozenset({"block_registration"}),
    )
    activate(store, enrollment(store, bindings=(registration, teams), rules=(rule,)))
    coordinator = Coordinator(store)
    first, _ = coordinator.submit(signal(workspace_settings, event="one"))
    second, _ = coordinator.submit(signal(workspace_settings, event="two"))
    actions = store.read().provider_actions
    assert len(actions) == 3
    control = next(a for a in actions if a.kind == "block_registration")
    assert control.incidents == (first.incident_id, second.incident_id)
    assert len({a.notice_id for a in actions if a.kind == "notify_teams"}) == 2
    assert set(store.read().holds[0].incident_ids) == {first.incident_id, second.incident_id}


def test_late_native_join_preserves_definition_required_flag(tmp_path, workspace_settings):
    """A late accessor shared by advisory/root and required/definition plans stays required."""
    import os
    from uuid import uuid4

    from response_support import principal

    from agent.response.guard import RootGuard
    from agent.response.providers.enrollment import native_begin, native_update

    store = provider_store(workspace_settings, tmp_path)
    registration = resource(workspace_settings)
    root_rule = Rule(alias="root-advisory", scope="root_run", actions=("revoke_native_token",))
    definition_rule = Rule(
        alias="definition-required",
        actions=("revoke_native_token",),
        required=frozenset({"revoke_native_token"}),
    )
    activate(
        store,
        enrollment(
            store,
            bindings=(registration,),
            rules=(root_rule, definition_rule),
            native_login_mount="jwt",
            native_login_role="exclusive",
            native_exclusive_tree=True,
        ),
    )
    run, owner = store.register(uuid4(), uuid4(), principal(workspace_settings))
    store.bind_actor(run, registration.actor_issuer, registration.actor_subject)
    try:
        item = native_begin(
            store, RootGuard(store, run, owner), "jwt", "exclusive", registration.origin, ""
        )
        item = native_update(store, item, "submitted")
        Coordinator(store).submit(
            signal(workspace_settings, root=run.root_run_id, event="root-hold")
        )
        Coordinator(store).submit(signal(workspace_settings, event="definition-hold"))
        native_update(
            store,
            item,
            "bound",
            origin=registration.origin,
            auth={"token_type": "service", "accessor": "late-accessor", "client_token": "fixture"},
        )
        state = store.read()
        assert len(state.provider_actions) == 1 and state.provider_actions[0].required
        assert len(state.provider_actions[0].incidents) == 2
        from agent.response.providers.proof import release_safe

        assert not release_safe(state, {p.incident_id for p in state.provider_plans})
    finally:
        store.finish(run)
        os.close(owner)
