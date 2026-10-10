"""Native intake accepts only enrolled scalar projection and exact host correlation."""

import json

import pytest
from provider_support import activate, enrollment, provider_store

from agent.recovery.models import now
from agent.response.coordinator import Coordinator
from agent.response.models import ResponseError
from agent.response.providers.models import Rule, SourceProfile


def fixture(store):
    """Enroll a synthetic relay whose event body cannot select arbitrary actions."""
    profile = SourceProfile(
        alias="native-fixture",
        issuer=store.settings.oauth_issuer or "offline",
        subject="collector",
        audience="native-events",
        schema_ref="fixture-v1",
        fixture_digest="1" * 64,
        pointers={"event_id": "/id", "occurred_at": "/time", "rule": "/rule", "object": "/object"},
        objects={"known": store.settings.workload_definition},
    )
    rule = Rule(alias="native-rule", source=profile.alias, native_rule="compromise")
    activate(store, enrollment(store, sources=(profile,), rules=(rule,)))
    return profile


def payload(**changes):
    """Return a bounded event containing an irrelevant vendor display field."""
    return json.dumps(
        dict(
            id="event-one",
            time=now().isoformat(),
            rule="compromise",
            object="known",
            display="ignored",
        )
        | changes
    ).encode()


def test_projection_replay_and_changed_security_conflict(tmp_path, workspace_settings):
    """Ignored display changes deduplicate; selected security changes conflict."""
    from agent.response.native import project

    store = provider_store(workspace_settings, tmp_path)
    profile = fixture(store)
    raw = payload()
    signal, rule = project(raw, profile, store.read())
    coordinator = Coordinator(store)
    incident, new = coordinator.submit(signal, native=profile, rule_alias=rule.alias)
    assert new and store.read().holds
    body = json.loads(raw)
    body["display"] = "different ignored display"
    duplicate, rule = project(json.dumps(body).encode(), profile, store.read())
    assert coordinator.submit(duplicate, native=profile, rule_alias=rule.alias)[1] is False
    body["time"] = now().isoformat()
    changed, rule = project(json.dumps(body).encode(), profile, store.read())
    with pytest.raises(ResponseError, match="event_conflict"):
        coordinator.submit(changed, native=profile, rule_alias=rule.alias)
    assert store.read().provider_plans[0].incident_id == incident.incident_id


@pytest.mark.parametrize(
    "raw",
    [b'{"id":1,"id":2}', b"[]", b'{"deep":' + b"[" * 9 + b"0" + b"]" * 9 + b"}", b" " * 65537],
)
def test_invalid_bounded_input_has_no_effect(tmp_path, workspace_settings, raw):
    """Malformed, duplicated or excessive input cannot create a hold or plan."""
    from agent.response.native import project

    store = provider_store(workspace_settings, tmp_path)
    profile = fixture(store)
    with pytest.raises(ResponseError):
        project(raw, profile, store.read())
    assert not store.read().incidents


async def test_native_route_auth_and_two_second_intake(
    tmp_path, workspace_settings, identity_provider
):
    """Native JWTs require their own audience/subject and commit the hold before reply."""
    import time

    import httpx

    from agent.response.api import create_response_app

    store = provider_store(workspace_settings, tmp_path)
    profile = fixture(store)
    app = create_response_app(
        workspace_settings, store=store, transport=httpx.MockTransport(identity_provider.handle)
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://local"
        ) as http:
            wrong = identity_provider.access(
                sub="collector", aud="resource", scope="response:submit", exp=int(time.time()) + 200
            )
            rejected = await http.post(
                "/response/native/native-fixture",
                content=payload(),
                headers={"Authorization": "Bearer " + wrong, "Content-Type": "application/json"},
            )
            assert rejected.status_code == 403 and not store.read().incidents
            token = identity_provider.access(
                sub="collector",
                aud=profile.audience,
                scope="response:submit",
                exp=int(time.time()) + 200,
            )
            for body, encoding, expected in (
                (b" " * 65537, "identity", 413),
                (payload(), "gzip", 400),
            ):
                rejected = await http.post(
                    "/response/native/native-fixture",
                    content=body,
                    headers={
                        "Authorization": "Bearer " + token,
                        "Content-Type": "application/json",
                        "Content-Encoding": encoding,
                    },
                )
                assert rejected.status_code == expected and not store.read().holds
            started = time.monotonic()
            accepted = await http.post(
                "/response/native/native-fixture",
                content=payload(),
                headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            )
            assert time.monotonic() - started < 2 and accepted.status_code == 202
            assert store.read().holds and store.read().provider_plans[0].mode == "synthetic"
            assert "known" not in accepted.text and "collector" not in accepted.text
            assert set(accepted.json()) == {"schema_version", "incident_id", "disposition"}


@pytest.mark.parametrize("field", ["access_token", "password", "client_secret", "Authorization"])
def test_native_secret_fields_rejected(tmp_path, workspace_settings, field):
    """Even an ignored raw credential field must not enter the trusted projection boundary."""
    from agent.response.native import project

    store = provider_store(workspace_settings, tmp_path)
    profile = fixture(store)
    with pytest.raises(ResponseError):
        project(payload(**{field: "synthetic-credential"}), profile, store.read())
    assert not store.read().holds


def test_root_correlation_rejects_different_verified_actor(tmp_path, workspace_settings):
    """A host request ID alone cannot map another actor's event onto a peer root."""
    import os
    from uuid import uuid4

    from provider_support import resource
    from response_support import principal

    from agent.response.native import project

    store = provider_store(workspace_settings, tmp_path)
    target = resource(workspace_settings)
    peer = resource(
        workspace_settings,
        alias="peer-registration",
        native_id="peer-native",
        actor_subject="peer-actor",
    )
    profile = SourceProfile(
        alias="root-relay",
        issuer=store.settings.oauth_issuer,
        subject="collector",
        audience="root-native",
        schema_ref="fixture-v1",
        fixture_digest="1" * 64,
        pointers={
            "event_id": "/id",
            "occurred_at": "/time",
            "rule": "/rule",
            "object": "/object",
            "request_id": "/request",
        },
        objects={"known": store.settings.workload_definition},
        object_bindings={"known": target.binding_id},
        allowed_scopes=frozenset({"root_run"}),
    )
    rule = Rule(
        alias="root-native", source=profile.alias, native_rule="compromise", scope="root_run"
    )
    activate(store, enrollment(store, bindings=(target, peer), sources=(profile,), rules=(rule,)))
    run, fd = store.register(uuid4(), uuid4(), principal(workspace_settings))
    try:
        store.bind_actor(run, store.settings.oauth_issuer, "peer-actor")
        with pytest.raises(ResponseError, match="mapping_missing"):
            project(payload(request=str(run.request_id)), profile, store.read())
        assert not store.read().holds and not store.read().root_holds
    finally:
        store.finish(run)
        os.close(fd)


def test_changed_native_object_same_definition_conflicts(tmp_path, workspace_settings):
    """Selected native object identity stays canonical even when aliases map to one workload."""
    from agent.response.native import project

    store = provider_store(workspace_settings, tmp_path)
    profile = SourceProfile(
        alias="native-fixture",
        issuer=store.settings.oauth_issuer,
        subject="collector",
        audience="native-events",
        schema_ref="fixture-v1",
        fixture_digest="1" * 64,
        pointers={"event_id": "/id", "occurred_at": "/time", "rule": "/rule", "object": "/object"},
        objects={
            "known": store.settings.workload_definition,
            "alias": store.settings.workload_definition,
        },
    )
    rule = Rule(alias="native-rule", source=profile.alias, native_rule="compromise")
    activate(store, enrollment(store, sources=(profile,), rules=(rule,)))
    body = json.loads(payload())
    first = project(json.dumps(body).encode(), profile, store.read())
    coordinator = Coordinator(store)
    coordinator.submit(
        first.signal, native=profile, rule_alias=rule.alias, native_digest=first.selected_digest
    )
    body["object"] = "alias"
    changed = project(json.dumps(body).encode(), profile, store.read())
    with pytest.raises(ResponseError, match="event_conflict"):
        coordinator.submit(
            changed.signal,
            native=profile,
            rule_alias=rule.alias,
            native_digest=changed.selected_digest,
        )


def test_enrollment_change_after_projection_rejects_intake(tmp_path, workspace_settings):
    """Projection cannot grant authority across an enrollment replacement race."""
    from agent.response.native import project

    store = provider_store(workspace_settings, tmp_path)
    profile = fixture(store)
    projected = project(payload(), profile, store.read())
    state = store.read()
    policy = type(state.enrollment).model_validate(
        state.enrollment.model_dump() | {"revision": state.enrollment.revision + 1}
    )
    with store.transaction() as (fd, state):
        store.commit(fd, state, enrollment=policy)
    with pytest.raises(ResponseError, match="provider_policy_changed"):
        Coordinator(store).submit(
            projected.signal,
            native=profile,
            rule_alias="native-rule",
            native_digest=projected.selected_digest,
            native_enrollment_digest=projected.enrollment_digest,
        )
    assert not store.read().holds
