"""Fixed proof workflows require actual pre-event state and exact authority."""

import pytest
from provider_support import activate, enrollment, provider_store, resource
from response_support import signal

from agent.response.coordinator import Coordinator
from agent.response.models import ResponseError
from agent.response.providers.models import ProofInput, Rule


def test_proof_input_rejects_scripts_and_destinations():
    """Private stdin carries credentials only; it cannot select URLs or executable code."""
    from pydantic import ValidationError

    for change in (
        {"url": "https://other.example"},
        {"sql": "SELECT anything"},
        {"delegated_token": "x" * 65537},
    ):
        with pytest.raises(ValidationError):
            ProofInput.model_validate(change)


async def test_post_event_proof_does_not_invent_baseline(tmp_path, workspace_settings):
    """Starting after containment records missing before-state without provider requests."""
    from agent.response.providers.workflow import run_probe

    store = provider_store(workspace_settings, tmp_path)
    binding = resource(workspace_settings)
    rule = Rule(
        alias="proof-rule",
        actions=("block_registration",),
        bindings=(binding.binding_id,),
        required=frozenset({"block_registration"}),
    )
    activate(store, enrollment(store, bindings=(binding,), rules=(rule,)))
    incident, _ = Coordinator(store).submit(signal(store.settings))
    result = await run_probe(
        store,
        incident_id=incident.incident_id,
        revision=store.read().revision,
        scenario="same_jwt",
        operator="reviewer",
        inputs=ProofInput(),
    )
    assert result["reason_code"] == "proof_required"
    assert result["outcomes"] == {"same_jwt": "inconclusive"}
    assert store.read().provider_actions[0].observations[-1].before_succeeded is False


async def test_unknown_scenario_fails_before_network(tmp_path, workspace_settings):
    """Scenario selection is an allowlist rather than a dynamic module or remote target."""
    from agent.response.providers.workflow import run_probe

    store = provider_store(workspace_settings, tmp_path)
    with pytest.raises(ResponseError):
        await run_probe(
            store,
            revision=store.read().revision,
            scenario="arbitrary-command",
            operator="reviewer",
            inputs=ProofInput(),
        )


async def test_isolated_post_event_probe_has_bounded_safe_output(tmp_path, workspace_settings):
    """The trusted subprocess can inspect state without exposing private configuration."""
    from agent.response.providers.workflow import isolated_probe

    store = provider_store(workspace_settings, tmp_path)
    binding = resource(workspace_settings)
    rule = Rule(
        alias="proof-rule",
        actions=("block_registration",),
        bindings=(binding.binding_id,),
        required=frozenset({"block_registration"}),
    )
    activate(store, enrollment(store, bindings=(binding,), rules=(rule,)))
    incident, _ = Coordinator(store).submit(signal(store.settings))
    result = await isolated_probe(
        store,
        inputs=ProofInput(),
        incident_id=incident.incident_id,
        root_id=None,
        revision=store.read().revision,
        scenario="same_jwt",
        operator="reviewer",
    )
    assert result["outcomes"] == {"same_jwt": "inconclusive"}
    assert binding.native_id not in str(result)


@pytest.mark.parametrize("scenario", ["same_jwt", "fresh_issuance", "dynamic_database"])
async def test_before_event_after_same_jwt_with_healthy_peer(
    tmp_path, workspace_settings, identity_provider, scenario
):
    """A held same JWT is denied while another enrolled actor can still acquire and clean up."""
    import os
    from uuid import uuid4

    import httpx
    from pydantic import SecretStr

    from agent.recovery.store import RecoveryStore
    from agent.response.providers.workflow import run_probe
    from agent.schemas import Principal

    identity_provider.subject = "fixture-user"
    settings = workspace_settings.model_copy(
        update={
            "vault_addr": "https://provider.example",
            "vault_token": SecretStr("fixture-admin"),
            "vault_audience": "vault",
            "database_host": "database.example",
            "database_name": "fixture",
        }
    )
    recovery = RecoveryStore(settings, project=tmp_path)
    recovery.initialize()
    from response_support import enrolled

    if scenario == "dynamic_database":
        from agent.response.store import ResponseStore
        from agent.validation.models import canonical

        store = ResponseStore(settings, project=tmp_path, recovery=recovery)
        store.prepare()
        (store.root / "policy.json").write_bytes(
            canonical(store.policy().model_copy(update={"automatic_cleanup": True}))
        )
        store.initialize()
    else:
        store = enrolled(settings, tmp_path, recovery=recovery)
    target = resource(settings, actor_subject="actor")
    peer = resource(
        settings, alias="peer-registration", native_id="peer-resource", actor_subject="peer-actor"
    )
    rule = Rule(
        alias="proof-rule",
        actions=("block_registration",),
        bindings=(target.binding_id,),
        required=frozenset({"block_registration"}),
    )
    dynamic_policy = {}
    connections = []
    if scenario == "dynamic_database":
        import json

        path = store.root / "provider-secrets.json"
        path.write_text(
            json.dumps(
                {
                    "dynamic-health": "host=database.example port=5432 "
                    "dbname=fixture user=healthy-role password=fixture"
                }
            )
        )
        path.chmod(0o600)
        dynamic_policy = {"dynamic_healthy_secret_alias": "dynamic-health"}
    activate(store, enrollment(store, bindings=(target, peer), rules=(rule,), **dynamic_policy))
    run, owner = store.register(
        uuid4(), uuid4(), Principal(issuer=settings.oauth_issuer, subject="fixture-user")
    )
    healthy, healthy_owner = store.register(
        uuid4(), uuid4(), Principal(issuer=settings.oauth_issuer, subject="fixture-peer")
    )
    store.bind_actor(run, settings.oauth_issuer, "actor")
    store.bind_actor(healthy, settings.oauth_issuer, "peer-actor")
    details = [
        {"type": "vault:path_access", "path": settings.vault_read_path, "capabilities": ["read"]}
    ]
    token = identity_provider.access(
        sub="fixture-user",
        aud="vault",
        act={"iss": settings.oauth_issuer, "sub": "actor"},
        authorization_details=details,
    )
    peer_token = identity_provider.access(
        sub="fixture-peer",
        aud="vault",
        act={"iss": settings.oauth_issuer, "sub": "peer-actor"},
        authorization_details=details,
    )
    blocked = False
    sequence = 0

    def handle(request):
        """Use exact synthetic routes and deny only the registration's original JWT."""
        nonlocal sequence
        if request.url.host == "id.example":
            return identity_provider.handle(request)
        if request.method == "PUT":
            for connection in connections:
                if connection.role == "fixture-role":
                    connection.terminated = True
            return httpx.Response(204)
        if request.method == "DELETE":
            return httpx.Response(204)
        if request.method == "GET" and request.url.path.endswith(settings.vault_read_path):
            if blocked and request.headers.get("X-Vault-Token") != peer_token:
                return httpx.Response(403, json={"errors": ["denied"]})
            sequence += 1
            return httpx.Response(
                200,
                json={
                    "lease_id": settings.vault_read_path + f"/fixture-{sequence}",
                    "lease_duration": 60,
                    "data": {"username": "fixture-role", "password": "fixture-password"},
                },
            )
        pytest.fail("uncompiled request")

    transport = httpx.MockTransport(handle)
    incident = None
    processing = []

    async def connect(parameters):
        """Use native-shaped independent session failures instead of root cancellation."""
        from test_provider_database_proof import Failure, Session

        if blocked and parameters["user"] == "fixture-role":
            raise Failure("28P01")
        connection = Session(parameters["user"])
        connections.append(connection)
        return connection

    def ready(output):
        """Commit the hold and close application owners independently of the proof process."""
        nonlocal blocked, incident
        incident, _ = Coordinator(store).submit(signal(settings))
        blocked = True
        store.finish(run)
        store.finish(healthy)
        os.close(owner)
        os.close(healthy_owner)
        if scenario == "dynamic_database":
            import asyncio

            processing.append(
                asyncio.create_task(
                    Coordinator(store, transport=transport).process(incident.incident_id)
                )
            )
            return
        with store.transaction() as (fd, state):
            store.commit(
                fd,
                state,
                provider_actions=tuple(
                    type(a).model_validate(a.model_dump() | {"state": "acknowledged"})
                    for a in state.provider_actions
                ),
            )

    result = await run_probe(
        store,
        root_id=run.root_run_id,
        revision=store.read().revision,
        scenario=scenario,
        operator="reviewer",
        inputs=ProofInput(
            delegated_token=token,
            healthy_delegated_token=peer_token,
            healthy_root=healthy.root_run_id,
            subject_token=identity_provider.access(sub="fixture-user"),
            actor_token=identity_provider.access(sub="actor", aud="actor"),
        ),
        transport=transport,
        connect=connect if scenario == "dynamic_database" else None,
        ready=ready,
    )
    if processing:
        await processing[0]
    assert result["outcomes"] == (
        {"dynamic_fresh": "proven", "dynamic_session": "proven"}
        if scenario == "dynamic_database"
        else {scenario: "proven"}
    )
    if scenario == "dynamic_database":
        assert store.summary(incident).database_checks == result["outcomes"]
    assert all(
        p.state in {"cleaned", "denied_no_issuance"}
        for p in store.read().probe_acquisitions
        if p.credential_class == "vault_lease"
    )
    assert all(a.state == "resolved" for a in recovery.read().attempts)


@pytest.mark.parametrize("malformed_peer", [False, True])
async def test_root_native_token_loss_preserves_same_actor_peer(
    tmp_path, workspace_settings, malformed_peer
):
    """Exclusive root tokens can be revoked independently without blocking a shared actor."""
    import os
    from uuid import uuid4

    import httpx
    from response_support import principal

    from agent.response.guard import RootGuard
    from agent.response.providers.enrollment import native_begin, native_update
    from agent.response.providers.workflow import run_probe

    settings = workspace_settings.model_copy(update={"vault_addr": "https://provider.example"})
    store = provider_store(settings, tmp_path)
    registration = resource(settings)
    rule = Rule(
        alias="root-rule",
        scope="root_run",
        actions=("revoke_native_token",),
        required=frozenset({"revoke_native_token"}),
    )
    activate(
        store,
        enrollment(
            store,
            bindings=(registration,),
            rules=(rule,),
            native_login_mount="jwt",
            native_login_role="exclusive",
            native_exclusive_tree=True,
        ),
    )
    roots = [store.register(uuid4(), uuid4(), principal(settings)) for _ in range(2)]
    for index, (root, owner) in enumerate(roots):
        store.bind_actor(root, registration.actor_issuer, registration.actor_subject)
        item = native_begin(
            store, RootGuard(store, root, owner), "jwt", "exclusive", settings.vault_addr, ""
        )
        item = native_update(store, item, "submitted")
        native_update(
            store,
            item,
            "bound",
            origin=settings.vault_addr,
            auth={
                "token_type": "service",
                "accessor": f"accessor-{index}",
                "client_token": f"fixture-token-{index}",
            },
        )
    blocked = False

    def handle(request):
        """Deny only the target token and preserve the separately owned peer."""
        token = request.headers["X-Vault-Token"]
        index = int(token.rsplit("-", 1)[1])
        if blocked and index == 1 and malformed_peer:
            return httpx.Response(200, json={"errors": ["invalid peer state"]})
        if blocked and index == 0:
            return httpx.Response(403, json={"errors": ["denied"]})
        return httpx.Response(
            200, json={"data": {"accessor": f"accessor-{index}", "type": "service", "ttl": 600}}
        )

    def ready(output):
        """Contain one root, retaining the other root's exact native ownership."""
        nonlocal blocked
        Coordinator(store).submit(signal(settings, root=roots[0][0].root_run_id))
        blocked = True
        for root, owner in roots[:1]:
            store.finish(root)
            os.close(owner)
        with store.transaction() as (fd, state):
            store.commit(
                fd,
                state,
                provider_actions=tuple(
                    type(a).model_validate(a.model_dump() | {"state": "acknowledged"})
                    for a in state.provider_actions
                ),
            )

    result = await run_probe(
        store,
        root_id=roots[0][0].root_run_id,
        revision=store.read().revision,
        scenario="native_token",
        operator="reviewer",
        inputs=ProofInput(
            native_token="fixture-token-0",
            healthy_native_token="fixture-token-1",
            healthy_root=roots[1][0].root_run_id,
        ),
        transport=httpx.MockTransport(handle),
        ready=ready,
    )
    assert result["outcomes"] == {"native_token": "inconclusive" if malformed_peer else "proven"}
    store.check(roots[1][0])
    store.finish(roots[1][0])
    os.close(roots[1][1])
    assert len(store.read().provider_actions) == 1
    assert store.read().provider_actions[0].binding.root_run_id == roots[0][0].root_run_id


@pytest.mark.parametrize("scalar_ids", [False, True])
async def test_tenant_sessions_before_after_with_reviewed_schema(
    tmp_path, workspace_settings, scalar_ids
):
    """Only the mapped user's preexisting tenant sessions disappear; peer sessions remain."""
    import os
    from uuid import uuid4

    import httpx
    from pydantic import SecretStr
    from response_support import principal

    from agent.response.providers.workflow import run_probe

    settings = workspace_settings.model_copy(
        update={
            "verify_tenant_url": "https://provider.example",
            "verify_api_client_id": "fixture",
            "verify_api_client_secret": SecretStr("fixture"),
            "oauth_token_endpoint": "https://provider.example/token",
            "oauth_provider": "generic",
        }
    )
    store = provider_store(settings, tmp_path)
    user = resource(
        settings,
        "user",
        session_id_field="@" if scalar_ids else "sessionId",
        session_schema_digest="1" * 64,
    )
    peer = resource(
        settings,
        "user",
        alias="peer-user",
        native_id="peer-user",
        user_subject="peer",
        session_id_field="@" if scalar_ids else "sessionId",
        session_schema_digest="1" * 64,
    )
    rule = Rule(
        alias="sessions-rule",
        actions=("revoke_user_sessions",),
        bindings=(user.binding_id,),
        required=frozenset({"revoke_user_sessions"}),
    )
    activate(store, enrollment(store, bindings=(user, peer), rules=(rule,)))
    root, owner = store.register(uuid4(), uuid4(), principal(settings))
    revoked = False

    def handle(request):
        """Return private native session IDs only inside the trusted proof process."""
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "fixture", "token_type": "Bearer"})
        if request.url.path.endswith("peer-user"):
            return httpx.Response(
                200, json=["peer-session"] if scalar_ids else [{"sessionId": "peer-session"}]
            )
        return httpx.Response(
            200,
            json=[]
            if revoked
            else ["old-session"]
            if scalar_ids
            else [{"sessionId": "old-session"}],
        )

    def ready(output):
        """Commit the exact tenant hold and complete its acknowledged control."""
        nonlocal revoked
        Coordinator(store).submit(signal(settings))
        revoked = True
        store.finish(root)
        os.close(owner)
        with store.transaction() as (fd, state):
            store.commit(
                fd,
                state,
                provider_actions=tuple(
                    type(a).model_validate(a.model_dump() | {"state": "acknowledged"})
                    for a in state.provider_actions
                ),
            )

    result = await run_probe(
        store,
        root_id=root.root_run_id,
        revision=store.read().revision,
        scenario="user_sessions",
        operator="reviewer",
        inputs=ProofInput(healthy_binding=peer.binding_id),
        transport=httpx.MockTransport(handle),
        ready=ready,
    )
    assert result["outcomes"] == {"tenant_sessions": "proven"}
    assert "old-session" not in str(result)


@pytest.mark.parametrize("rotation_ttl,expected", [(600, "proven"), (1, "inconclusive")])
async def test_static_before_event_after_attribution(
    tmp_path, workspace_settings, rotation_ttl, expected
):
    """Scheduled rotation can obscure password attribution; session loss stays separate."""
    import hashlib
    import json
    import os
    from uuid import uuid4

    import httpx
    from pydantic import SecretStr
    from response_support import principal
    from test_provider_database_proof import Failure, Session

    from agent.response.providers.workflow import run_probe

    settings = workspace_settings.model_copy(
        update={"vault_addr": "https://provider.example", "vault_token": SecretStr("fixture")}
    )
    store = provider_store(settings, tmp_path)
    secrets = {
        "static-proof": "host=database.example port=5432 dbname=fixture user=isolated",
        "static-health": "host=database.example port=5432 dbname=fixture user=healthy",
    }
    path = store.root / "provider-secrets.json"
    path.write_text(json.dumps(secrets))
    path.chmod(0o600)
    binding = resource(
        settings,
        "static_role",
        proof_secret_alias="static-proof",
        healthy_secret_alias="static-health",
        proof_secret_digest=hashlib.sha256(secrets["static-proof"].encode()).hexdigest(),
        healthy_secret_digest=hashlib.sha256(secrets["static-health"].encode()).hexdigest(),
    )
    rule = Rule(
        alias="static-rule",
        actions=("rotate_static", "terminate_static_sessions"),
        bindings=(binding.binding_id,),
        required=frozenset({"rotate_static", "terminate_static_sessions"}),
    )
    activate(store, enrollment(store, bindings=(binding,), rules=(rule,)))
    root, owner = store.register(uuid4(), uuid4(), principal(settings))
    rotated = False
    connections = []

    async def connect(parameters):
        """Keep old and healthy sessions independent across native credential rotation."""
        if rotated and parameters.get("password") == "old":
            raise Failure("28P01")
        connection = Session(parameters["user"])
        connections.append(connection)
        return connection

    def handle(request):
        """Expose credentials solely to the compiled explicitly authorized proof route."""
        assert request.method == "GET" and "/static-creds/" in request.url.path
        return httpx.Response(
            200,
            json={
                "data": {
                    "username": "isolated",
                    "password": "new" if rotated else "old",
                    "ttl": rotation_ttl,
                }
            },
        )

    def ready(output):
        """Simulate acknowledged isolated controls after the before-state exists."""
        nonlocal rotated
        Coordinator(store).submit(signal(settings))
        rotated = True
        for connection in connections:
            if connection.role == "isolated":
                connection.terminated = True
        store.finish(root)
        os.close(owner)
        with store.transaction() as (fd, state):
            store.commit(
                fd,
                state,
                provider_actions=tuple(
                    type(a).model_validate(a.model_dump() | {"state": "acknowledged"})
                    for a in state.provider_actions
                ),
            )

    result = await run_probe(
        store,
        root_id=root.root_run_id,
        revision=store.read().revision,
        scenario="static_database",
        operator="reviewer",
        inputs=ProofInput(),
        transport=httpx.MockTransport(handle),
        connect=connect,
        ready=ready,
    )
    assert result["outcomes"] == {
        "static_old": expected,
        "static_new": expected,
        "static_session": "proven",
    }
    assert all(connection.closed for connection in connections)
