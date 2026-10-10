"""Function 10 closeout keeps native source review separate from synthetic software tests."""

from pathlib import Path

import httpx
import pytest
from provider_support import activate, enrollment, provider_store, resource
from pydantic import SecretStr
from response_support import signal

from agent.response.coordinator import Coordinator
from agent.response.providers.models import Rule
from agent.response.providers.worker import Worker


def test_all_nine_paths_block_without_native_enrollment(tmp_path, workspace_settings):
    """No local cancellation, empty inventory or green test suite can certify providers."""
    from agent.validation.closeout import provider_closeout

    store = provider_store(workspace_settings, tmp_path)
    from response_support import signal

    from agent.response.coordinator import Coordinator

    incident, _ = Coordinator(store).submit(signal(workspace_settings))
    acceptance = Path("specs/007-provider-remediation/acceptance.json").read_bytes()
    report = provider_closeout(store.read(), incident.incident_id)
    assert len(report["cases"]) == 9
    assert {case["outcome"] for case in report["cases"]} == {"blocked"}
    assert Path("specs/007-provider-remediation/acceptance.json").read_bytes() == acceptance


@pytest.mark.parametrize(
    "kind,binding_kind",
    [
        ("block_registration", "registration"),
        ("suspend_user", "user"),
        ("revoke_user_sessions", "user"),
        ("rotate_static", "static_role"),
        ("notify_teams", "teams"),
    ],
)
@pytest.mark.parametrize("lost_reply", [False, True])
async def test_synthetic_control_matrix_is_not_native_acceptance(
    tmp_path, workspace_settings, kind, binding_kind, lost_reply
):
    """Real intake/planning/dispatch/status preserve separate acknowledgment and native proof."""
    from agent.validation.closeout import provider_closeout

    settings = workspace_settings.model_copy(
        update={
            "vault_addr": "https://provider.example",
            "vault_token": SecretStr("fixture"),
            "verify_tenant_url": "https://provider.example",
            "verify_api_client_id": "fixture",
            "verify_api_client_secret": SecretStr("fixture"),
            "oauth_token_endpoint": "https://provider.example/token",
            "oauth_provider": "generic",
        }
    )
    store = provider_store(settings, tmp_path)
    binding = resource(settings, binding_kind)
    rule = Rule(
        alias="matrix-rule",
        actions=(kind,),
        bindings=(binding.binding_id,),
        required=frozenset({kind}) if kind != "notify_teams" else frozenset(),
    )
    activate(store, enrollment(store, bindings=(binding,), rules=(rule,)))
    incident, _ = Coordinator(store).submit(signal(settings))
    calls = []

    def handle(request):
        """Acknowledge only synthetic routes; never contact a native provider."""
        calls.append(request)
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "fixture", "token_type": "Bearer"})
        if lost_reply:
            raise httpx.ReadError("PRIVATE_PROVIDER_CANARY", request=request)
        return httpx.Response(204)

    worker = Worker(store, transport=httpx.MockTransport(handle))
    await worker.process(incident.incident_id)
    worker.normalize()
    await worker.process(incident.incident_id)
    action = store.read().provider_actions[0]
    expected = "uncertain" if lost_reply else "acknowledged"
    assert action.state == expected
    assert all(o.result == "not_run" for o in action.observations)
    assert len([r for r in calls if r.url.path != "/token"]) == 1
    summary = store.summary(incident)
    assert summary.provider_controls[0].state == expected
    assert set(
        provider_closeout(store.read(), incident.incident_id)["cases"][i]["outcome"]
        for i in range(9)
    ) == {"blocked"}
    assert store.read().holds


@pytest.mark.parametrize("native_login", [False, True])
def test_reviewed_native_fixture_predicates_remain_independent(
    tmp_path, workspace_settings, native_login
):
    """A synthetic test of reviewed-evidence predicates passes only its covered paths."""
    from datetime import timedelta
    from uuid import uuid4

    from agent.recovery.models import now
    from agent.response.providers.enrollment import digest
    from agent.response.providers.models import Observation, SourceProfile
    from agent.validation.closeout import provider_closeout
    from agent.validation.models import implementation_revision

    store = provider_store(workspace_settings, tmp_path)
    # Test-only state construction avoids representing synthetic transport as live evidence.
    binding = resource(workspace_settings)
    source = SourceProfile(
        alias="native-source",
        issuer=workspace_settings.oauth_issuer,
        subject="collector",
        audience="native-events",
        schema_ref="fixture-v1",
        fixture_digest="1" * 64,
        collector_digest="2" * 64,
        provenance="native",
        reviewed_by="fixture-reviewer",
        reviewed_at=now(),
        clock_bound_seconds=1,
        pointers={"event_id": "/id", "occurred_at": "/time", "rule": "/rule", "object": "/object"},
        objects={"fixture-object": workspace_settings.workload_definition},
    )
    rule = Rule(
        alias="native-rule",
        source=source.alias,
        native_rule="fixture-rule",
        actions=("block_registration",),
        bindings=(binding.binding_id,),
        required=frozenset({"block_registration"}),
    )
    policy = enrollment(
        store,
        bindings=(binding,),
        sources=(source,),
        rules=(rule,),
        native_login_mount="jwt" if native_login else None,
        native_login_role="exclusive" if native_login else None,
        native_exclusive_tree=native_login,
    )
    with store.transaction() as (fd, state):
        store.commit(fd, state, enrollment=policy)
    incident, _ = Coordinator(store).submit(
        signal(workspace_settings), native=source, rule_alias=rule.alias
    )
    state = store.read()
    action = state.provider_actions[0]
    observations = []
    for path in ("native_intake", "registration", "same_jwt", "fresh_issuance"):
        observation = Observation(
            installation_id=state.installation_id,
            environment_digest=state.environment_digest,
            implementation_digest=implementation_revision(),
            enrollment_digest=digest(policy),
            incident_id=incident.incident_id,
            action_id=action.action_id,
            binding_id=binding.binding_id,
            resource_generation=1,
            path=path,
            result="proven",
            source="native_evidence",
            source_digest="3" * 64,
            reviewer="fixture-reviewer",
            reviewed_at=now(),
            observed_at=incident.received_at if path == "native_intake" else now(),
            event_digest=incident.payload_digest if path == "native_intake" else None,
            before_succeeded=True,
            healthy_control=True,
            credential_digest="4" * 64,
            credential_expires_at=now() + timedelta(seconds=600),
            clock_bound_seconds=1,
        )
        observations.append(observation)
    with store.transaction() as (fd, state):
        store.commit(
            fd,
            state,
            provider_actions=(
                type(action).model_validate(
                    action.model_dump()
                    | {"state": "acknowledged", "observations": tuple(observations)}
                ),
            ),
        )
    acceptance = Path("specs/007-provider-remediation/acceptance.json").read_bytes()
    cases = {
        case["case"]: case
        for case in provider_closeout(store.read(), incident.incident_id)["cases"]
    }
    assert cases["F10-T1"]["outcome"] == "pass" and cases["F10-T3"]["outcome"] == "pass"
    assert cases["F10-T2"]["outcome"] == "blocked" and cases["F10-T4"]["outcome"] == "blocked"
    assert cases["F10-T9"]["outcome"] == "pass"
    assert cases["F10-T8"]["outcome"] == ("blocked" if native_login else "pass")
    if native_login:
        assert "native_login_fresh_issuance_unverified" in cases["F10-T8"]["limitations"]
    latest = Observation.model_validate(
        observations[-2].model_dump()
        | {"observation_id": uuid4(), "result": "disproven", "observed_at": now()}
    )
    with store.transaction() as (fd, state):
        current = state.provider_actions[0]
        store.commit(
            fd,
            state,
            provider_actions=(
                type(current).model_validate(
                    current.model_dump() | {"observations": (*current.observations, latest)}
                ),
            ),
        )
    cases = {
        case["case"]: case
        for case in provider_closeout(store.read(), incident.incident_id)["cases"]
    }
    assert cases["F10-T3"]["outcome"] == "fail" and cases["F10-T9"]["outcome"] == "fail"
    assert Path("specs/007-provider-remediation/acceptance.json").read_bytes() == acceptance
