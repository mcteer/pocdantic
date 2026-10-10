"""Imported proof is bounded, correlated, reviewed and independently classified."""

from uuid import uuid4

import pytest
from provider_support import activate, enrollment, provider_store, resource
from response_support import signal

from agent.response.coordinator import Coordinator
from agent.response.models import ResponseError
from agent.response.providers.models import Observation, Rule
from agent.validation.models import canonical, implementation_revision


def setup(store):
    """Commit one held synthetic registration incident for exact evidence correlation."""
    binding = resource(store.settings)
    rule = Rule(
        alias="proof-rule",
        actions=("block_registration",),
        bindings=(binding.binding_id,),
        required=frozenset({"block_registration"}),
    )
    activate(store, enrollment(store, bindings=(binding,), rules=(rule,)))
    incident, _ = Coordinator(store).submit(signal(store.settings))
    state = store.read()
    action = state.provider_actions[0]
    observation = Observation(
        installation_id=state.installation_id,
        environment_digest=state.environment_digest,
        implementation_digest=implementation_revision(),
        enrollment_digest=action.enrollment_digest,
        incident_id=incident.incident_id,
        action_id=action.action_id,
        binding_id=binding.binding_id,
        resource_generation=binding.generation,
        path="registration",
        result="proven",
        source="synthetic",
        source_digest="2" * 64,
    )
    return observation


def test_import_is_idempotent_and_conflict_closed(tmp_path, workspace_settings):
    """Identical observations deduplicate; a changed observation UUID cannot overwrite."""
    from agent.response.providers.proof import import_observation

    store = provider_store(workspace_settings, tmp_path)
    observation = setup(store)
    revision = store.read().revision
    assert import_observation(store, canonical(observation), revision) is True
    assert import_observation(store, canonical(observation), store.read().revision) is False
    changed = observation.model_copy(update={"source_digest": "3" * 64})
    with pytest.raises(ResponseError, match="provider_evidence_invalid"):
        import_observation(store, canonical(changed), store.read().revision)


def test_foreign_target_and_oversize_no_change(tmp_path, workspace_settings):
    """Foreign metadata and oversized import never update a journal."""
    from agent.response.providers.proof import import_observation

    store = provider_store(workspace_settings, tmp_path)
    observation = setup(store)
    revision = store.read().revision
    for raw in (
        canonical(observation.model_copy(update={"installation_id": uuid4()})),
        b" " * 1048577,
    ):
        with pytest.raises(ResponseError):
            import_observation(store, raw, revision)
        assert store.read().revision == revision


@pytest.mark.parametrize("start_bound,end_bound", [(None, 1), (1, None), (6, 1), (1, 6)])
def test_missing_or_excess_clock_bound_suppresses_interval(start_bound, end_bound):
    """Unsynchronized provider clocks never produce a precise-looking elapsed claim."""
    from agent.recovery.models import now
    from agent.response.providers.report import interval

    stamp = now()
    assert interval(stamp, stamp, start_bound, end_bound) is None


def test_timing_has_explicit_uncertainty_and_rejects_negative():
    """Cross-system ordering is represented as an interval, separate from local monotonic time."""
    from datetime import timedelta

    from agent.recovery.models import now
    from agent.response.providers.report import interval

    stamp = now()
    assert interval(stamp, stamp + timedelta(seconds=10), 1, 2) == {
        "lower_ms": 7000,
        "upper_ms": 13000,
        "uncertainty_ms": 3000,
    }
    assert interval(stamp, stamp - timedelta(seconds=1), 1, 1) is None


def test_new_synthetic_contradiction_cannot_hide_behind_old_live_proof(
    tmp_path, workspace_settings
):
    """Latest path evidence wins before source classification, even for synthetic contradictions."""
    from datetime import timedelta

    from agent.recovery.models import now
    from agent.response.providers.proof import complete

    store = provider_store(workspace_settings, tmp_path)
    observation = setup(store)
    action = store.read().provider_actions[0]
    observations = []
    for path in ("registration", "same_jwt", "fresh_issuance"):
        data = observation.model_dump() | {
            "observation_id": uuid4(),
            "path": path,
            "source": "live_probe",
            "reviewer": "reviewer",
            "reviewed_at": now(),
            "before_succeeded": True,
            "healthy_control": True,
            "credential_digest": "3" * 64,
            "credential_expires_at": now() + timedelta(seconds=600),
        }
        observations.append(Observation.model_validate(data))
    action = type(action).model_validate(
        action.model_dump() | {"state": "acknowledged", "observations": tuple(observations)}
    )
    assert complete(action, live=True, fresh=True)
    contradiction = Observation.model_validate(
        observations[-1].model_dump()
        | {
            "observation_id": uuid4(),
            "source": "synthetic",
            "result": "disproven",
            "observed_at": now(),
        }
    )
    action = type(action).model_validate(
        action.model_dump() | {"observations": (*action.observations, contradiction)}
    )
    assert not complete(action, live=True, fresh=True)
