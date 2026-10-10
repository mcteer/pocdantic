"""Reject ambiguous authority and preserve strict private/public schema boundaries."""

import pytest
from provider_support import enrollment, provider_store, resource
from pydantic import ValidationError


def test_duplicate_native_resource_rejected(tmp_path, workspace_settings):
    """Different aliases cannot authorize two effects on the same native resource."""
    store = provider_store(workspace_settings, tmp_path)
    one = resource(workspace_settings)
    two = resource(workspace_settings, alias="another")
    with pytest.raises(ValidationError):
        enrollment(store, bindings=(one, two))


def test_root_scope_cannot_select_shared_control(workspace_settings):
    """Root rules cannot silently delete a shared registration or suspend a user."""
    from agent.response.providers.models import Rule

    with pytest.raises(ValidationError):
        Rule(alias="root-rule", scope="root_run", actions=("block_registration",))


def test_private_repr_extra_fields_and_schema(workspace_settings):
    """Strict versions reject coercion and debugging never prints native identifiers."""
    item = resource(workspace_settings)
    assert item.native_id not in repr(item)
    for change in ({"schema_version": "1"}, {"unknown": "secret"}):
        with pytest.raises(ValidationError):
            type(item).model_validate(item.model_dump() | change)


def test_models_require_utc_and_closed_results(workspace_settings):
    """Provider messages cannot become typed proof outcomes or naive timestamps."""
    from agent.response.providers.models import ProviderAction

    item = resource(workspace_settings)
    with pytest.raises(ValidationError):
        ProviderAction(
            binding=item,
            kind="block_registration",
            enrollment_digest="0" * 64,
            state="secret exception",
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"generation": True},
        {"generation": 0},
        {"checked_at": "2026-01-01T00:00:00"},
        {"origin": "https://provider.example/path"},
        {"origin": "https://user:secret@provider.example"},
        {"kind": "native_token", "token_type": "batch", "exclusive_tree": True},
    ],
)
def test_invalid_resource_contract(workspace_settings, changes):
    """Strict generations, UTC and destination/ownership constraints fail before effects."""
    with pytest.raises(ValidationError):
        resource(workspace_settings, **changes)


def test_enrollment_capacity(tmp_path, workspace_settings):
    """Capacity is rejected at the boundary before any provider request is possible."""
    store = provider_store(workspace_settings, tmp_path)
    bindings = tuple(
        resource(workspace_settings, alias=f"resource-{i}", native_id=f"native-{i}")
        for i in range(65)
    )
    with pytest.raises(ValidationError):
        enrollment(store, bindings=bindings)


def test_action_dependency_cycle_rejected(tmp_path, workspace_settings):
    """A persisted dependency cycle must fail closed rather than stall forever."""
    from uuid import uuid4

    from response_support import signal

    from agent.response.coordinator import Coordinator
    from agent.response.providers.models import ProviderAction

    store = provider_store(workspace_settings, tmp_path)
    incident, _ = Coordinator(store).submit(signal(workspace_settings))
    first, second = uuid4(), uuid4()
    binding = resource(workspace_settings)
    actions = tuple(
        ProviderAction(
            action_id=aid,
            kind="block_registration",
            binding=binding,
            incidents=(incident.incident_id,),
            enrollment_digest="0" * 64,
            dependencies=(dep,),
        )
        for aid, dep in ((first, second), (second, first))
    )
    state = store.read()
    with pytest.raises(ValidationError):
        type(state).model_validate(state.model_dump() | {"provider_actions": actions})


def test_bound_native_acquisition_requires_exact_owned_service(workspace_settings):
    """A bound native token cannot be represented without trusted exclusive ownership."""
    from uuid import uuid4

    from agent.recovery.models import BoundOwnership
    from agent.response.providers.models import NativeTokenAcquisition

    owner = BoundOwnership(
        root_run_id=uuid4(),
        request_id=uuid4(),
        workload_definition=workspace_settings.workload_definition,
        issuer="https://issuer.example",
        subject="fixture-user",
        generation=1,
    )
    with pytest.raises(ValidationError):
        NativeTokenAcquisition(
            ownership=owner,
            actor_issuer="https://issuer.example",
            actor_subject="fixture-actor",
            mount="jwt",
            role="exclusive",
            enrollment_digest="1" * 64,
            state="bound",
        )


def test_probe_cleanup_requires_actual_credential_identity(workspace_settings):
    """A typed cleaned label cannot invent a lease handle or its exact recovery linkage."""
    from response_support import binding

    from agent.response.providers.models import ProbeAcquisition

    owner = binding(workspace_settings).ownership()
    for state in ("issued", "cleanup_pending", "cleaned"):
        with pytest.raises(ValidationError):
            ProbeAcquisition(
                ownership=owner,
                credential_path="database/creds/fixture",
                enrollment_digest="1" * 64,
                scenario="same_jwt",
                state=state,
            )


def test_active_probe_capacity_rejected_atomically(tmp_path, workspace_settings):
    """The seventeenth unknown issuance is rejected without erasing the first sixteen."""
    from response_support import binding

    from agent.response.providers.models import ProbeAcquisition

    store = provider_store(workspace_settings, tmp_path)
    owner = binding(workspace_settings).ownership()
    probes = tuple(
        ProbeAcquisition(
            ownership=owner,
            credential_path="database/creds/fixture",
            enrollment_digest="1" * 64,
            scenario="same_jwt",
        )
        for _ in range(17)
    )
    with pytest.raises(ValidationError):
        type(store.read()).model_validate(
            store.read().model_dump() | {"probe_acquisitions": probes}
        )
    assert not store.read().probe_acquisitions
