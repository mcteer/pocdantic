from uuid import uuid4

from agent.observability import BoundObserver, NullSink
from agent.validation.store import PrivateStore


def test_typed_projection_and_private_bindings(tmp_path):
    store = PrivateStore(tmp_path / ".local/validation", project=tmp_path)
    public, private = [], []

    class Sink:
        def emit(self, event):
            public.append(event)

        def bind(self, value):
            private.append(value)

    observer = BoundObserver(
        Sink(),
        uuid4(),
        uuid4(),
        store.definition_ref("agent-canary"),
        store.definition_ref("workload-canary"),
    )
    observer.record("database.read", "completed")
    observer.record("secret-canary", "secret-canary")
    assert len(public) == 1 and public[0].phase == "database"
    assert "canary" not in public[0].model_dump_json()
    observer.begin_operation(
        validation_id=uuid4(),
        observation_id=uuid4(),
        source_kind="vault",
        source_instance="private-canary",
        phase="credential",
    )
    assert len(private) == 1 and private[0].native_request_id is None
    assert private[0].operation_ref == public[-1].operation_ref


def test_sink_failure_is_safe_and_does_not_raise():
    class Broken:
        def emit(self, event):
            raise RuntimeError("secret")

        def bind(self, value):
            raise RuntimeError("secret")

    observer = BoundObserver(Broken(), uuid4(), uuid4(), uuid4(), uuid4())
    assert not observer.record("cleanup", "completed")
    assert observer.failed
    assert NullSink().emit(None) is None


async def test_runtime_child_terminal_order_and_broken_sink():
    from agent.demo import model
    from agent.runtime import Runtime
    from agent.schemas import Principal, RequestEnvelope
    from agent.validation.scenarios import offline_settings

    events = []

    class Sink:
        def emit(self, event):
            events.append(event)

    runtime = Runtime(offline_settings(), model=model(), event_sink=Sink())
    response = await runtime.run(
        RequestEnvelope(task="synthetic"),
        Principal(issuer="synthetic", subject="synthetic", scopes=frozenset({"tickets:read"})),
    )
    assert response.status == "completed"
    child = [e for e in events if e.phase == "delegation"]
    assert [e.detail for e in child] == ["started", "completed"]
    assert all(e.parent_run_id == response.run_id for e in child)
    assert events[0].detail == "verified" and events[-1].detail == "completed"


async def test_failed_child_has_terminal_event():
    from agent.demo import model
    from agent.runtime import Runtime
    from agent.schemas import Principal, RequestEnvelope
    from agent.validation.scenarios import offline_settings

    events = []

    class Sink:
        def emit(self, event):
            events.append(event)

    runtime = Runtime(
        offline_settings().model_copy(update={"request_limit": 1}), model=model(), event_sink=Sink()
    )
    result = await runtime.run(
        RequestEnvelope(task="synthetic"),
        Principal(issuer="synthetic", subject="synthetic", scopes=frozenset({"tickets:read"})),
    )
    assert result.status == "failed"
    assert [e.detail for e in events if e.phase == "delegation"] == ["started", "failed"]


async def test_post_call_native_binding_validation_cannot_skip_cleanup():
    import httpx
    from pydantic import SecretStr

    from agent.vault import VaultClient

    calls = []

    class Sink:
        def emit(self, event):
            pass

        def bind(self, binding):
            pass

    observer = BoundObserver(
        Sink(), uuid4(), uuid4(), uuid4(), uuid4(), validation_id=uuid4(), observation_id=uuid4()
    )

    def handle(request):
        calls.append(request.method)
        return (
            httpx.Response(
                200,
                json={
                    "request_id": "private-" * 100,
                    "lease_id": "synthetic-lease",
                    "lease_duration": 60,
                    "data": {"username": "synthetic", "password": "synthetic"},
                },
            )
            if request.method == "GET"
            else httpx.Response(204)
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        async with VaultClient(
            "https://synthetic.invalid", "", http, operation_observer=observer
        ).credentials(SecretStr("synthetic"), "database/creds/read"):
            pass
    assert calls == ["GET", "PUT"] and observer.failed


def test_response_observer_only_closed_action_labels():
    """Response tracing never accepts incident identity or a provider's free text."""
    from contextlib import nullcontext
    from types import SimpleNamespace

    from agent.observability import response_action

    recorded = []

    class Tracer:
        def start_as_current_span(self, name, *, attributes):
            recorded.append((name, attributes))
            return nullcontext()

    telemetry = SimpleNamespace(provider=SimpleNamespace(get_tracer=lambda _: Tracer()))
    response_action(telemetry, "revoke_exact", "confirmed")
    assert recorded == [
        ("response", {"response_action": "revoke_exact", "response_status": "confirmed"})
    ]
