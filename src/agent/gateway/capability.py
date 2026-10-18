"""Every-turn admission and bounded model observation using trusted run dependencies."""

import asyncio
import time
from dataclasses import dataclass, field

from pydantic_ai.capabilities import AbstractCapability

from .config import digest, opaque_ref
from .models import GatewayError, ModelAttempt
from .transport import Dispatch, dispatch_scope


@dataclass
class ModelBoundary:
    """Owned model client and immutable transport/evidence bindings for one runtime."""

    client: object = field(repr=False)
    policy: object
    expected: dict = field(repr=False)
    store: object = field(repr=False)

    def check(self):
        """Require unchanged private controls immediately before each dispatch."""
        return self.store.admit(self.expected)

    async def aclose(self):
        """Drain the dedicated model HTTP client at host shutdown."""
        await self.client.aclose()


class GatewayCapability(AbstractCapability):
    """Attach a new context-local single-send guard to every root and child model turn."""

    def __init__(self, boundary):
        """Bind trusted control state, never a browser or model-supplied authority object."""
        self.boundary = boundary

    async def wrap_model_request(self, ctx, *, request_context, handler):
        """Record start before dispatch and terminal uncertainty without replaying effects."""
        deps, boundary = ctx.deps, self.boundary
        observer = deps.observer
        event = ModelAttempt(
            run_id=deps.run_id,
            request_id=deps.request_id,
            parent_run_id=deps.parent_run_id,
            definition_ref=observer.agent_ref,
            workload_ref=observer.workload_ref,
            sequence=ctx.run_step,
            route_ref=opaque_ref(boundary.expected["policy_digest"]),
            model_ref=opaque_ref(
                digest(boundary.expected["policy_digest"] + boundary.policy.model)
            ),
            protocol=boundary.policy.protocol,
            stage="admitted",
        )
        started = time.monotonic()
        state = Dispatch(check=lambda: (deps.check_containment(), boundary.check()))

        def record(stage, **updates):
            """Validate all derived metadata before it can reach storage or an exporter."""
            nonlocal event
            event = ModelAttempt.model_validate(event.model_dump() | {"stage": stage} | updates)
            telemetry = observer.telemetry
            if telemetry:
                try:
                    # The exporter filters correlation again; it never receives model content.
                    attributes = {
                        "run_id": str(deps.run_id),
                        "gateway_attempt_id": str(event.attempt_id),
                        "gateway_stage": stage,
                        "agent_ref": str(event.definition_ref),
                        "workload_ref": str(event.workload_ref),
                    }
                    if event.parent_run_id:
                        attributes["parent_run_id"] = str(event.parent_run_id)
                    if event.input_tokens is not None:
                        attributes["gen_ai.usage.input_tokens"] = event.input_tokens
                    if event.output_tokens is not None:
                        attributes["gen_ai.usage.output_tokens"] = event.output_tokens
                    with telemetry.provider.get_tracer("agent").start_as_current_span(
                        "model", attributes=attributes
                    ):
                        pass
                    if telemetry.delivery.state == "failed":
                        event = event.model_copy(update={"telemetry_state": "degraded"})
                except Exception:
                    event = event.model_copy(update={"telemetry_state": "degraded"})
            boundary.store.record(event)

        state.on_send = lambda: record("dispatched")
        try:
            deps.check_containment()
            review = boundary.check()
            state.signatures = review.error_signatures
            record("admitted")
            with dispatch_scope(state):
                response = await handler(request_context)
            usage = response.usage
            record(
                "completed",
                duration_ms=int((time.monotonic() - started) * 1000),
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
            )
            return response
        except BaseException as error:
            if isinstance(error, asyncio.CancelledError):
                stage, code = ("unknown" if state.sent else "cancelled"), None
            elif isinstance(error, GatewayError) or state.reason:
                code = state.reason or str(error)
                stage = "unknown" if code == "gateway_dispatch_unknown" else "denied"
            else:
                code, stage = "gateway_request_failed", "failed"
            # Observation failure must never interrupt credential/tool cleanup or mask cancellation.
            try:
                record(stage, reason=code, duration_ms=int((time.monotonic() - started) * 1000))
            except Exception:
                pass
            if isinstance(error, (GatewayError, asyncio.CancelledError)):
                raise
            raise GatewayError(code or "gateway_request_failed") from None
