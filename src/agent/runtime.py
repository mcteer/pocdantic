"""Bounded agent execution with trusted identity, policy, containment, and audit.

Profiles select tools and delegation roles. Runtime dependencies carry authority
outside the model; cancellation invalidates approval state before a run is forgotten.
"""

import asyncio
import json
import time
from dataclasses import dataclass, replace
from uuid import UUID, uuid4

from opentelemetry.context import Context
from pydantic import TypeAdapter
from pydantic_ai import Agent
from pydantic_ai.messages import ModelMessage
from pydantic_ai.models import Model
from pydantic_ai.usage import UsageLimits

from .approval import ApprovalStore
from .capabilities import CAPABILITY_FACTORIES, ContainmentCapability, Dependencies
from .observability import BoundObserver, NullSink
from .schemas import AgentDefinition, AgentOutput, AgentResponse, Principal, RequestEnvelope
from .security import Audit, Containment, Policy, SecurityError
from .settings import Settings
from .telemetry import Telemetry, safe_instrumentation


def load_definitions(path: str) -> dict[str, AgentDefinition]:
    """Load strict profile definitions from the repository or packaged defaults.

    Reject unknown capabilities, duplicate profiles, or a child role broader than
    the supported read-only delegation contract.
    """
    from .validation.context import profile_bytes

    content = profile_bytes(path).decode("utf-8")
    definitions = TypeAdapter(list[AgentDefinition]).validate_python(json.loads(content))
    if len({x.id for x in definitions}) != len(definitions):
        raise SecurityError("profile_duplicate")
    for item in definitions:
        if not item.capabilities or any(x not in CAPABILITY_FACTORIES for x in item.capabilities):
            raise SecurityError("capability_unknown")
        if item.policy_role == "ticket-reader" and item.capabilities != ("ticket-read",):
            raise SecurityError("child_profile_overprivileged")
        if item.id == "ticket-reader" and item.policy_role != "ticket-reader":
            raise SecurityError("child_profile_overprivileged")
        if len(set(item.capabilities)) != len(item.capabilities):
            raise SecurityError("capability_duplicate")
        if "delegate-tickets" in item.capabilities and "ticket-reader" not in {
            x.id for x in definitions
        }:
            raise SecurityError("child_profile_missing")
    return {item.id: item for item in definitions}


def build_agent(
    definition: AgentDefinition, model: str | Model, telemetry=None
) -> Agent[Dependencies, AgentOutput]:
    """Construct a profile’s Pydantic AI agent with fixed tools, output schema, and limits."""
    return Agent(
        model,
        deps_type=Dependencies,
        output_type=AgentOutput,
        name=definition.id,
        instructions=definition.instructions,
        retries=1,
        tool_timeout=10,
        model_settings={"max_tokens": 1000},
        capabilities=[
            *(CAPABILITY_FACTORIES[name]() for name in definition.capabilities),
            safe_instrumentation(telemetry),
            ContainmentCapability(),
        ],
    )


@dataclass(frozen=True)
class RunContext:
    request_id: UUID
    run_id: UUID


class Runtime:
    def __init__(
        self,
        settings: Settings,
        *,
        model: str | Model | None = None,
        database_reader=None,
        approval_backend=None,
        telemetry=None,
        event_sink=None,
        definition_ref=None,
        validation_id=None,
        observation_id=None,
        response_store=None,
    ):
        """Build agents and process-local policy, audit, approval, and containment state.

        Inject trusted adapters and an optional private event sink without giving them
        to model prompts or public output.
        """
        self.settings = settings
        from .response.store import ResponseStore

        self.response_store = response_store or ResponseStore(settings)
        self.telemetry = telemetry or Telemetry()
        self.event_sink = event_sink or NullSink()
        self.validation_id, self.observation_id = validation_id, observation_id
        refs = {}
        self.definition_ref = definition_ref or (lambda name: refs.setdefault(name, uuid4()))
        self.definitions = load_definitions(settings.profiles_file)
        selected = model or settings.model
        self.agents = {
            key: build_agent(definition, selected, self.telemetry)
            for key, definition in self.definitions.items()
        }
        self.policy, self.containment, self.audit = Policy(), Containment(), Audit()
        self.approvals = ApprovalStore()
        self.database_reader = database_reader
        self.approval_backend = approval_backend
        self._active: dict = {}
        self._reserved: dict[UUID, RunContext] = {}

    def reserve(self, request_id: UUID) -> RunContext:
        """Allocate a run ID before asynchronous admission, binding it to the request ID."""
        context = RunContext(request_id, uuid4())
        # Reserve before any await so workspace admission and cancellation share one run ID.
        self._reserved[context.run_id] = context
        return context

    def forget(self, run_id: UUID) -> None:
        """Remove a finished run’s reservations and approval state; reject an active run."""
        if run_id in self._active:
            raise SecurityError("run_active")
        self._reserved.pop(run_id, None)
        self.approvals.forget_run(run_id)
        self.containment.blocked_runs.discard(run_id)

    def contain_run(self, run_id) -> None:
        """Trusted control-plane entry point, not a model tool or public endpoint."""
        self.containment.block_run(run_id)
        if run_id in self._active:
            self._active[run_id][1].cancel()

    def contain_definition(self, definition: str) -> None:
        """Block a profile or workload and cancel its matching active runs."""
        self.containment.block_definition(definition)
        for profile, task in list(self._active.values()):
            if profile == definition or definition == self.settings.workload_definition:
                task.cancel()

    async def run(self, request, principal, **kwargs):
        """Execute a task inside a fresh metadata-only root trace and return a safe
        AgentResponse.
        """
        tracer = self.telemetry.provider.get_tracer("agent")
        attributes = {"request_id": str(request.request_id)}
        if self.validation_id:
            attributes["validation_id"] = str(self.validation_id)
        if self.observation_id:
            attributes["observation_id"] = str(self.observation_id)
        with tracer.start_as_current_span("run", context=Context(), attributes=attributes):
            return await self._run(request, principal, **kwargs)

    async def run_action(self, request, principal, action, *, run_context):
        """Trusted exact-action entry point; no model or earlier tool replay."""
        return await self.run(request, principal, run_context=run_context, _action=action)

    async def _run(
        self,
        request: RequestEnvelope,
        principal: Principal,
        *,
        database_reader=None,
        message_history: list[ModelMessage] | None = None,
        run_context: RunContext | None = None,
        _action=None,
    ) -> AgentResponse:
        """Enforce identity, containment, usage, and time bounds around one reserved run.

        A trusted retry action bypasses model planning but retains policy and approval
        checks. Terminal paths invalidate outstanding approvals and release active
        state.
        """
        if run_context is not None:
            if (
                self._reserved.get(run_context.run_id) is not run_context
                or run_context.request_id != request.request_id
            ):
                raise SecurityError("run_context_invalid")
            self._reserved.pop(run_context.run_id)
            run_id = run_context.run_id
        else:
            run_id = uuid4()
        from opentelemetry.trace import get_current_span

        get_current_span().set_attribute("run_id", str(run_id))
        limits = UsageLimits(
            request_limit=self.settings.request_limit,
            tool_calls_limit=self.settings.tool_calls_limit,
            output_tokens_limit=self.settings.output_tokens_limit,
        )
        observer = BoundObserver(
            self.event_sink,
            request.request_id,
            run_id,
            self.definition_ref(request.profile),
            self.definition_ref(self.settings.workload_definition),
            validation_id=self.validation_id,
            observation_id=self.observation_id,
            telemetry=self.telemetry,
            definition_ref=self.definition_ref,
        )
        get_current_span().set_attributes(
            {"agent_ref": str(observer.agent_ref), "workload_ref": str(observer.workload_ref)}
        )
        selected_reader = database_reader or self.database_reader
        guard_context = None
        root_guard = None
        from .broker import DatabaseBroker

        if isinstance(selected_reader, DatabaseBroker):
            selected_reader = replace(selected_reader, operation_observer=observer)
        deps = Dependencies(
            principal,
            request.request_id,
            run_id,
            request.profile,
            self.settings.workload_definition,
            self.policy,
            self.containment,
            self.audit,
            self.approvals,
            self.agents.get("ticket-reader"),
            limits,
            policy_role=self.definitions[request.profile].policy_role
            if request.profile in self.definitions
            else None,
            database_reader=selected_reader,
            observer=observer,
            approval_backend=self.approval_backend,
        )
        common = {
            "request_id": request.request_id,
            "run_id": run_id,
            "correlation_id": str(request.request_id),
        }
        try:
            if principal.expires_at is not None and principal.expires_at <= time.time():
                raise SecurityError("identity_expired")
            if request.profile not in self.agents:
                raise SecurityError("profile_unknown")
            from .response.guard import root_scope

            guard_context = root_scope(
                self.response_store, request.request_id, run_id, principal, self.contain_run
            )
            root_guard = await guard_context.__aenter__()
            deps = replace(deps, root_guard=root_guard)
            if isinstance(selected_reader, DatabaseBroker):
                selected_reader = replace(selected_reader, run_guard=root_guard)
                deps = replace(deps, database_reader=selected_reader)
            deps.check_containment()
            deps.record("identity", "verified")
            deps.record("run", "started")
            self._active[run_id] = (request.profile, asyncio.current_task())
            async with asyncio.timeout(self.settings.timeout_seconds):
                if _action is not None:
                    from .capabilities import request_simulated_action

                    if (
                        "simulated-infrastructure"
                        not in self.definitions[request.profile].capabilities
                    ):
                        raise SecurityError("profile_unavailable")
                    await request_simulated_action(deps, _action)
                    result = None
                else:
                    result = await self.agents[request.profile].run(
                        request.task,
                        deps=deps,
                        message_history=message_history,
                        usage_limits=limits,
                        metadata={
                            "request_id": str(request.request_id),
                            "run_id": str(run_id),
                            "agent_definition": request.profile,
                            "workload_definition": self.settings.workload_definition,
                        },
                    )
            deps.check_containment()
            if message_history is not None:
                if result is not None:
                    message_history[:] = result.all_messages()
            deps.record("run", "completed")
            if observer.failed:
                return AgentResponse(**common, status="failed", error_code="storage_error")
            return AgentResponse(
                **common,
                status="completed",
                output=result.output
                if result
                else AgentOutput(summary="Completed simulated restart"),
            )
        except SecurityError as error:
            deps.record("run", "denied")
            return AgentResponse(**common, status="denied", error_code=str(error))
        except asyncio.CancelledError:
            try:
                deps.check_containment()
            except SecurityError:
                deps.record("run", "contained")
                return AgentResponse(**common, status="denied", error_code="contained")
            deps.record("run", "interrupted")
            raise
        except Exception:
            deps.record("run", "failed")
            return AgentResponse(**common, status="failed", error_code="agent_run_failed")
        finally:
            self.approvals.invalidate_run(run_id)
            self._active.pop(run_id, None)
            if guard_context is not None and root_guard is not None:
                await guard_context.__aexit__(None, None, None)
