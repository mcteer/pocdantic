import asyncio
import json
import time
from importlib.resources import files
from pathlib import Path
from uuid import uuid4

from pydantic import TypeAdapter
from pydantic_ai import Agent
from pydantic_ai.models import Model
from pydantic_ai.usage import UsageLimits

from .approval import ApprovalStore
from .capabilities import CAPABILITY_FACTORIES, ContainmentCapability, Dependencies
from .schemas import AgentDefinition, AgentOutput, AgentResponse, Principal, RequestEnvelope
from .security import Audit, Containment, Policy, SecurityError
from .settings import Settings
from .telemetry import safe_instrumentation


def load_definitions(path: str) -> dict[str, AgentDefinition]:
    profile = Path(path)
    if path == "config/agents.json" and not profile.is_file():
        content = files("pocdantic").joinpath("default_agents.json").read_text()
    else:
        content = profile.read_text()
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
    definition: AgentDefinition, model: str | Model
) -> Agent[Dependencies, AgentOutput]:
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
            safe_instrumentation(),
            ContainmentCapability(),
        ],
    )


class Runtime:
    def __init__(
        self,
        settings: Settings,
        *,
        model: str | Model | None = None,
        database_reader=None,
        approval_backend=None,
    ):
        self.settings = settings
        self.definitions = load_definitions(settings.profiles_file)
        selected = model or settings.model
        self.agents = {
            key: build_agent(definition, selected) for key, definition in self.definitions.items()
        }
        self.policy, self.containment, self.audit = Policy(), Containment(), Audit()
        self.approvals = ApprovalStore()
        self.database_reader = database_reader
        self.approval_backend = approval_backend
        self._active: dict = {}

    def contain_run(self, run_id) -> None:
        """Trusted control-plane entry point, not a model tool or public endpoint."""
        self.containment.block_run(run_id)
        if run_id in self._active:
            self._active[run_id][1].cancel()

    def contain_definition(self, definition: str) -> None:
        self.containment.block_definition(definition)
        for profile, task in list(self._active.values()):
            if profile == definition or definition == self.settings.workload_definition:
                task.cancel()

    async def run(
        self, request: RequestEnvelope, principal: Principal, *, database_reader=None
    ) -> AgentResponse:
        run_id = uuid4()
        limits = UsageLimits(
            request_limit=self.settings.request_limit,
            tool_calls_limit=self.settings.tool_calls_limit,
            output_tokens_limit=self.settings.output_tokens_limit,
        )
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
            database_reader=database_reader or self.database_reader,
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
            self.containment.check(self.settings.workload_definition, run_id)
            self.containment.check(request.profile, run_id)
            deps.record("run", "started")
            self._active[run_id] = (request.profile, asyncio.current_task())
            async with asyncio.timeout(self.settings.timeout_seconds):
                result = await self.agents[request.profile].run(
                    request.task,
                    deps=deps,
                    usage_limits=limits,
                    metadata={
                        "request_id": str(request.request_id),
                        "run_id": str(run_id),
                        "agent_definition": request.profile,
                        "workload_definition": self.settings.workload_definition,
                    },
                )
            self.containment.check(self.settings.workload_definition, run_id)
            deps.record("run", "completed")
            return AgentResponse(**common, status="completed", output=result.output)
        except SecurityError as error:
            deps.record("run", "denied")
            return AgentResponse(**common, status="denied", error_code=str(error))
        except asyncio.CancelledError:
            try:
                deps.check_containment()
            except SecurityError:
                deps.record("run", "contained")
                return AgentResponse(**common, status="denied", error_code="contained")
            raise
        except Exception:
            deps.record("run", "failed")
            return AgentResponse(**common, status="failed", error_code="agent_run_failed")
        finally:
            self._active.pop(run_id, None)
