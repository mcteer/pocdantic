"""Typed lifecycle events and private native-operation bindings.

Public events contain closed metadata, while private bindings connect operations to
source evidence. Observer health is shared across parent/child runs. Storage failures
are surfaced without bypassing authorization or preventing cleanup finally blocks.
"""

from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from .validation.models import LifecycleEvent, PrivateOperationBinding


class EventSink(Protocol):
    def emit(self, event: LifecycleEvent) -> None:
        """Accept one bounded lifecycle event without receiving task or credential
        payloads.
        """
        ...


class PrivateOperationSink(Protocol):
    def bind(self, binding: PrivateOperationBinding) -> None:
        """Persist private operation metadata used to correlate native source evidence."""
        ...


class NullSink:
    def emit(self, event):
        """Discard lifecycle events when no evidence sink has been configured."""
        pass

    def bind(self, binding):
        """Discard private bindings when no evidence sink has been configured."""
        pass


class StoreSink:
    def __init__(self, writer):
        """Bind lifecycle and native-operation storage to a locked private run writer."""
        self.writer = writer

    def emit(self, event):
        """Append one typed lifecycle event to the private run journal."""
        self.writer.append_event(event)

    def transaction(self, observer, source_instance, approval, data, raw, approved):
        """Persist original Verify bytes and a digest-bound normalized transaction record.

        Keep provider-native fields private and expose only the precise decision to
        trusted scenario code.
        """
        import hashlib

        from .validation.models import TransactionEvidence
        from .validation.store import decode_json

        # Preserve original bytes, including unknown private fields, after verified native binding.
        decode_json(raw)
        value = TransactionEvidence(
            validation_id=observer.validation_id,
            observation_id=observer.observation_id,
            run_id=observer.run_id,
            source_instance=source_instance,
            native_transaction_id=data["id"],
            approval_ref=approval.id,
            action_digest=approval.digest,
            decision=observer_decision(data, approved),
            raw_digest=hashlib.sha256(raw).hexdigest(),
        )
        self.writer.write_bytes(f"source-{value.artifact_id}.raw", raw)
        self.writer.write_json(f"transaction-{value.artifact_id}.json", value)
        self.phone_decision = value.decision

    def bind(self, binding):
        # Immutable stages retain the pre-call record and subsequent native response binding.
        """Append immutable binding stages, retaining both pre-call intent and native
        response IDs.
        """
        self.writer.append_event(binding, "bindings.jsonl")


PHASES = {
    "run": "run",
    "delegation": "delegation",
    "policy": "policy",
    "approval": "approval",
    "identity": "identity",
    "credential": "credential",
    "database": "database",
    "database.read": "database",
    "cleanup": "cleanup",
    "telemetry": "telemetry",
    "report": "report",
}
DETAILS = frozenset(
    (
        "started",
        "completed",
        "failed",
        "denied",
        "allowed",
        "pending",
        "contained",
        "interrupted",
        "acquired",
        "revoked",
        "verified",
        "attempted",
        "acknowledged",
        "received",
        "blocked",
    )
)


@dataclass
class BoundObserver:
    sink: EventSink
    request_id: UUID
    run_id: UUID
    agent_ref: UUID
    workload_ref: UUID
    parent_run_id: UUID | None = None
    validation_id: UUID | None = None
    observation_id: UUID | None = None
    health: list[bool] = field(default_factory=lambda: [False])
    telemetry: object = None
    expected_outcome: str = "success"
    definition_ref: Callable | None = None

    @property
    def failed(self):
        """Read shared observer health so a child storage failure is visible to its parent."""
        return self.health[0]

    @failed.setter
    def failed(self, value):
        """Update the shared failure flag without replacing the parent/child health
        reference.
        """
        self.health[0] = value

    def record(self, phase, detail, **metadata) -> bool:
        """Emit a supported lifecycle event and optional metadata-only span.

        Unsupported labels are ignored. Sink failures set the shared failure flag and
        return false rather than interrupting a caller’s cleanup path.
        """
        if phase not in PHASES or detail not in DETAILS:
            return False
        try:
            event = LifecycleEvent(
                request_id=self.request_id,
                run_id=self.run_id,
                agent_ref=self.agent_ref,
                workload_ref=self.workload_ref,
                parent_run_id=self.parent_run_id,
                validation_id=self.validation_id,
                observation_id=self.observation_id,
                phase=PHASES[phase],
                detail=detail,
                **metadata,
            )
            attributes = {
                k: str(v) if isinstance(v, UUID) else v
                for k, v in event.model_dump().items()
                if v is not None
            }
            span_context = (
                self.telemetry.provider.get_tracer("agent").start_as_current_span(
                    PHASES[phase], attributes=attributes
                )
                if self.telemetry
                else nullcontext()
            )
            with span_context as span:
                if span and span.get_span_context().is_valid:
                    context = span.get_span_context()
                    event = event.model_copy(
                        update={
                            "trace_id": f"{context.trace_id:032x}",
                            "span_id": f"{context.span_id:016x}",
                        }
                    )
                self.sink.emit(event)
            return True
        except Exception:
            self.failed = True
            return False

    def fact(self, name, **private):
        """Trusted in-process facts; never copied into lifecycle or telemetry fields."""
        callback = getattr(self.sink, "fact", None)
        if callback:
            try:
                callback(name, **private)
            except Exception:
                self.failed = True
                if name in {
                    "cleanup_pending",
                    "cleanup_failed",
                    "cleanup_unknown",
                    "credential_uncertain",
                }:
                    return False
                raise ValueError("storage_error") from None
        return True

    def scope(self, phase):
        """Create a metadata-only span context for a trusted phase, or a no-op context."""
        if not self.telemetry:
            return nullcontext()
        attributes = {
            "request_id": str(self.request_id),
            "run_id": str(self.run_id),
            "agent_ref": str(self.agent_ref),
            "workload_ref": str(self.workload_ref),
        }
        for name in ("validation_id", "observation_id", "parent_run_id"):
            if getattr(self, name):
                attributes[name] = str(getattr(self, name))
        return self.telemetry.provider.get_tracer("agent").start_as_current_span(
            phase, attributes=attributes
        )

    def begin_operation(self, **private_metadata):
        # A failed pre-call private binding must be visible to trusted callers before an effect.
        """Persist the private pre-call binding before an observed external effect.

        A storage failure raises before the effect can start; return the binding so the
        response can later attach its native IDs.
        """
        try:
            binding = PrivateOperationBinding(run_id=self.run_id, **private_metadata)
            self.sink.bind(binding)
        except Exception:
            self.failed = True
            raise ValueError("storage_error") from None
        self.record(binding.phase, "attempted", operation_ref=binding.operation_ref)
        return binding

    def finish_operation(self, binding, **native_fields):
        """Append native response fields to the binding, marking observer failure if
        unwritable.
        """
        from .validation.models import now

        try:
            updated = PrivateOperationBinding.model_validate(
                binding.model_dump() | native_fields | {"finished_at": now()}
            )
            self.sink.bind(updated)
            return updated
        except Exception:
            self.failed = True
            return binding


def observer_decision(data, approved):
    """Distinguish a verified approval, an explicit native denial, and an unverified
    outcome.
    """
    return (
        "approved"
        if approved
        else "denied"
        if data.get("state") in {"DENIED", "VERIFY_DENIED", "USER_DENIED"}
        else "unverified"
    )
