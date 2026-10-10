import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import Literal
from uuid import UUID, uuid4

from .schemas import Action
from .security import SecurityError


def action_digest(subject: str, run_id: UUID, action: Action) -> str:
    value = {"subject": subject, "run_id": str(run_id), "action": action.model_dump()}
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass(frozen=True)
class ApprovalOutcome:
    decision: Literal["approved", "denied", "unconfirmed"]

    def __bool__(self):
        return self.decision == "approved"


@dataclass
class Approval:
    id: UUID
    digest: str
    subject: str
    expires_at: float
    run_id: UUID
    state: str = "pending"
    source_event: str | None = None


class ApprovalStore:
    """Trusted service-only state. No HTTP or model-facing decision setter."""

    def __init__(self):
        self._items: dict[UUID, Approval] = {}
        self._lock = threading.Lock()

    def create(self, subject: str, run_id: UUID, action: Action, ttl: float = 120) -> Approval:
        item = Approval(
            uuid4(), action_digest(subject, run_id, action), subject, time.monotonic() + ttl, run_id
        )
        with self._lock:
            self._items[item.id] = item
        return item

    def record_decision(
        self, approval_id: UUID, *, approved: bool, approver: str, source_event: str
    ) -> None:
        with self._lock:
            item = self._items.get(approval_id)
            if not item or item.state != "pending" or approver != item.subject or not source_event:
                raise SecurityError("approval_invalid")
            if time.monotonic() >= item.expires_at:
                item.state = "expired"
                raise SecurityError("approval_invalid")
            item.state = "approved" if approved else "denied"
            item.source_event = source_event

    def consume(self, approval_id: UUID, subject: str, run_id: UUID, action: Action) -> Approval:
        with self._lock:
            item = self._items.get(approval_id)
            if (
                not item
                or item.state != "approved"
                or time.monotonic() >= item.expires_at
                or item.digest != action_digest(subject, run_id, action)
            ):
                raise SecurityError("approval_invalid")
            item.state = "consumed"
            return item

    def invalidate(self, approval_id: UUID, state: str = "cancelled") -> None:
        if state not in {"cancelled", "unconfirmed", "superseded", "expired"}:
            raise ValueError("invalid approval terminal state")
        with self._lock:
            item = self._items.get(approval_id)
            if item and item.state in {"pending", "approved"}:
                item.state = state

    def invalidate_run(self, run_id: UUID) -> None:
        with self._lock:
            for item in self._items.values():
                if item.run_id == run_id and item.state in {"pending", "approved"}:
                    item.state = "cancelled"

    def forget_run(self, run_id: UUID) -> None:
        with self._lock:
            self._items = {key: item for key, item in self._items.items() if item.run_id != run_id}
