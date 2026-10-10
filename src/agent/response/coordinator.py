"""Contain first, then drain owners and reconcile attributable exact cleanup.

No model chooses an action. Submission never calls providers. Every network action
has prior durable intent, and uncertainty prevents automatic replay across incidents.
"""

import asyncio
import hashlib
import math
import time
from contextlib import nullcontext
from uuid import uuid4

from pydantic import ValidationError

from agent.recovery.models import now
from agent.recovery.store import RecoveryError
from agent.validation.models import canonical
from agent.validation.store import decode_json

from .models import (
    DefinitionHold,
    Incident,
    ReleaseRecord,
    ResponseAction,
    ResponseError,
    RiskSignal,
    Source,
)


def parse_signal(raw):
    """Strict bounded JSON including duplicate-key and depth rejection before mutation."""
    try:
        if len(raw) > 16384:
            raise ValueError()
        data = decode_json(raw)
        pending = [(data, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > 8:
                raise ValueError()
            if isinstance(value, dict):
                pending.extend((x, depth + 1) for x in value.values())
            if isinstance(value, list):
                pending.extend((x, depth + 1) for x in value)
        return RiskSignal.model_validate(data)
    except Exception:
        raise ResponseError("signal_invalid") from None


def elapsed_ms(start, end=None):
    """Return a same-process duration, or null when the monotonic clock is invalid."""
    elapsed = (time.monotonic() if end is None else end) - start
    return int(elapsed * 1000) if math.isfinite(elapsed) and elapsed >= 0 else None


class Coordinator:
    """One worker's fixed-target incident lifecycle, backed by authoritative journals."""

    def __init__(self, store, *, transport=None, cancel=None, work_budget=60, telemetry=None):
        """Inject provider transport/cancel callback only from a trusted host or fixture."""
        self.store = store
        self.transport = transport
        self.cancel = cancel
        self.work_budget = work_budget
        self.telemetry = telemetry

    def submit(
        self,
        signal,
        source=None,
        *,
        native=None,
        rule_alias=None,
        native_digest=None,
        native_enrollment_digest=None,
    ):
        """Persist a checked immutable scope and cancellation action before acknowledgment."""
        try:
            signal = RiskSignal.model_validate(signal.model_dump())
        except ValidationError:
            raise ResponseError("signal_invalid") from None
        policy = self.store.policy()
        alias = "local-operator"
        if native is not None:
            from .providers.models import SourceProfile

            state = self.store.read()
            if (
                not isinstance(native, SourceProfile)
                or state.schema_version != 2
                or state.enrollment is None
                or native not in state.enrollment.sources
                or signal.target.kind not in native.allowed_scopes
            ):
                raise ResponseError("source_invalid")
            from .providers.enrollment import digest as enrollment_digest

            captured_enrollment = enrollment_digest(state.enrollment)
            if (
                native_enrollment_digest is not None
                and native_enrollment_digest != captured_enrollment
            ):
                raise ResponseError("provider_policy_changed")
            if native_digest is not None:
                import re

                if not isinstance(native_digest, str) or not re.fullmatch(
                    r"[a-f0-9]{64}", native_digest
                ):
                    raise ResponseError("signal_invalid")
            alias = native.alias
        elif source is not None:
            if (
                not isinstance(source, Source)
                or source not in policy.sources
                or signal.target.kind not in source.allowed_scopes
            ):
                raise ResponseError("source_invalid")
            alias = source.alias
        digest = hashlib.sha256(
            canonical(
                {
                    "signal": signal.model_dump(mode="json"),
                    "profile": native.model_dump(mode="json"),
                    "rule": rule_alias,
                    "selected_digest": native_digest,
                    "enrollment_digest": captured_enrollment,
                }
            )
            if native
            else canonical(signal)
        ).hexdigest()
        with self.store.transaction() as (fd, state):
            if native is not None and (
                state.enrollment is None
                or enrollment_digest(state.enrollment) != captured_enrollment
            ):
                raise ResponseError("provider_policy_changed")
            if state.schema_version != 2:
                raise ResponseError("response_schema_migration_required")
            if native is not None and native not in state.enrollment.sources:
                raise ResponseError("provider_policy_changed")
            duplicate = next(
                (i for i in state.incidents if (i.source, i.event_id) == (alias, signal.event_id)),
                None,
            )
            if duplicate:
                if duplicate.payload_digest != digest:
                    raise ResponseError("event_conflict")
                return duplicate, False
            age = (now() - signal.occurred_at).total_seconds()
            if age > 300 or age < -30:
                raise ResponseError("signal_stale")
            target = signal.target
            if (
                target.kind == "definition"
                and target.workload_definition != policy.workload_definition
                or target.kind == "root_run"
                and not any(r.root_run_id == target.root_run_id for r in state.runs)
            ):
                raise ResponseError("target_unknown")
            if (
                len(state.incidents) >= 1000
                or sum(i.phase != "settled" for i in state.incidents) >= 16
            ):
                raise ResponseError("response_capacity")
            incident_id = uuid4()
            item = Incident(
                incident_id=incident_id,
                source=alias,
                event_id=signal.event_id,
                source_at=signal.occurred_at,
                payload_digest=digest,
                policy_digest=state.policy_digest,
                target=target,
                generation=state.generation + (target.kind == "definition"),
                actions=(ResponseAction(kind="cancel_local", target_id=incident_id),),
            )
            holds = state.holds
            roots = state.root_holds
            generation = state.generation
            if target.kind == "root_run":
                roots = tuple(set((*roots, target.root_run_id)))
            else:
                generation += 1
                old = holds[0].incident_ids if holds else ()
                holds = (
                    DefinitionHold(
                        workload_definition=policy.workload_definition,
                        generation=generation,
                        incident_ids=(*old, item.incident_id),
                    ),
                )
            from .providers.planner import build

            planned = build(
                state,
                item,
                rule_alias=rule_alias,
                mode=native.provenance if native else "local_only",
                reason=signal.reason,
                source_clock_bound_seconds=native.clock_bound_seconds if native else None,
            )
            self.store.commit(
                fd,
                state,
                **planned,
                incidents=(*state.incidents, item),
                holds=holds,
                root_holds=roots,
                generation=generation,
            )
        if self.cancel:
            started = time.monotonic()
            for run in self.store.read().runs:
                if item.matches(run) and run.state == "active":
                    self.cancel(run.root_run_id)
            self.change(item.incident_id, cancel_ms=elapsed_ms(started))
        return self.get(item.incident_id), True

    def get(self, incident_id):
        """Read one retained incident; no action is triggered by inspection."""
        item = next((i for i in self.store.read().incidents if i.incident_id == incident_id), None)
        if item is None:
            raise ResponseError("target_unknown")
        return item

    def change(self, incident_id, *, expected_revision=None, **changes):
        """Compare current immutable identity and atomically update only lifecycle fields."""
        allowed = {"phase", "reason_code", "actions", "cancel_ms", "cleanup_ms", "worker_ms"}
        if set(changes) - allowed:
            raise ResponseError()
        with self.store.transaction() as (fd, state):
            item = next((i for i in state.incidents if i.incident_id == incident_id), None)
            if item is None:
                raise ResponseError("target_unknown")
            if expected_revision is not None and item.revision != expected_revision:
                raise ResponseError("revision_conflict")
            if "actions" in changes:
                replacements = {a.action_id: a for a in changes["actions"]}
                if any(
                    a.action_id not in replacements
                    or a.status == "confirmed"
                    and replacements[a.action_id] != a
                    for a in item.actions
                ):
                    raise ResponseError("revision_conflict")
            updated = Incident.model_validate(
                item.model_dump() | changes | {"revision": item.revision + 1}
            )
            self.store.commit(
                fd,
                state,
                incidents=tuple(
                    updated if i.incident_id == incident_id else i for i in state.incidents
                ),
            )
            return updated

    def action(self, incident_id, action_id, status, reason="contained"):
        """Persist a result without mutating a confirmed action or its exact target."""
        item = self.get(incident_id)
        if not any(a.action_id == action_id for a in item.actions):
            raise ResponseError("target_unknown")
        actions = []
        for action in item.actions:
            if action.action_id == action_id:
                if action.status == "confirmed":
                    return item
                action = ResponseAction.model_validate(
                    action.model_dump()
                    | {
                        "status": status,
                        "reason_code": reason,
                        "completed_at": now()
                        if status in ("confirmed", "denied", "failed", "uncertain")
                        else None,
                    }
                )
            actions.append(action)
        return self.change(incident_id, expected_revision=item.revision, actions=tuple(actions))

    def normalize(self):
        """Mark old submitted work uncertain; never start network work during recovery."""
        for item in self.store.read().incidents:
            for action in item.actions:
                if action.status == "submitted":
                    self.action(
                        item.incident_id,
                        action.action_id,
                        "uncertain",
                        "cleanup_uncertain" if action.kind == "revoke_exact" else "owner_draining",
                    )

    def _owned_runs(self, item):
        """Resolve incident scope only through the trusted root registry."""
        return tuple(r for r in self.store.read().runs if item.matches(r))

    def _drained(self, item):
        """A free lifetime lock includes subprocess drain, not merely parent process death."""
        return all(not self.store.busy(r.root_run_id) for r in self._owned_runs(item))

    def _terminalize(self, item):
        """Normalize abandoned roots only after acquiring proof that every owner exited."""
        for run in self._owned_runs(item):
            if run.state == "active" and not self.store.busy(run.root_run_id):
                self.store.finish(run)

    def _reconcile_locked(self, incident_id, recovery):
        """Join exact receipts under effect ownership; no provider request or scheduling."""
        item = self.get(incident_id)
        self._terminalize(item)
        if not self._drained(item):
            return self.change(incident_id, phase="partial", reason_code="owner_draining")
        cancel = next(a for a in item.actions if a.kind == "cancel_local")
        self.action(incident_id, cancel.action_id, "confirmed")
        if recovery is None:
            return self.change(incident_id, phase="settled", reason_code="contained")
        attempts = {a.incident_id: a for a in recovery.attempts}
        selected = [
            a
            for a in recovery.attempts
            if a.ownership.kind == "bound"
            and item.matches(a.ownership)
            and (a.state != "resolved" or a.updated_at >= item.contained_at)
        ]
        item = self.get(incident_id)
        actions = list(item.actions)
        for attempt in selected:
            action = next(
                (
                    a
                    for a in actions
                    if a.kind == "revoke_exact" and a.target_id == attempt.incident_id
                ),
                None,
            )
            if action is None:
                action = ResponseAction(kind="revoke_exact", target_id=attempt.incident_id)
                actions.append(action)
        if tuple(actions) != item.actions:
            item = self.change(incident_id, actions=tuple(actions))
        for action in item.actions:
            if action.kind != "revoke_exact" or action.status == "confirmed":
                continue
            attempt = attempts.get(action.target_id)
            if attempt is not None and attempt.state == "resolved" and attempt.receipt is not None:
                self.action(incident_id, action.action_id, "confirmed")
            elif attempt is None:
                self.action(incident_id, action.action_id, "uncertain", "cleanup_uncertain")
        legacy = any(
            a.state != "resolved" and a.ownership.kind == "legacy_unattributed"
            for a in recovery.attempts
        )
        unknown = any(a.state != "resolved" and not a.lease_handle for a in selected)
        item = self.get(incident_id)
        complete = all(a.status == "confirmed" for a in item.actions) and not legacy and not unknown
        reason = (
            "legacy_unattributed"
            if legacy
            else "acquisition_uncertain"
            if unknown
            else (
                next((a.reason_code for a in item.actions if a.status != "confirmed"), "contained")
            )
        )
        return self.change(
            incident_id, phase="settled" if complete else "partial", reason_code=reason
        )

    def _reconcile_local(self, incident_id):
        """Explicit no-network reconciliation; configured state must remain available."""
        mode = self.store.anchor().recovery_mode
        try:
            with self.store.recovery.effect() if mode == "configured" else nullcontext():
                recovery = self.store.recovery.read() if mode == "configured" else None
                return self._reconcile_locked(incident_id, recovery)
        except RecoveryError as error:
            raise ResponseError(
                "response_busy" if str(error) == "recovery_busy" else "response_storage_error"
            ) from None

    async def _process_local(self, incident_id):
        """One bounded attempt to drain and complete never-submitted exact cleanup."""
        start = time.monotonic()
        deadline = start + self.work_budget
        self.change(incident_id, phase="responding")
        try:
            while not self._drained(self.get(incident_id)):
                if time.monotonic() >= deadline:
                    return self.change(incident_id, phase="partial", reason_code="owner_draining")
                await asyncio.sleep(0.05)
            mode = self.store.anchor().recovery_mode
            while True:
                try:
                    context = (
                        self.store.recovery.effect() if mode == "configured" else nullcontext()
                    )
                    context.__enter__()
                    break
                except RecoveryError as error:
                    if str(error) != "recovery_busy":
                        raise
                    if time.monotonic() >= deadline:
                        return self.change(
                            incident_id, phase="partial", reason_code="owner_draining"
                        )
                    await asyncio.sleep(0.05)
            try:
                recovery = self.store.recovery.normalize_owned() if mode == "configured" else None
                item = self._reconcile_locked(incident_id, recovery)
                if recovery is None:
                    return item
                policy = self.store.policy()
                for action in item.actions:
                    if action.kind != "revoke_exact" or action.status != "planned":
                        continue
                    attempt = next(
                        (
                            a
                            for a in self.store.recovery.read().attempts
                            if a.incident_id == action.target_id
                        ),
                        None,
                    )
                    if attempt is None or not attempt.lease_handle:
                        self.action(
                            incident_id, action.action_id, "uncertain", "acquisition_uncertain"
                        )
                        continue
                    prior = any(
                        a.kind == "revoke_exact"
                        and a.target_id == action.target_id
                        and a.action_id != action.action_id
                        and a.status != "planned"
                        for i in self.store.read().incidents
                        for a in i.actions
                    )
                    if prior:
                        self.action(incident_id, action.action_id, "uncertain", "cleanup_uncertain")
                        continue
                    if not policy.automatic_cleanup or not self.store.settings.vault_token:
                        self.action(incident_id, action.action_id, "denied", "cleanup_denied")
                        continue
                    if deadline - time.monotonic() < 10:
                        break
                    self.action(incident_id, action.action_id, "submitted")
                    cleanup_start = time.monotonic()
                    try:
                        from agent.recovery.commands import revoke_exact

                        await revoke_exact(self.store.recovery, attempt, transport=self.transport)
                    except asyncio.CancelledError:
                        self.action(incident_id, action.action_id, "uncertain", "cleanup_uncertain")
                        raise
                    except Exception as error:
                        denied = str(error) == "recovery_access_denied"
                        self.action(
                            incident_id,
                            action.action_id,
                            "denied" if denied else "uncertain",
                            "cleanup_denied" if denied else "cleanup_uncertain",
                        )
                    else:
                        self.action(incident_id, action.action_id, "confirmed")
                    self.change(incident_id, cleanup_ms=elapsed_ms(cleanup_start))
                return self._reconcile_locked(incident_id, self.store.recovery.read())
            finally:
                context.__exit__(None, None, None)
        except asyncio.CancelledError:
            raise
        except Exception:
            return self.change(incident_id, phase="partial", reason_code="cleanup_uncertain")
        finally:
            self.change(incident_id, worker_ms=elapsed_ms(start))

    def reconcile(self, incident_id):
        """Join local cleanup receipts and independent provider proof without network."""
        self._reconcile_local(incident_id)
        self.provider_phase(incident_id)
        return self.get(incident_id)

    async def process(self, incident_id):
        """Run local cleanup first, then the native plan within one shared 120s budget."""
        started = time.monotonic()
        local = await self._process_local(incident_id)
        state = self.store.read()
        if getattr(state, "enrollment", None) and local.actions[0].status == "confirmed":
            from .providers.worker import Worker

            worker = Worker(
                self.store,
                transport=self.transport,
                budget=max(0, 120 - (time.monotonic() - started)),
                telemetry=self.telemetry,
            )
            await worker.process(incident_id)
            self.provider_phase(incident_id)
        return self.get(incident_id)

    def provider_phase(self, incident_id):
        """Prevent local settlement from concealing required external work or missing proof."""
        from .providers.worker import plan_actions

        state = self.store.read()
        if state.schema_version != 2:
            return
        actions = plan_actions(state, incident_id)
        from .providers.proof import complete as proven

        plan = next((p for p in state.provider_plans if p.incident_id == incident_id), None)
        unknown_native = any(
            a.state in {"intent", "submitted", "uncertain"}
            and self.get(incident_id).matches(a.ownership)
            for a in state.native_acquisitions
        )
        complete = (
            not unknown_native
            and not (plan and plan.missing_controls)
            and all(proven(a) for a in actions if a.required)
        )
        if not complete:
            self.change(incident_id, phase="partial", reason_code="proof_required")

    def release(self, definition, incident_ids, revision, operator):
        """Atomically release only current local definition holds after proven cleanup/drain."""
        mode = self.store.anchor().recovery_mode
        try:
            with self.store.recovery.effect() if mode == "configured" else nullcontext():
                recovery = self.store.recovery.read() if mode == "configured" else None
                with self.store.transaction() as (fd, state):
                    if state.revision != revision:
                        raise ResponseError("revision_conflict")
                    hold = state.holds[0] if state.holds else None
                    if (
                        not hold
                        or hold.workload_definition != definition
                        or set(hold.incident_ids) != set(incident_ids)
                        or len(incident_ids) != len(set(incident_ids))
                    ):
                        raise ResponseError("release_unsafe")
                    items = [i for i in state.incidents if i.incident_id in hold.incident_ids]
                    if any(
                        i.phase != "settled" or any(a.status != "confirmed" for a in i.actions)
                        for i in items
                    ):
                        raise ResponseError("release_unsafe")
                    if (
                        any(self.store.busy(r.root_run_id) for r in state.runs)
                        or recovery is not None
                        and any(a.state != "resolved" for a in recovery.attempts)
                    ):
                        raise ResponseError("release_unsafe")
                    if state.schema_version == 2 and state.enrollment is not None:
                        # Until all independent provider proofs are resolved, local release
                        # must not make new roots eligible after a native response.
                        from .providers.proof import release_safe

                        if not release_safe(state, set(incident_ids)):
                            raise ResponseError("release_unsafe")
                    record = ReleaseRecord(
                        workload_definition=definition,
                        incident_ids=tuple(incident_ids),
                        expected_revision=revision,
                        new_generation=state.generation + 1,
                        operator=operator,
                    )
                    self.store.commit(
                        fd,
                        state,
                        holds=(),
                        **(
                            {
                                "subject_holds": tuple(
                                    h
                                    for h in state.subject_holds
                                    if h.incident_id not in incident_ids
                                )
                            }
                            if state.schema_version == 2
                            else {}
                        ),
                        generation=state.generation + 1,
                        releases=(*state.releases, record),
                    )
                    return record
        except RecoveryError as error:
            raise ResponseError(
                "response_busy" if str(error) == "recovery_busy" else "response_storage_error"
            ) from None
