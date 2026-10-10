"""One bounded provider attempt with durable intent and no automatic mutation replay.

Effect ownership outlives production children. Control transactions never wait on
network/drain. Every dispatch rechecks pinned enrollment and exact immutable resource.
"""

import asyncio
import json
import sys
import time
from datetime import timedelta

import httpx
from pydantic import SecretStr

from agent.recovery.models import now
from agent.recovery.store import RecoveryError
from agent.recovery.workers import descriptor_scope, network_process
from agent.response.models import ResponseError
from agent.settings import Settings
from agent.validation.models import implementation_revision
from agent.validation.store import decode_json

from .common import Result, Router
from .enrollment import digest, read_secrets
from .models import Observation, ProviderAction, require

SETTINGS = (
    "vault_addr",
    "vault_namespace",
    "vault_token",
    "verify_tenant_url",
    "verify_api_client_id",
    "verify_api_client_secret",
    "oauth_provider",
    "oauth_issuer",
    "oauth_discovery_url",
    "oauth_token_endpoint",
    "oauth_auth_method",
)


def provider_settings(settings):
    """Serialize only needed authority into the private pipe, never flags or worker output."""
    return {
        key: value.get_secret_value() if isinstance(value, SecretStr) else value
        for key in SETTINGS
        for value in (getattr(settings, key),)
    }


def get_action(state, action_id):
    """Resolve one exact retained action; missing records are never treated as completed."""
    item = next((a for a in state.provider_actions if a.action_id == action_id), None)
    require(item is not None, "target_unknown")
    return item


def change(store, action_id, **changes):
    """Update lifecycle fields under a fresh transaction while preserving exact authority."""
    require(
        not set(changes)
        - {"state", "reason", "submitted_at", "completed_at", "observations", "attempt_ms"},
        "provider_policy_changed",
    )
    with store.transaction() as (fd, state):
        action = get_action(state, action_id)
        updated = ProviderAction.model_validate(action.model_dump() | changes)
        store.commit(
            fd,
            state,
            provider_actions=tuple(
                updated if a.action_id == action_id else a for a in state.provider_actions
            ),
        )
        return updated


def plan_actions(state, incident_id):
    """Resolve references from a durable immutable plan, not caller-supplied resource IDs."""
    plan = next((p for p in state.provider_plans if p.incident_id == incident_id), None)
    return tuple(get_action(state, action_id) for action_id in plan.action_ids) if plan else ()


class Worker:
    """Serialize native effects using the installation's existing effect owner."""

    def __init__(self, store, *, transport=None, budget=120, telemetry=None):
        """Fixtures can inject HTTP; live dispatch always uses isolated bounded children."""
        self.store, self.transport, self.budget = store, transport, budget
        self.telemetry = telemetry

    def normalize(self):
        """Normalize only after proving that no effect owner can still finish a submission."""
        mode = self.store.anchor().recovery_mode
        try:
            with self.store.recovery.effect() if mode == "configured" else self.store.effect():
                self._normalize_owned()
        except RecoveryError:
            raise ResponseError("provider_busy") from None

    def _normalize_owned(self):
        """Recover abandoned submitted records as uncertain without any provider request."""
        with self.store.transaction() as (fd, state):
            if state.schema_version != 2:
                return
            actions = tuple(
                ProviderAction.model_validate(
                    a.model_dump() | {"state": "uncertain", "reason": "provider_uncertain"}
                )
                if a.state == "submitted"
                else a
                for a in state.provider_actions
            )
            native = tuple(
                type(a).model_validate(a.model_dump() | {"state": "uncertain"})
                if a.state == "submitted"
                else a
                for a in state.native_acquisitions
            )
            probes = tuple(
                type(a).model_validate(a.model_dump() | {"state": "uncertain"})
                if a.state == "submitted"
                else a
                for a in state.probe_acquisitions
            )
            if (actions, native, probes) != (
                state.provider_actions,
                state.native_acquisitions,
                state.probe_acquisitions,
            ):
                self.store.commit(
                    fd,
                    state,
                    provider_actions=actions,
                    native_acquisitions=native,
                    probe_acquisitions=probes,
                )

    async def dispatch(self, action, *, read_only=False):
        """Execute exactly one action; secrets and native responses cannot escape the adapter."""
        values = read_secrets(self.store) if action.binding.secret_alias else {}
        secrets = (
            {action.binding.secret_alias: values[action.binding.secret_alias]}
            if action.binding.secret_alias in values
            else {}
        )
        if action.binding.secret_alias:
            import hashlib

            secret = secrets.get(action.binding.secret_alias)
            require(
                secret is not None
                and action.binding.secret_digest
                == hashlib.sha256(secret.get_secret_value().encode()).hexdigest(),
                "provider_policy_changed",
            )
        if self.transport is not None:
            async with httpx.AsyncClient(
                transport=self.transport, timeout=10, trust_env=False, follow_redirects=False
            ) as http:
                return await Router(self.store.settings, http, secrets).execute(
                    action, read_only=read_only
                )
        payload = {
            "action": action.model_dump(mode="json"),
            "read_only": read_only,
            "settings": provider_settings(self.store.settings),
            "secrets": {k: v.get_secret_value() for k, v in secrets.items()},
        }
        async with network_process(__name__) as process:
            output, _ = await process.communicate(json.dumps(payload).encode())
            require(process.returncode == 0 and len(output) <= 8192, "provider_uncertain")
            try:
                return Result.model_validate(decode_json(output))
            except Exception:
                raise ResponseError("provider_uncertain") from None

    def observe(self, action, result):
        """Persist only an independent typed readback, never promote acknowledgment to denial."""
        if result.path is None:
            return action
        state = self.store.read()
        observation = Observation(
            installation_id=state.installation_id,
            environment_digest=state.environment_digest,
            implementation_digest=implementation_revision(),
            enrollment_digest=action.enrollment_digest,
            incident_id=action.incidents[0],
            action_id=action.action_id,
            binding_id=action.binding.binding_id,
            resource_generation=action.binding.generation,
            path=result.path,
            result=result.proof,
            source="synthetic" if self.transport is not None else "provider_readback",
            source_digest=result.source_digest,
        )
        return change(
            self.store, action.action_id, observations=(*action.observations, observation)
        )

    async def process(self, incident_id):
        """Finish only unsubmitted work in one overall budget, preserving every uncertain effect."""
        deadline = time.monotonic() + self.budget
        mode = self.store.anchor().recovery_mode
        incident = next(i for i in self.store.read().incidents if i.incident_id == incident_id)
        # Owners drain without control/effect locks so ordinary cleanup can complete.
        while any(
            incident.matches(r) and self.store.busy(r.root_run_id) for r in self.store.read().runs
        ):
            if time.monotonic() >= deadline:
                return
            await asyncio.sleep(0.05)
        while True:
            try:
                context = (
                    self.store.recovery.effect() if mode == "configured" else self.store.effect()
                )
                owner = context.__enter__()
                break
            except RecoveryError as error:
                if str(error) != "recovery_busy":
                    raise ResponseError() from None
                if time.monotonic() >= deadline:
                    return
                await asyncio.sleep(0.05)
        try:
            with descriptor_scope(owner.fd):
                for selected in plan_actions(self.store.read(), incident_id):
                    if deadline - time.monotonic() < 10:
                        break
                    with self.store.transaction() as (fd, state):
                        action = get_action(state, selected.action_id)
                        if action.state != "planned":
                            continue
                        require(
                            state.enrollment is not None
                            and digest(state.enrollment) == action.enrollment_digest,
                            "provider_policy_changed",
                        )
                        if not action.binding.enabled or action.binding.capability != "supported":
                            updated = ProviderAction.model_validate(
                                action.model_dump()
                                | {
                                    "state": "denied",
                                    "reason": "missing_authority",
                                    "completed_at": now(),
                                }
                            )
                        elif any(not dependency_ready(state, dep) for dep in action.dependencies):
                            continue
                        else:
                            updated = ProviderAction.model_validate(
                                action.model_dump() | {"state": "submitted", "submitted_at": now()}
                            )
                        self.store.commit(
                            fd,
                            state,
                            provider_actions=tuple(
                                updated if a.action_id == action.action_id else a
                                for a in state.provider_actions
                            ),
                        )
                    if updated.state != "submitted":
                        continue
                    attempt_start = time.monotonic()
                    try:
                        async with asyncio.timeout(min(10, deadline - time.monotonic())):
                            result = await self.dispatch(updated)
                        completed = change(
                            self.store,
                            updated.action_id,
                            state=result.state,
                            reason=result.reason,
                            completed_at=now(),
                            attempt_ms=max(0, int((time.monotonic() - attempt_start) * 1000)),
                        )
                        if result.path:
                            self.observe(completed, result)
                        from agent.observability import provider_action

                        provider_action(
                            self.telemetry, completed.kind, completed.state, result.proof
                        )
                    except asyncio.CancelledError:
                        change(
                            self.store,
                            updated.action_id,
                            state="uncertain",
                            reason="provider_uncertain",
                        )
                        raise
                    except Exception:
                        change(
                            self.store,
                            updated.action_id,
                            state="uncertain",
                            reason="provider_uncertain",
                        )
        finally:
            context.__exit__(None, None, None)

    async def reconcile(self, incident_id, revision):
        """Read current provider state once/action; never credentials, mutation or notice resend."""
        deadline = time.monotonic() + self.budget
        state = self.store.read()
        require(state.revision == revision, "revision_conflict")
        mode = self.store.anchor().recovery_mode
        with self.store.recovery.effect() if mode == "configured" else self.store.effect() as owner:
            with descriptor_scope(owner.fd):
                from .proof import expire_known_probe_jwts

                expire_known_probe_jwts(self.store)
                state = self.store.read()
                for action in plan_actions(state, incident_id):
                    if deadline - time.monotonic() < 10:
                        break
                    if action.kind in {"notify_teams", "rotate_static"}:
                        continue
                    try:
                        async with asyncio.timeout(10):
                            result = await self.dispatch(action, read_only=True)
                        current = get_action(self.store.read(), action.action_id)
                        observed = self.observe(current, result)
                        if result.proof == "proven":
                            change(
                                self.store,
                                observed.action_id,
                                state="reconciled",
                                reason="provider_reconciled",
                            )
                    except Exception:
                        # Readback failure leaves the prior effect history and holds intact.
                        continue


async def child():
    """Read private stdin once and emit only the bounded safe result of a compiled adapter."""
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "provider_capacity")
        data = decode_json(raw)
        settings = Settings(_env_file=None, **data["settings"])
        action = ProviderAction.model_validate(data["action"])
        secrets = {k: SecretStr(v) for k, v in data["secrets"].items()}
        async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as http:
            result = await Router(settings, http, secrets).execute(
                action, read_only=data["read_only"]
            )
    except Exception:
        result = Result(state="uncertain", reason="provider_uncertain")
    sys.stdout.write(result.model_dump_json())


if __name__ == "__main__":
    asyncio.run(child())


def dependency_ready(state, action_id):
    """Follow explicit reviewed successors; a failed predecessor is never replayed.

    The journal rejects cycles and branching retry lineage. Only the latest attempt
    can satisfy a dependent action; metadata acknowledgment remains separate proof.
    """
    action = get_action(state, action_id)
    successors = {a.predecessor: a for a in state.provider_actions if a.predecessor}
    while action.action_id in successors:
        action = successors[action.action_id]
    return action.state in {"acknowledged", "reconciled"}


def retry(store, action_id, revision, operator, *, _owned=False):
    """Create one linked reviewed attempt under exact current holds and resource generation.

    Uncertainty needs fresh independent evidence of non-application; session revocation
    always needs an explicit native review because retry could affect newer sessions.
    A resend remains a new notice revision. This function never dispatches the effect.
    """
    from uuid import uuid4

    from .models import RecoveryDecision

    mode = store.anchor().recovery_mode
    from contextlib import nullcontext

    context = (
        nullcontext()
        if _owned
        else (store.recovery.effect() if mode == "configured" else store.effect())
    )
    with context:
        with store.transaction() as (fd, state):
            require(state.revision == revision, "revision_conflict")
            action = get_action(state, action_id)
            require(
                state.enrollment is not None
                and digest(state.enrollment) == action.enrollment_digest,
                "provider_policy_changed",
            )
            require(
                action.state in {"failed", "denied", "uncertain", "acknowledged"},
                "provider_retry_review",
            )
            held = {i for h in state.holds for i in h.incident_ids}
            held.update(
                i.incident_id
                for i in state.incidents
                if i.target.kind == "root_run" and i.target.root_run_id in state.root_holds
            )
            require(set(action.incidents) <= held, "release_unsafe")
            require(
                not any(a.predecessor == action_id for a in state.provider_actions),
                "provider_retry_review",
            )
            reviewed = [
                o
                for o in action.observations
                if o.source == "native_evidence"
                and o.reviewer
                and o.reviewed_at
                and now() - o.reviewed_at <= timedelta(seconds=300)
            ]
            if action.state == "uncertain" or action.kind == "revoke_user_sessions":
                require(
                    any(
                        o.result == "disproven"
                        and o.path
                        in {
                            "registration",
                            "native_token",
                            "tenant_user",
                            "tenant_sessions",
                            "static_session",
                            "notification",
                        }
                        for o in reviewed
                    ),
                    "provider_retry_review",
                )
            if action.kind == "rotate_static":
                # Scheduled or uncertain rotation cannot be attributed by current metadata.
                require(action.state == "denied", "provider_retry_review")
            new = ProviderAction(
                kind=action.kind,
                scope=action.scope,
                binding=action.binding,
                enrollment_digest=action.enrollment_digest,
                required=action.required,
                incidents=action.incidents,
                dependencies=action.dependencies,
                predecessor=action.action_id,
                notice_id=uuid4() if action.kind == "notify_teams" else None,
                notice_revision=action.notice_revision + 1 if action.kind == "notify_teams" else 1,
            )
            decision = RecoveryDecision(
                operator=operator,
                expected_revision=revision,
                enrollment_digest=action.enrollment_digest,
                incident_ids=tuple(sorted(held, key=str)),
                predecessor=action.action_id,
                successor=new.action_id,
                decision="resend" if action.kind == "notify_teams" else "retry",
            )
            plans = tuple(
                type(p).model_validate(
                    p.model_dump()
                    | {
                        "action_ids": tuple(
                            new.action_id if ref == action_id else ref for ref in p.action_ids
                        )
                    }
                )
                if action_id in p.action_ids
                else p
                for p in state.provider_plans
            )
            store.commit(
                fd,
                state,
                provider_actions=(*state.provider_actions, new),
                provider_plans=plans,
                provider_decisions=(*state.provider_decisions, decision),
            )
            return new


async def reviewed_retry(store, action_id, revision, operator, *, transport=None):
    """Read exact current metadata before deciding whether an explicitly reviewed retry is safe.

    Keep effect ownership across readback and decision, but never hold the control lock
    during network I/O. Concurrent intake changes the revision and cancels this decision.
    Rotation and notice adapters cannot safely infer non-application from metadata.
    """
    mode = store.anchor().recovery_mode
    context = store.recovery.effect() if mode == "configured" else store.effect()
    with context as owner, descriptor_scope(owner.fd):
        state = store.read()
        require(state.revision == revision, "revision_conflict")
        action = get_action(state, action_id)
        if action.kind not in {"rotate_static", "notify_teams"}:
            worker = Worker(store, transport=transport)
            try:
                async with asyncio.timeout(10):
                    result = await worker.dispatch(action, read_only=True)
            except Exception:
                raise ResponseError("provider_retry_review") from None
            require(store.read().revision == revision, "revision_conflict")
            # Metadata confirmation is enough to avoid another mutation, but never
            # replaces the independent credential-loss proof required for release.
            if result.proof == "proven":
                worker.observe(action, result)
                change(store, action_id, state="reconciled", reason="provider_reconciled")
                return get_action(store.read(), action_id)
            require(
                result.reason not in {"provider_uncertain", "provider_denied"},
                "provider_retry_review",
            )
        return retry(store, action_id, revision, operator, _owned=True)
