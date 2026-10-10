"""Single-owner browser jobs, safe approval retry, and cleanup quarantine.

Submission UUIDs make uncertain HTTP delivery idempotent. Jobs belong to one session;
private identity and approval snapshots never become response fields. Unresolved
credential cleanup blocks further admission for this process.
"""

import asyncio
from dataclasses import dataclass, field, replace
from uuid import uuid4

from agent.broker import DatabaseBroker
from agent.observability import NullSink
from agent.schemas import Action, RequestEnvelope
from agent.security import SecurityError
from agent.services import VerifyApprovalBackend
from agent.workspace.models import JobView, WorkflowError, now


@dataclass(repr=False)
class Candidate:
    action: bytes
    issuer: str
    subject: str
    profile: str
    approval_id: object
    child: object = None


@dataclass(repr=False)
class Job:
    view: JobView
    request: RequestEnvelope
    context: object
    session: object
    snapshot: object = None
    events: list = field(default_factory=list)
    candidates: list = field(default_factory=list)
    writes: int = 0
    acquired: int = 0
    revoked: int = 0
    reads: int = 0
    uncertain: bool = False
    stopped: bool = False
    worker: object = None
    effect_context: object = None
    effect_owner: object = None
    incidents: set = field(default_factory=set)
    current_incident: object = None


class MemorySink:
    def __init__(self, manager, job):
        """Initialize bounded in-memory lifecycle counts and private approval candidates
        for one job.
        """
        self.manager, self.job = manager, job

    def emit(self, event):
        """Project typed lifecycle events into the public job state and bounded counters."""
        job = self.job
        job.events.append(event)
        del job.events[:-1000]
        if event.phase == "database" and event.detail == "completed":
            job.reads += 1
        if event.phase == "cleanup" and event.detail in {"attempted", "started"}:
            job.view.state = "cleaning_up"
        if event.phase == "credential" and event.detail == "acquired":
            job.acquired += 1
            job.view.cleanup_status = "pending"
        if event.phase == "cleanup" and event.detail == "revoked":
            job.revoked += 1
            # This event now follows durable closure. Drop completed quarantine refs
            # before retention can prune their receipts; keep session history separate.
            self.manager.recovery_incidents.discard(job.current_incident)
            job.view.cleanup_status = "revoked" if job.revoked == job.acquired else "pending"

    def fact(self, name, **private):
        """Consume trusted private approval and credential facts without exposing their
        native fields.

        Preserve uncertainty and exact-action retry candidates for the manager’s checks.
        """
        job = self.job
        if name == "recovery_incident":
            job.current_incident = private["incident_id"]
            job.incidents.add(private["incident_id"])
            self.manager.recovery_incidents.add(private["incident_id"])
        elif name == "approval_started":
            approval, action, principal = (
                private["approval"],
                private["action"],
                private["principal"],
            )
            job.candidates.append(
                Candidate(
                    action.model_dump_json().encode(),
                    principal.issuer,
                    principal.subject,
                    private["profile"],
                    approval.id,
                )
            )
            job.view.approval_status = "pending"
            job.view.action_summary = "Simulated restart of sandbox/demo"
            job.view.state = "waiting_for_approval"
        elif name == "approval_decision":
            job.view.approval_status = private["decision"]
            job.view.state = "running"
        elif name == "simulated_write":
            job.writes += 1
        elif name == "cleanup_unknown":
            job.view.cleanup_status = "unknown"
            job.view.state = "cleaning_up"
            job.uncertain = True
            self.manager.quarantined = True
        elif name == "cleanup_pending":
            job.view.state = "cleaning_up"
        elif name == "cleanup_failed":
            if job.view.cleanup_status != "unknown":
                job.view.cleanup_status = "failed"
            job.uncertain = True
        elif name == "credential_uncertain":
            job.view.cleanup_status = "unknown"
            job.uncertain = True
            self.manager.quarantined = True

    def bind(self, binding):
        # No private bindings are retained by the browser workspace.
        """Discard native source bindings; browser jobs do not provide durable validation
        evidence.
        """
        pass


class RunsManager:
    def __init__(
        self,
        runtime,
        auth,
        store,
        *,
        database_reader_factory=None,
        approval_backend=None,
        recovery_store=None,
    ):
        """Bind the runtime, auth/session managers, trusted factories, and single-owner
        state.
        """
        self.runtime, self.auth, self.store = runtime, auth, store
        self.database_reader_factory = database_reader_factory
        self.backend = approval_backend
        from agent.recovery.store import RecoveryStore

        self.recovery = recovery_store or RecoveryStore(runtime.settings)
        self.owner = None
        self.quarantined = False
        self.recovery_incidents = set()
        self.last_failure = None
        self.worker = None
        store.on_close = self.close_session

    @property
    def busy(self):
        """Report active ownership or unresolved cleanup quarantine, both of which block
        admission.
        """
        return self.owner is not None or self.quarantined

    def check_recovery(self):
        """Clear volatile quarantine only when every owned incident has durable closure.

        No job, session, approval, or credentials are modified. Unknown legacy cleanup
        without incident linkage stays quarantined; storage failure never clears it.
        """
        if self.owner is not None or not self.quarantined:
            return
        incidents = self.recovery_incidents
        if not incidents:
            return
        try:
            with self.recovery.effect():
                journal = self.recovery.read()
                terminal = {a.incident_id for a in journal.attempts if a.state == "resolved"}
                if incidents <= terminal and all(a.state == "resolved" for a in journal.attempts):
                    self.quarantined = False
                    self.recovery_incidents.clear()
        except SecurityError:
            return

    def get(self, session, job_id):
        """Return a job only if it belongs to the requesting session."""
        job = session.jobs.get(job_id)
        if not job:
            raise SecurityError("run_not_found")
        return job

    def _duplicate(self, session, key, payload):
        """Return the prior job for an identical submission, rejecting changed payload
        under the same UUID.
        """
        previous = session.submissions.get(key)
        if previous:
            old, job = previous
            if old != payload:
                raise SecurityError("submission_conflict")
            return job

    def _capacity(self, session):
        """Reject a session that has reached its bounded job/submission storage capacity."""
        if len(session.jobs) >= 20 or len(session.submissions) >= 20:
            raise SecurityError("capacity_exceeded")

    async def submit(self, session, value):
        """Deduplicate and reserve a task before asynchronous identity admission."""
        payload = ("task", value.task, value.profile)
        duplicate = self._duplicate(session, value.submission_id, payload)
        if duplicate:
            return duplicate
        self._capacity(session)
        if value.profile not in self.runtime.definitions:
            raise SecurityError("profile_unavailable")
        return await self._start(
            session,
            value.submission_id,
            payload,
            RequestEnvelope(task=value.task, profile=value.profile),
        )

    async def retry(self, session, parent_id, value):
        """Admit a fresh approval for one safe, unconfirmed exact action.

        Reject replay after writes, ambiguous candidates, unresolved cleanup, or changed
        identity. Do not rerun the original model or its earlier tools.
        """
        parent = self.get(session, parent_id)
        payload = ("retry", parent_id)
        duplicate = self._duplicate(session, value.submission_id, payload)
        if duplicate:
            return duplicate
        if len(session.submissions) >= 20:
            raise SecurityError("capacity_exceeded")
        if len(parent.candidates) == 1 and parent.candidates[0].child:
            child = parent.candidates[0].child
            session.submissions[value.submission_id] = (payload, child)
            return child
        if (
            not self.project_job(parent).retry_available
            or len(parent.candidates) != 1
            or parent.writes
            or parent.uncertain
            or parent.stopped
            or parent.view.cleanup_status not in {"not_acquired", "revoked"}
            or parent.acquired != parent.revoked
        ):
            raise SecurityError("retry_unavailable")
        self._capacity(session)
        candidate = parent.candidates[0]
        return await self._start(
            session,
            value.submission_id,
            payload,
            RequestEnvelope(task="Retry confirmed action", profile=candidate.profile),
            parent=parent,
            candidate=candidate,
        )

    async def _start(self, session, key, payload, request, *, parent=None, candidate=None):
        """Reserve job, submission key, and runtime ID before awaiting credentials.

        Single ownership prevents concurrent effects; failed admission unwinds reserved
        state. A retry snapshot must still match current identity and policy.
        """
        self.check_recovery()
        if self.quarantined:
            raise SecurityError("workspace_unavailable")
        if self.owner is not None:
            raise SecurityError("workspace_busy")
        if session.state != "active":
            raise SecurityError("sign_in_required")
        context = self.runtime.reserve(request.request_id)
        job = Job(
            JobView(
                job_id=uuid4(),
                request_id=request.request_id,
                run_id=context.run_id,
                parent_job_id=parent.view.job_id if parent else None,
                kind="approval_retry" if parent else "task",
            ),
            request,
            context,
            session,
        )
        self.owner = job
        session.jobs[job.view.job_id] = job
        session.submissions[key] = (payload, job)
        try:
            from agent.recovery.store import RecoveryError, configured

            if (
                configured(self.runtime.settings)
                or self.recovery.root.exists()
                or self.recovery.root.is_symlink()
                or self.recovery.established
            ):
                if getattr(self.recovery, "workspace_required", False):
                    self.recovery.claim_workspace()
                job.effect_context = self.recovery.effect()
                job.effect_owner = job.effect_context.__enter__()
                state = self.recovery.read()
                blocked = [item for item in state.attempts if item.state != "resolved"]
                if blocked:
                    raise RecoveryError(blocked[0].reason_code)
            job.snapshot = await self.auth.admit(session)
            if session.state != "active" or job.stopped:
                raise SecurityError("sign_in_required")
            if candidate:
                principal = job.snapshot.principal
                if (principal.issuer, principal.subject) != (candidate.issuer, candidate.subject):
                    raise SecurityError("retry_unavailable")
                definition = self.runtime.definitions.get(candidate.profile)
                if not definition or "simulated-infrastructure" not in definition.capabilities:
                    raise SecurityError("retry_unavailable")
                self.runtime.policy.authorize(
                    principal, definition.policy_role, Action.model_validate_json(candidate.action)
                )
                candidate.child = job
                parent.view.retry_available = False
                self.runtime.approvals.invalidate(candidate.approval_id, "superseded")
            self.store.touch(session)
            job.worker = asyncio.create_task(self._execute(job, candidate))
            self.worker = job.worker
            return job
        except BaseException:
            session.jobs.pop(job.view.job_id, None)
            session.submissions.pop(key, None)
            self.runtime.forget(context.run_id)
            self.owner = None
            if job.effect_owner:
                job.effect_context.__exit__(None, None, None)
                job.effect_owner = None
            raise

    async def _execute(self, job, candidate):
        """Run the admitted task or exact retry and produce a bounded credential-free job
        view.

        Project precise approval outcomes, truncate results, and quarantine uncertain
        cleanup. Always invalidate pending approvals and release active ownership.
        """
        runtime = self.runtime
        sink = MemorySink(self, job)
        runtime.event_sink = sink

        async def unavailable(deps, approval, action):
            """Reject a phone request with a safe configuration error when approval is
            disabled.
            """
            raise SecurityError("approval_unavailable")

        runtime.approval_backend = self.backend or (
            VerifyApprovalBackend(runtime.settings)
            if runtime.settings.verify_push_enabled
            else unavailable
        )
        job.view.started_at = now()
        job.view.state = "running"
        try:
            if candidate:
                result = await runtime.run_action(
                    job.request,
                    job.snapshot.principal,
                    Action.model_validate_json(candidate.action),
                    run_context=job.context,
                )
            else:
                reader = (
                    self.database_reader_factory(job.snapshot, sink)
                    if self.database_reader_factory
                    else DatabaseBroker(
                        runtime.settings,
                        job.snapshot.access_token,
                        job.snapshot.principal.subject,
                        observer=lambda stage: self._stage(job, stage),
                        recovery_store=self.recovery,
                        effect_owner=job.effect_owner,
                    )
                )
                if isinstance(reader, DatabaseBroker):
                    reader = replace(
                        reader, recovery_store=self.recovery, effect_owner=job.effect_owner
                    )
                result = await runtime.run(
                    job.request,
                    job.snapshot.principal,
                    database_reader=reader,
                    run_context=job.context,
                )
            code = result.error_code
            if code == "storage_error":
                job.uncertain = True
                job.view.cleanup_status = "unknown"
                self.quarantined = True
            if job.stopped or code == "contained":
                job.view.state = "interrupted"
                code = "interrupted"
            elif (
                job.view.cleanup_status in {"unknown", "failed", "pending"}
                or job.acquired != job.revoked
            ):
                job.view.state = "failed"
                code = "cleanup_failed"
                if job.view.cleanup_status == "pending":
                    job.view.cleanup_status = "failed"
            elif job.view.approval_status == "unconfirmed":
                job.view.state = "failed"
                code = "approval_unconfirmed"
            elif job.view.approval_status == "denied":
                job.view.state = "denied"
                code = "approval_denied"
            elif (
                result.status == "completed"
                and "database-read" in runtime.definitions[job.request.profile].capabilities
                and not job.reads
            ):
                job.view.state = "failed"
                code = "task_failed"
            elif result.status == "completed":
                job.view.state = "completed"
                if job.view.approval_status == "pending":
                    job.view.state = "failed"
                    code = "approval_unconfirmed"
            else:
                job.view.state = "denied" if code == "policy_denied" else "failed"
            if result.output:
                summary = result.output.summary
                job.view.result = summary[:32000]
                job.view.truncated = len(summary) > 32000
            if code:
                job.view.error = WorkflowError.of(self._safe(code))
        except asyncio.CancelledError:
            job.view.state = "interrupted"
            job.view.error = WorkflowError.of("interrupted")
        except Exception:
            job.view.state = "failed"
            job.view.error = WorkflowError.of("task_failed")
        finally:
            runtime.approvals.invalidate_run(job.context.run_id)
            if job.view.approval_status == "pending":
                job.view.approval_status = "unconfirmed"
                if not job.stopped and job.view.error and job.view.error.code == "task_failed":
                    job.view.error = WorkflowError.of("approval_unconfirmed")
            job.view.finished_at = now()
            job.view.retry_available = (
                job.view.state == "failed"
                and job.view.error is not None
                and job.view.error.code == "approval_unconfirmed"
                and job.view.approval_status == "unconfirmed"
                and len(job.candidates) == 1
                and not job.writes
                and not job.uncertain
                and not job.stopped
                and job.view.cleanup_status in {"not_acquired", "revoked"}
                and job.acquired == job.revoked
            )
            job.snapshot = None
            runtime.event_sink = NullSink()
            runtime.approval_backend = None
            self.owner = None
            if job.effect_owner:
                job.effect_context.__exit__(None, None, None)
                job.effect_owner = None

    def _stage(self, job, stage):
        """Translate trusted broker lifecycle stages without double-counting acquired
        leases.
        """
        if stage == "lease_acquired":
            # Runtime observer records acquisition; this callback handles only errors.
            return
        if stage.startswith("denied:"):
            code = stage.partition(":")[2]
            if code in {"vault_http_401", "vault_http_403"}:
                self.last_failure = "provider_access_denied"
            job.view.error = WorkflowError.of(self._safe(code))
            if code == "cleanup_failed":
                job.view.cleanup_status = "failed"
                job.uncertain = True

    @staticmethod
    def _safe(code):
        """Map internal failure codes to the closed browser error catalog."""
        from agent.workspace.models import ERRORS

        if code in ERRORS:
            return code
        if code.startswith("verify_"):
            return "approval_invalid"
        if code.startswith(("database_", "vault_", "delegation_", "oauth_")):
            return "database_unavailable"
        if code == "approval_denied_or_expired":
            return "approval_unconfirmed"
        return "task_failed"

    def close_session(self, session):
        """Contain session work immediately and return a coroutine that drains admission
        and execution.

        Credentials and runtime records can be discarded only after this drain finishes.
        """
        for job in session.jobs.values():
            job.view.retry_available = False
            if job.view.state not in {"completed", "denied", "failed", "interrupted"}:
                job.stopped = True
                self.runtime.approvals.invalidate_run(job.context.run_id)
                self.runtime.contain_run(job.context.run_id)

        async def drain():
            """Wait for workers and admission ownership to end, then forget reserved
            runtime state.
            """
            owned = [j.worker for j in session.jobs.values() if j.worker and not j.worker.done()]
            if owned:
                await asyncio.gather(*owned, return_exceptions=True)
            # Admission has no effects; it checks closing state after renewal.
            while self.owner and self.owner.session is session:
                await asyncio.sleep(0.01)
            for job in list(session.jobs.values()):
                self.runtime.forget(job.context.run_id)

        return drain()

    def project_job(self, job):
        """Return containment details only after the caller has resolved a session-owned job."""
        from agent.response.store import ResponseStore

        control = self.runtime.response_store
        if not isinstance(control, ResponseStore):
            return job.view
        try:
            state = control.read()
            root = next((r for r in state.runs if r.root_run_id == job.context.run_id), None)
            details = tuple(
                control.summary(i, state) for i in state.incidents if root and i.matches(root)
            )
            return job.view.model_copy(
                update={
                    "containment": details,
                    "retry_available": job.view.retry_available
                    and not any(i.contained for i in details),
                }
            )
        except SecurityError:
            return job.view.model_copy(update={"retry_available": False})

    def containment_view(self, session=None):
        """Anonymous restriction is aggregate; only this session's roots authorize details."""
        from agent.response.store import ResponseStore

        control = self.runtime.response_store
        if not isinstance(control, ResponseStore):
            return {"restricted": False, "next_action": None}
        try:
            state = control.read()
            restricted = bool(state.holds)
            roots = {job.context.run_id for job in session.jobs.values()} if session else set()
            details = tuple(
                control.summary(i, state).model_dump(mode="json")
                for i in state.incidents
                if any(r.root_run_id in roots and i.matches(r) for r in state.runs)
            )
            view = {
                "restricted": restricted,
                "next_action": "inspect_incident" if restricted else None,
            }
            if session is not None:
                view["incidents"] = details
            return view
        except SecurityError as error:
            from agent.response.models import REASONS

            return {"restricted": True, "next_action": REASONS.get(str(error), "repair_storage")}
