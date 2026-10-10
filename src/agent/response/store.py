"""Private atomic control state with short locks independent of active database work.

Reuse the recovery store's verified-descriptor/fsync primitives, but keep a separate
anchor, state root and control lock. Never await effect ownership under a control lock.
"""

import fcntl
import hashlib
import os
from contextlib import ExitStack, contextmanager
from datetime import timedelta
from uuid import uuid4

from pydantic import ValidationError

from agent.recovery.models import Anchor, now
from agent.recovery.store import RecoveryError, RecoveryStore, check_stat, environment_digest
from agent.validation.models import canonical
from agent.validation.store import decode_json, no_symlinks

from .models import (
    REASONS,
    PublicSummary,
    ResponseAnchor,
    ResponseError,
    RunBinding,
    SourcePolicy,
)

MAX_BYTES = 16 * 1024 * 1024
RESERVE = 256 * 1024


class ResponseStore(RecoveryStore):
    """Durable installed controls; tests can inject an isolated project, never a CLI root."""

    def __init__(self, settings, *, project=None, recovery=None):
        """Bind fixed private response storage and its associated recovery installation."""
        super().__init__(settings, project=project)
        self.root = self.project / ".local/response"
        self.max_bytes = MAX_BYTES
        self.recovery = recovery or RecoveryStore(settings, project=self.project)

    def _validate_root(self):
        """Extend verified recovery primitives to control and worker lock identities."""
        super()._validate_root()
        for name in ("policy.json", "control.lock", "worker.lock"):
            check_stat((self.root / name).lstat())
        # Schema-1 installations gain this provider-only lock during explicit prepare.
        if (self.root / "probe.lock").exists() or (self.root / "probe.lock").is_symlink():
            check_stat((self.root / "probe.lock").lstat())

    @contextmanager
    def transaction(self):
        """Hold one short verified control lock; convert private failures to safe reasons."""
        try:
            with self._lock("control.lock"), self._directory() as fd:
                journal = self._read(fd)
                yield fd, journal
        except ResponseError:
            raise
        except RecoveryError as error:
            raise ResponseError(
                "response_busy"
                if str(error) == "recovery_busy"
                else "response_uninitialized"
                if str(error) == "recovery_uninitialized"
                else "response_storage_error"
            ) from None
        except (OSError, ValueError, TypeError, ValidationError):
            raise ResponseError() from None

    def policy(self):
        """Read the fixed, owner-only bounded mapping, never a caller-selected file."""
        try:
            no_symlinks(self.root)
            check_stat(self.root.parent.stat(), directory=True)
            check_stat(self.root.stat(), directory=True)
            path = self.root / "policy.json"
            with path.open("rb") as file:
                before = os.fstat(file.fileno())
                check_stat(before)
                raw = file.read(32769)
                after = path.lstat()
                if len(raw) > 32768 or (before.st_dev, before.st_ino) != (
                    after.st_dev,
                    after.st_ino,
                ):
                    raise ResponseError()
            policy = SourcePolicy.model_validate(decode_json(raw))
            if (
                policy.workload_definition != self.settings.workload_definition
                or policy.environment_digest != environment_digest(self.settings)
                or policy.issuer != (self.settings.oauth_issuer or "offline")
                or policy.audience is not None
                and policy.audience
                in {
                    self.settings.oauth_audience,
                    self.settings.actor_audience,
                    self.settings.vault_audience,
                    self.settings.oauth_client_id,
                    self.settings.login_client_id,
                }
            ):
                raise ResponseError("response_policy_changed")
            return policy
        except ResponseError:
            raise
        except Exception:
            raise ResponseError() from None

    def prepare(self):
        """Create one private draft from current settings; never overwrite even a draft."""
        try:
            no_symlinks(self.root)
            self.root.parent.mkdir(mode=0o700, exist_ok=True)
            check_stat(self.root.parent.stat(), directory=True)
            self.root.mkdir(mode=0o700, exist_ok=True)
            check_stat(self.root.stat(), directory=True)
            policy = SourcePolicy(
                workload_definition=self.settings.workload_definition,
                environment_digest=environment_digest(self.settings),
                issuer=self.settings.oauth_issuer or "offline",
            )
            fd = os.open(
                self.root / "policy.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "wb") as file:
                file.write(canonical(policy))
                file.flush()
                os.fsync(file.fileno())
            for path in (self.root, self.root.parent, self.project):
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            return True
        except Exception:
            raise ResponseError() from None

    def initialize(self):
        """Enroll a prepared policy; established or partial installations cannot reset."""
        if (
            any(
                (self.root / name).exists() or (self.root / name).is_symlink()
                for name in (
                    "anchor.json",
                    "state.json",
                    "control.lock",
                    "worker.lock",
                    "probe.lock",
                    "journal.lock",
                    "effect.lock",
                    "workspace.lock",
                )
            )
            or self.established
        ):
            self.read()
            return False
        policy = self.policy()
        try:
            recovery = None
            if (
                self.settings.database_host
                or self.recovery.root.exists()
                or self.recovery.root.is_symlink()
            ):
                recovery = self.recovery.read()
                if recovery.schema_version != 2:
                    raise ResponseError("response_migration_required")
            install = uuid4()
            anchor = ResponseAnchor(
                installation_id=install,
                recovery_mode="configured" if recovery else "not_configured",
                recovery_installation_id=recovery.installation_id if recovery else None,
            )
            from .providers.journal import ResponseJournalV2

            journal = ResponseJournalV2(
                installation_id=install,
                environment_digest=policy.environment_digest,
                policy_digest=hashlib.sha256(canonical(policy)).hexdigest(),
            )
            values = {"anchor.json": anchor, "state.json": journal}
            for name in (
                *values,
                "control.lock",
                "worker.lock",
                "probe.lock",
                "journal.lock",
                "effect.lock",
                "workspace.lock",
            ):
                fd = os.open(
                    self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                with os.fdopen(fd, "wb") as file:
                    file.write(canonical(values[name]) if name in values else b"")
                    file.flush()
                    os.fsync(file.fileno())
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            self.read()
            return True
        except ResponseError:
            raise
        except Exception:
            raise ResponseError() from None

    def _read(self, fd):
        """Validate both independent enrollment identities and captured policy bindings."""
        anchor = ResponseAnchor.model_validate(self._read_file(fd, "anchor.json"))
        from .providers.journal import parse_journal

        journal = parse_journal(self._read_file(fd, "state.json"))
        policy = self.policy()
        if anchor.installation_id != journal.installation_id:
            raise ResponseError()
        if (
            journal.environment_digest != policy.environment_digest
            or journal.policy_digest != hashlib.sha256(canonical(policy)).hexdigest()
        ):
            raise ResponseError("response_policy_changed")
        if anchor.recovery_mode == "configured":
            with self.recovery._directory() as recovery_fd:
                recovery_anchor = Anchor.model_validate(
                    self.recovery._read_file(recovery_fd, "anchor.json")
                )
            if recovery_anchor.installation_id != anchor.recovery_installation_id:
                raise ResponseError()
        elif (
            self.settings.database_host
            or self.recovery.root.exists()
            or self.recovery.root.is_symlink()
        ):
            raise ResponseError("response_policy_changed")
        return journal

    def migrate(self):
        """Atomically upgrade response only, with all workers and root owners quiescent.

        Legacy authority/receipts stay byte-identical. No historical provider plan is
        inferred; an older process rejects v2 instead of silently ignoring new holds.
        """
        from .providers.journal import ResponseJournalV2

        if self.read().schema_version == 2:
            return False
        mode = self.anchor().recovery_mode
        try:
            with ExitStack() as locks:
                if mode == "configured":
                    locks.enter_context(self.recovery.workspace())
                locks.enter_context(self.workspace())
                locks.enter_context(self._lock("worker.lock"))
                locks.enter_context(
                    self.recovery.effect() if mode == "configured" else self.effect()
                )
                with self.transaction() as (fd, journal):
                    if journal.schema_version == 2:
                        return False
                    if any(self.busy(r.root_run_id) for r in journal.runs):
                        raise ResponseError("response_busy")
                    value = ResponseJournalV2.model_validate(
                        journal.model_dump() | {"schema_version": 2}
                    )
                    self._write(fd, value)
                    return True
        except RecoveryError as error:
            raise ResponseError(
                "response_busy" if str(error) == "recovery_busy" else "response_storage_error"
            ) from None

    def subject_held(self, issuer, subject):
        """Read whether this verified user has an unreleased local execution hold."""
        state = self.read()
        return any(
            h.issuer == issuer and h.subject == subject for h in getattr(state, "subject_holds", ())
        )

    def bind_actor(self, binding, issuer, subject):
        """Capture verified actor attribution prospectively without changing lease ownership."""
        self.check(binding)
        with self.transaction() as (fd, state):
            run = next(r for r in state.runs if r.root_run_id == binding.root_run_id)
            if run.actor_subject is not None and (run.actor_issuer, run.actor_subject) != (
                issuer,
                subject,
            ):
                raise ResponseError("mapping_missing")
            policy = state.enrollment
            if policy:
                matches = [b for b in policy.bindings if b.enabled and b.kind == "registration"]
                if matches and not any(
                    (b.actor_issuer, b.actor_subject) == (issuer, subject) for b in matches
                ):
                    raise ResponseError("mapping_missing")
            updated = RunBinding.model_validate(
                run.model_dump() | {"actor_issuer": issuer, "actor_subject": subject}
            )
            self.commit(
                fd,
                state,
                runs=tuple(updated if r.root_run_id == run.root_run_id else r for r in state.runs),
            )

    def read(self):
        """Read without normalization or provider calls; status is never an effect trigger."""
        with self.transaction() as (_, journal):
            return journal

    def anchor(self):
        """Read validated recovery-mode enrollment with no inferred missing-state bypass."""
        with self.transaction() as (fd, _):
            return ResponseAnchor.model_validate(self._read_file(fd, "anchor.json"))

    def commit(self, fd, journal, **changes):
        """Atomically advance the journal while retaining space for accepted action results."""
        if journal.schema_version != 2:
            raise ResponseError("response_schema_migration_required")
        updated = type(journal).model_validate(
            journal.model_dump() | changes | {"revision": journal.revision + 1, "updated_at": now()}
        )
        reserved = sum(
            max(
                0,
                RESERVE - len(canonical(i.actions)),
            )
            for i in updated.incidents
            if i.phase != "settled"
        )
        from .providers.journal import result_reservation

        reserved += result_reservation(updated)
        if len(canonical(updated)) + reserved > MAX_BYTES:
            raise ResponseError("response_capacity")
        self._write(fd, updated)
        return updated

    def busy(self, run_id):
        """Test an existing root lifetime lock; child-inherited descriptors keep it busy."""
        try:
            with self._lock(f"run-{run_id}.lock"):
                return False
        except RecoveryError as error:
            if str(error) == "recovery_busy":
                return True
            raise ResponseError() from None

    def register(self, request_id, root_id, principal):
        """Bind a fresh host allocation to verified context before model/effect work."""
        if principal.issuer != self.policy().issuer:
            raise ResponseError("source_invalid")
        with self.transaction() as (fd, journal):
            if journal.schema_version != 2:
                raise ResponseError("response_schema_migration_required")
            if (
                journal.holds
                or root_id in journal.root_holds
                or any(
                    h.issuer == principal.issuer and h.subject == principal.subject
                    for h in journal.subject_holds
                )
            ):
                raise ResponseError("contained")
            if any(r.root_run_id == root_id for r in journal.runs):
                raise ResponseError("contained")
            if len(journal.runs) >= 1000:
                raise ResponseError("response_capacity")
            run = RunBinding(
                root_run_id=root_id,
                request_id=request_id,
                workload_definition=self.settings.workload_definition,
                generation=journal.generation,
                issuer=principal.issuer,
                subject=principal.subject,
            )
            lock = os.open(
                f"run-{root_id}.lock",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=fd,
            )
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.fsync(fd)
                self.commit(fd, journal, runs=(*journal.runs, run))
                return run, lock
            except BaseException:
                os.close(lock)
                raise

    def check(self, binding):
        """Deny unknown, terminal, stale-generation or durably held roots at every boundary."""
        journal = self.read()
        run = next((r for r in journal.runs if r.root_run_id == binding.root_run_id), None)
        if (
            journal.schema_version != 2
            or run is None
            or run.state != "active"
            or run.ownership() != binding.ownership()
            or journal.holds
            or any(
                h.issuer == binding.issuer and h.subject == binding.subject
                for h in getattr(journal, "subject_holds", ())
            )
            or run.root_run_id in journal.root_holds
            or run.generation != journal.generation
        ):
            raise ResponseError("contained")

    def finish(self, binding):
        """Record terminal state after cleanup drain; holds remain independently durable."""
        with self.transaction() as (fd, journal):
            runs = tuple(
                RunBinding.model_validate(
                    r.model_dump() | {"state": "terminal", "finished_at": now()}
                )
                if r.root_run_id == binding.root_run_id
                else r
                for r in journal.runs
            )
            self.commit(fd, journal, runs=runs)

    def pinned_recovery(self, journal):
        """Select receipt IDs pinned by active scopes/actions; call under effect ownership."""
        state = self.read()
        pinned = {
            a.target_id
            for i in state.incidents
            for a in i.actions
            if a.kind == "revoke_exact" and a.status != "confirmed"
        }
        pinned.update(
            p.recovery_incident_id
            for p in getattr(state, "probe_acquisitions", ())
            if p.recovery_incident_id is not None
        )
        for item in journal.attempts:
            ownership = getattr(item, "ownership", None)
            if (
                ownership is not None
                and ownership.kind == "bound"
                and any(i.phase != "settled" and i.matches(ownership) for i in state.incidents)
            ):
                pinned.add(item.incident_id)
        return pinned

    def prune(self):
        """Retain unresolved attribution and all active scopes across both journals."""
        recovery_mode = self.anchor().recovery_mode
        context = self.recovery.effect() if recovery_mode == "configured" else _nothing()
        with context:
            recovery = self.recovery.read() if recovery_mode == "configured" else None
            with self.transaction() as (fd, journal):
                cutoff = now() - timedelta(days=30)
                pins = (
                    {
                        a.ownership.root_run_id
                        for a in recovery.attempts
                        if a.state != "resolved" and a.ownership.kind == "bound"
                    }
                    if recovery
                    else set()
                )
                pins.update(
                    r.root_run_id
                    for r in journal.runs
                    if any(i.phase != "settled" and i.matches(r) for i in journal.incidents)
                )
                from .providers.retention import (
                    acquisition_roots,
                    closure,
                    incident_pins,
                    prune_fields,
                    recent_incidents,
                )

                provider_pins = incident_pins(journal) | recent_incidents(journal, cutoff)
                initial_ids = (
                    provider_pins
                    | {
                        i.incident_id
                        for i in journal.incidents
                        if i.phase != "settled" or i.received_at >= cutoff
                    }
                    | {iid for hold in journal.holds for iid in hold.incident_ids}
                )
                provider_pins, _ = closure(journal, initial_ids)
                pins.update(
                    r.root_run_id
                    for r in journal.runs
                    if any(
                        i.incident_id in provider_pins and i.matches(r) for i in journal.incidents
                    )
                )
                pins.update(acquisition_roots(journal))
                if journal.holds:
                    pins.update(r.root_run_id for r in journal.runs)
                runs = tuple(
                    r
                    for r in journal.runs
                    if r.root_run_id in pins
                    or r.state == "active"
                    or (r.finished_at or r.started_at) >= cutoff
                )
                roots = {r.root_run_id for r in runs}
                hold_ids = {x for h in journal.holds for x in h.incident_ids}
                hold_ids.update(provider_pins)
                incidents = tuple(
                    i
                    for i in journal.incidents
                    if i.phase != "settled"
                    or i.incident_id in hold_ids
                    or i.received_at >= cutoff
                    or i.target.kind == "root_run"
                    and i.target.root_run_id in roots
                )
                self.commit(
                    fd,
                    journal,
                    runs=runs,
                    incidents=incidents,
                    root_holds=tuple(x for x in journal.root_holds if x in roots),
                    releases=tuple(r for r in journal.releases if r.released_at >= cutoff),
                    **prune_fields(journal, {i.incident_id for i in incidents}, roots, cutoff),
                )
                for run in journal.runs:
                    if run.root_run_id not in roots:
                        os.unlink(f"run-{run.root_run_id}.lock", dir_fd=fd)
                os.fsync(fd)

    def summary(self, incident, journal=None):
        """Project an owned incident without event/source/user/native identifiers."""
        journal = journal or self.read()
        held = (
            incident.target.root_run_id in journal.root_holds
            if incident.target.kind == "root_run"
            else any(incident.incident_id in h.incident_ids for h in journal.holds)
        )
        cleanup = (
            "not_applicable"
            if self.anchor().recovery_mode == "not_configured"
            else ("confirmed" if incident.phase == "settled" else "pending")
        )
        from .providers.report import controls, database_checks

        return PublicSummary(
            provider_controls=controls(journal, incident.incident_id),
            database_checks=database_checks(journal, incident.incident_id),
            incident_id=incident.incident_id,
            scope=incident.target.kind,
            phase=incident.phase,
            contained=held,
            cleanup=cleanup,
            reason_code=incident.reason_code,
            next_action=REASONS[incident.reason_code],
        )


@contextmanager
def _nothing():
    """No recovery lock exists only in explicitly enrolled non-database mode."""
    yield
