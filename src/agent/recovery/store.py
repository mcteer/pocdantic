"""Fixed-root durable recovery journal and explicit workspace/effect ownership.

Network work never holds journal.lock. Every transaction revalidates private paths,
file identities, ownership, permissions, and anchor agreement. Failed durability latches
an in-process block; in-memory handles must still be cleaned by the trusted caller.
"""

import fcntl
import hashlib
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from agent.security import SecurityError
from agent.validation.context import profile_bytes
from agent.validation.models import canonical
from agent.validation.store import decode_json, no_symlinks, project_root

from .models import (
    REASONS,
    Anchor,
    AttemptV2,
    BoundOwnership,
    JournalV2,
    LegacyOwnership,
    OperationalView,
    Receipt,
    now,
    parse_journal,
)

MAX_BYTES = 4 * 1024 * 1024
RECEIPT_RESERVE = 16 * 1024
LOCKS = ("workspace.lock", "effect.lock", "journal.lock")


class RecoveryError(SecurityError):
    def __init__(self, code="recovery_storage_error"):
        """Expose only supported safe recovery codes, never filesystem/provider diagnostics."""
        super().__init__(code if code in REASONS else "recovery_storage_error")


def configured(settings):
    """Identify live database integration without reading or using administrative credentials."""
    return bool(settings.database_host)


def environment_digest(settings):
    """Hash nonsecret target configuration and profiles; persist no raw settings."""
    names = (
        "vault_addr",
        "vault_namespace",
        "vault_read_path",
        "database_host",
        "database_port",
        "database_name",
        "database_username_suffix",
        "oauth_issuer",
        "oauth_discovery_url",
        "oauth_audience",
        "vault_audience",
        "actor_audience",
        "oauth_client_id",
        "workload_definition",
    )
    values = {name: getattr(settings, name) for name in names}
    values["vault_addr"] = (settings.vault_addr or "").rstrip("/").lower()
    values["database_host"] = (settings.database_host or "").lower()
    try:
        values["profiles"] = hashlib.sha256(profile_bytes(settings.profiles_file)).hexdigest()
        return hashlib.sha256(canonical(values)).hexdigest()
    except Exception:
        raise RecoveryError() from None


def check_stat(value, *, directory=False):
    """Require a private owned regular file or directory, rejecting hardlinked files."""
    expected = 0o700 if directory else 0o600
    if (
        value.st_uid != os.getuid()
        or stat.S_IMODE(value.st_mode) != expected
        or not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
        or not directory
        and value.st_nlink != 1
    ):
        raise RecoveryError()


@dataclass(repr=False)
class EffectOwner:
    store: object
    fd: int
    active: bool = True
    used: bool = False
    incident_id: object = None
    binding: object = None

    def require(self, store):
        """Reject released, foreign, or fabricated ownership before admitting an acquisition."""
        if (
            not self.active
            or self.store is not store
            or not any(owner is self for owner in store.owners)
        ):
            raise RecoveryError("recovery_busy")
        store._validate_root()


class RecoveryStore:
    def __init__(self, settings, *, project=None):
        """Resolve one immutable project root; tests may inject an isolated project directory."""
        self.settings = settings
        self.max_bytes = MAX_BYTES
        self.project = Path(project or project_root()).absolute()
        self.root = self.project / ".local/recovery"
        self.workspace_context = None
        self.failed = False
        self.established = False
        self.identity = None
        self.owners = []

    def claim_workspace(self):
        """Claim initialized lifetime storage without creating a missing journal."""
        if self.workspace_context is None:
            context = self.workspace()
            context.__enter__()
            self.workspace_context = context

    def release_workspace(self):
        """Release lifetime ownership after all effect and diagnostic workers drain."""
        if self.workspace_context is not None:
            context, self.workspace_context = self.workspace_context, None
            context.__exit__(None, None, None)

    def _validate_root(self):
        """Recheck path identities and permissions on every state operation."""
        if self.failed:
            raise RecoveryError()
        try:
            no_symlinks(self.root)
            if not self.root.exists():
                raise RecoveryError(
                    "recovery_storage_error" if self.established else "recovery_uninitialized"
                )
            check_stat(self.root.parent.stat(), directory=True)
            value = self.root.stat()
            check_stat(value, directory=True)
            identity = (value.st_dev, value.st_ino)
            if self.identity is not None and self.identity != identity:
                raise RecoveryError()
            self.identity = identity
            self.established = True
            for name in ("anchor.json", "state.json", *LOCKS):
                check_stat((self.root / name).lstat())
        except RecoveryError:
            raise
        except Exception:
            raise RecoveryError() from None

    @contextmanager
    def _directory(self):
        """Open and verify an anchored directory descriptor, rechecking it on exit."""
        self._validate_root()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            value = os.fstat(fd)
            check_stat(value, directory=True)
            if (value.st_dev, value.st_ino) != self.identity:
                raise RecoveryError()
            yield fd
            if not self.failed:
                self._validate_root()
        finally:
            os.close(fd)

    @contextmanager
    def _lock(self, name):
        """Take one nonblocking verified lock; never recreate a missing lock file."""
        try:
            with self._directory() as directory:
                fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                try:
                    check_stat(os.fstat(fd))
                    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if (before.st_dev, before.st_ino) != (os.fstat(fd).st_dev, os.fstat(fd).st_ino):
                        raise RecoveryError()
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        raise RecoveryError("recovery_busy") from None
                    yield fd
                    after = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                        self.failed = True
                        raise RecoveryError()
                finally:
                    os.close(fd)
        except RecoveryError:
            raise
        except OSError:
            self.failed = True
            raise RecoveryError() from None

    @contextmanager
    def effect(self):
        """Own the single live effect until the caller and every cleanup worker have stopped."""
        with self._lock("effect.lock") as fd:
            owner = EffectOwner(self, fd)
            self.owners.append(owner)
            try:
                yield owner
            finally:
                owner.active = False
                self.owners.remove(owner)

    def workspace(self):
        """Return workspace lifetime ownership, independently of the effect lock."""
        return self._lock("workspace.lock")

    def _read_file(self, directory, name):
        """Read bounded private bytes through a verified descriptor, detecting replacement races."""
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as file:
            before = os.fstat(file.fileno())
            check_stat(before)
            raw = file.read(self.max_bytes + 1)
            after = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or len(
                raw
            ) > self.max_bytes:
                raise RecoveryError()
        return decode_json(raw)

    def _read(self, directory):
        """Validate anchor, snapshot, and current environment while holding journal.lock."""
        anchor = Anchor.model_validate(self._read_file(directory, "anchor.json"))
        journal = parse_journal(self._read_file(directory, "state.json"))
        if anchor.installation_id != journal.installation_id:
            raise RecoveryError()
        if journal.environment_digest != environment_digest(self.settings):
            raise RecoveryError("recovery_environment_mismatch")
        return journal

    def read(self):
        """Read authoritative current state without creating files or contacting providers."""
        try:
            with self._lock("journal.lock"), self._directory() as directory:
                return self._read(directory)
        except RecoveryError:
            raise
        except Exception:
            raise RecoveryError() from None

    def _write(self, directory, journal):
        """Commit a complete snapshot with file fsync, atomic replacement, and directory fsync."""
        raw = canonical(journal)
        if len(raw) > self.max_bytes:
            raise RecoveryError("recovery_capacity")
        name = str(uuid4()) + ".tmp"
        try:
            before = os.stat("state.json", dir_fd=directory, follow_symlinks=False)
            check_stat(before)
            fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
            )
            with os.fdopen(fd, "wb") as file:
                check_stat(os.fstat(file.fileno()))
                file.write(raw)
                file.flush()
                os.fsync(file.fileno())
            self._validate_root()
            after = os.stat("state.json", dir_fd=directory, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise RecoveryError()
            os.replace(name, "state.json", src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        except Exception:
            self.failed = True
            raise RecoveryError() from None
        finally:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
            except OSError:
                self.failed = True
                raise RecoveryError() from None

    def initialize(self):
        """Explicitly enroll a wholly absent root; never overwrite partial or established state."""
        if self.root.exists() or self.root.is_symlink() or self.established:
            self.read()
            return False
        if not all(
            (
                self.settings.database_host,
                self.settings.database_name,
                self.settings.vault_addr,
                self.settings.vault_audience,
                self.settings.oauth_audience,
                self.settings.oauth_client_id,
            )
        ):
            raise RecoveryError("configuration_missing")
        digest = environment_digest(self.settings)
        try:
            no_symlinks(self.root)
            self.root.parent.mkdir(mode=0o700, exist_ok=True)
            check_stat(self.root.parent.stat(), directory=True)
            self.root.mkdir(mode=0o700)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            installation = uuid4()
            try:
                values = {
                    "anchor.json": Anchor(installation_id=installation),
                    "state.json": JournalV2(
                        installation_id=installation, environment_digest=digest
                    ),
                }
                for name in (*values, *LOCKS):
                    fd = os.open(
                        name,
                        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                    with os.fdopen(fd, "wb") as file:
                        file.write(canonical(values[name]) if name in values else b"")
                        file.flush()
                        os.fsync(file.fileno())
                os.fsync(directory)
            finally:
                os.close(directory)
            for path in (self.root.parent, self.project):
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            self.read()
            return True
        except RecoveryError:
            raise
        except Exception:
            self.failed = True
            raise RecoveryError() from None

    def _prune(self, journal, *, reserve=False):
        """Remove only resolved records, retaining uncertainty even when capacity is exhausted."""
        cutoff = now() - timedelta(days=7)
        pins = set()
        response_root = self.project / ".local/response"
        if (response_root / "anchor.json").exists() or response_root.is_symlink():
            from agent.response.store import ResponseStore

            try:
                pins = ResponseStore(
                    self.settings, project=self.project, recovery=self
                ).pinned_recovery(journal)
            except Exception:
                return journal.attempts
        attempts = [
            a
            for a in journal.attempts
            if a.state != "resolved" or a.updated_at >= cutoff or a.incident_id in pins
        ]
        if reserve:
            while (
                len(attempts) >= 1000
                or len(canonical(journal.model_copy(update={"attempts": tuple(attempts)})))
                > MAX_BYTES - RECEIPT_RESERVE
            ):
                oldest = next(
                    (
                        a
                        for a in sorted(attempts, key=lambda x: x.updated_at)
                        if a.state == "resolved"
                        and a.incident_id not in pins
                        and a.updated_at < cutoff
                    ),
                    None,
                )
                if oldest is None:
                    raise RecoveryError("recovery_capacity")
                attempts.remove(oldest)
        return tuple(attempts)

    def begin(self, owner, binding=None):
        """Reserve receipt capacity and durably commit intent before any credential request."""
        owner.require(self)
        if owner.used:
            raise RecoveryError("recovery_busy")
        try:
            with self._lock("journal.lock"), self._directory() as directory:
                journal = self._read(directory)
                if journal.schema_version != 2:
                    raise RecoveryError("recovery_migration_required")
                unfinished = [a for a in journal.attempts if a.state != "resolved"]
                if unfinished:
                    raise RecoveryError(unfinished[0].reason_code)
                attempts = self._prune(journal, reserve=True)
                ownership = BoundOwnership.model_validate(binding or owner.binding)
                item = AttemptV2(
                    ownership=ownership,
                    incident_id=uuid4(),
                    operation_id=uuid4(),
                    environment_digest=journal.environment_digest,
                    credential_path=self.settings.vault_read_path,
                )
                updated = type(journal).model_validate(
                    journal.model_dump()
                    | {
                        "attempts": (*attempts, item),
                        "revision": journal.revision + 1,
                        "updated_at": now(),
                    }
                )
                if len(canonical(updated)) > MAX_BYTES - RECEIPT_RESERVE:
                    raise RecoveryError("recovery_capacity")
                self._write(directory, updated)
                owner.used = True
                owner.incident_id = item.incident_id
                return item
        except (ValidationError, OSError):
            self.failed = True
            raise RecoveryError() from None

    def update(self, incident_id, expected_revision, **changes):
        """Compare-and-swap one attempt, checking transitions and preserving native bindings."""
        allowed = {
            "intent": {"acquired", "unresolved"},
            "acquired": {"cleanup_pending", "unresolved"},
            "cleanup_pending": {"resolved", "unresolved"},
            "unresolved": {"unresolved", "cleanup_pending", "resolved"},
            "resolved": {"resolved"},
        }
        try:
            with self._lock("journal.lock"), self._directory() as directory:
                journal = self._read(directory)
                item = next((a for a in journal.attempts if a.incident_id == incident_id), None)
                if (
                    not item
                    or type(expected_revision) is not int
                    or item.revision != expected_revision
                ):
                    raise RecoveryError("recovery_evidence_invalid")
                if item.state == "resolved" or set(changes) - {
                    "state",
                    "native_request_id",
                    "lease_handle",
                    "reason_code",
                    "resolution",
                    "receipt",
                }:
                    raise RecoveryError("recovery_evidence_invalid")
                if changes.get("state", item.state) not in allowed[item.state]:
                    raise RecoveryError("recovery_evidence_invalid")
                for key in ("lease_handle", "native_request_id"):
                    if getattr(item, key) and changes.get(key, getattr(item, key)) != getattr(
                        item, key
                    ):
                        raise RecoveryError("recovery_evidence_invalid")
                receipt = changes.get("receipt")
                if receipt:
                    receipt = Receipt.model_validate(receipt)
                    if receipt.incident_revision != item.revision:
                        raise RecoveryError("recovery_evidence_invalid")
                    for other in journal.attempts:
                        if (
                            other.incident_id != item.incident_id
                            and other.receipt
                            and receipt.source_digests
                            and (
                                set(receipt.source_digests) & set(other.receipt.source_digests)
                                or receipt.native_request_id == other.receipt.native_request_id
                            )
                        ):
                            raise RecoveryError("recovery_evidence_invalid")
                updated = type(item).model_validate(
                    item.model_dump()
                    | changes
                    | {"revision": item.revision + 1, "updated_at": now()}
                )
                attempts = tuple(
                    updated if a.incident_id == incident_id else a for a in journal.attempts
                )
                journal = type(journal).model_validate(
                    journal.model_dump()
                    | {"attempts": attempts, "revision": journal.revision + 1, "updated_at": now()}
                )
                self._write(directory, journal)
                return updated
        except (ValidationError, OSError):
            raise RecoveryError() from None

    def prune(self):
        """Prune expired terminal records on explicit checks; never resolve an incident."""
        with self.effect(), self._lock("journal.lock"), self._directory() as directory:
            journal = self._read(directory)
            attempts = self._prune(journal)
            if attempts != journal.attempts:
                updated = type(journal).model_validate(
                    journal.model_dump()
                    | {"attempts": attempts, "revision": journal.revision + 1, "updated_at": now()}
                )
                self._write(directory, updated)

    def normalize(self):
        """Convert abandoned attempts only while exclusively owning the effect lock."""
        with self.effect():
            journal = self.read()
            for item in journal.attempts:
                if item.state not in {"resolved", "unresolved"}:
                    self.update(
                        item.incident_id,
                        item.revision,
                        state="unresolved",
                        reason_code="cleanup_unconfirmed"
                        if item.lease_handle
                        else "acquisition_uncertain",
                    )
            with self._lock("journal.lock"), self._directory() as directory:
                journal = self._read(directory)
                attempts = self._prune(journal)
                if attempts != journal.attempts:
                    journal = type(journal).model_validate(
                        journal.model_dump()
                        | {
                            "attempts": attempts,
                            "revision": journal.revision + 1,
                            "updated_at": now(),
                        }
                    )
                    self._write(directory, journal)
            return journal

    def status(self, *, authentication=False, owned=(), active_work=False):
        """Return aggregate state and only explicitly session-owned incident summaries."""
        if (
            not configured(self.settings)
            and not self.root.exists()
            and not self.root.is_symlink()
            and not self.established
        ):
            return OperationalView(authentication=authentication, active_work=active_work)
        try:
            journal = self.read()
            active_ids = {owner.incident_id for owner in self.owners if owner.active}
            blocked = [
                a
                for a in journal.attempts
                if a.state != "resolved" and a.incident_id not in active_ids
            ]
            reason = blocked[0].reason_code if blocked else None
            return OperationalView(
                authentication=authentication,
                recovery="blocked" if blocked else "clear",
                active_work=active_work or bool(active_ids),
                blocked_count=len(blocked),
                checked_at=now(),
                reason_code=reason,
                next_action=REASONS[reason][1] if reason else None,
                incidents=tuple(a.summary() for a in blocked if a.incident_id in owned),
            )
        except RecoveryError as error:
            reason = str(error)
            return OperationalView(
                authentication=authentication,
                recovery="uninitialized" if reason == "recovery_uninitialized" else "storage_error",
                active_work=active_work,
                checked_at=now(),
                reason_code=reason,
                next_action=REASONS[reason][1],
            )

    def migrate(self):
        """Atomically convert v1 state only, under offline workspace/effect ownership.

        No native fields, receipts, per-attempt revisions or timestamps are changed.
        An orphan temporary file is never promoted after a crash.
        """
        with self.workspace(), self.effect(), self._lock("journal.lock"), self._directory() as fd:
            journal = self._read(fd)
            if journal.schema_version == 2:
                return False
            attempts = tuple(
                AttemptV2.model_validate(
                    a.model_dump() | {"schema_version": 2, "ownership": LegacyOwnership()}
                )
                for a in journal.attempts
            )
            updated = JournalV2.model_validate(
                journal.model_dump()
                | {
                    "schema_version": 2,
                    "attempts": attempts,
                    "revision": journal.revision + 1,
                    "updated_at": now(),
                }
            )
            if len(canonical(updated)) > self.max_bytes:
                raise RecoveryError("recovery_capacity")
            self._write(fd, updated)
            return True

    def normalize_owned(self):
        """Normalize orphaned attempts when the caller already retains effect ownership."""
        journal = self.read()
        for item in journal.attempts:
            if item.state not in {"resolved", "unresolved"}:
                self.update(
                    item.incident_id,
                    item.revision,
                    state="unresolved",
                    reason_code="cleanup_unconfirmed"
                    if item.lease_handle
                    else "acquisition_uncertain",
                )
        return self.read()
