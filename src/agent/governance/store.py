"""Private anchored snapshots with short transactions and reserved effect capacity.

Every read checks the installation anchor and current environment. No operation creates
provider authority. A pending intent pins enough disk space for its bounded result.
"""

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import StrictInt

from agent.recovery.models import Digest, Revision
from agent.recovery.store import RecoveryStore, check_stat
from agent.validation.models import canonical
from agent.validation.store import no_symlinks

from .models import Candidate, CredentialIntent, GovernanceError, Journal, Record, require

LOCKS = ("control.lock", "effect.lock", "service.lock")
RESERVE = 256 * 1024


class Anchor(Record):
    """Immutable installation and original environment identity."""

    installation_id: UUID
    environment: Digest
    root_identity: tuple[StrictInt, StrictInt]
    file_identities: dict[str, tuple[StrictInt, StrictInt]]


class Seal(Record):
    """Durable current snapshot identity in the immutable control-lock inode."""

    installation_id: UUID
    revision: Revision
    state_identity: tuple[StrictInt, StrictInt]
    state_digest: Digest


class GovernanceStore(RecoveryStore):
    """Reuse verified descriptor operations while keeping governance state independent."""

    def __init__(self, *, project, environment):
        """Bind fixed paths and a nonsecret environment digest without reading credentials."""
        super().__init__(None, project=project)
        self.root = Path(project).absolute() / ".local/governance"
        self.environment = environment
        self.max_bytes = 32 * 1024 * 1024
        self.file_identities = {}

    def _validate_root(self):
        """Reject permission, inode, hardlink and symlink changes, including lock replacement."""
        try:
            require(not self.failed, "storage_error")
            no_symlinks(self.root)
            require(self.root.exists(), "not_initialized")
            check_stat(self.root.parent.stat(), directory=True)
            check_stat(self.root.stat(), directory=True)
            identity = (self.root.stat().st_dev, self.root.stat().st_ino)
            require(self.identity in (None, identity), "storage_error")
            self.identity = identity
            for name in ("anchor.json", "state.json", *LOCKS):
                value = (self.root / name).lstat()
                check_stat(value)
                current = (value.st_dev, value.st_ino)
                if name != "state.json":
                    require(self.file_identities.get(name, current) == current, "storage_error")
                    self.file_identities[name] = current
        except GovernanceError:
            raise
        except Exception:
            raise GovernanceError() from None

    @contextmanager
    def lock(self, name):
        """Take a verified nonblocking lock; contention never waits while holding another lock."""
        require(name in LOCKS)
        try:
            with self._lock(name) as fd:
                yield fd
        except GovernanceError:
            raise
        except Exception as error:
            code = "workspace_busy" if str(error) == "recovery_busy" else "storage_error"
            raise GovernanceError(code) from None

    def serialized(self, value):
        """Encode one canonical private snapshot; callers use its size for admission."""
        return canonical(value)

    def _read(self, directory):
        """Require anchor/snapshot agreement and immutable environment before returning state."""
        anchor = Anchor.model_validate(self._read_file(directory, "anchor.json"))
        require(anchor.root_identity == self.identity, "storage_error")
        require(set(anchor.file_identities) == {"anchor.json", *LOCKS}, "storage_error")
        for name, expected in anchor.file_identities.items():
            value = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(expected == (value.st_dev, value.st_ino), "storage_error")
        seal = Seal.model_validate(self._read_file(directory, "control.lock"))
        journal = Journal.model_validate(self._read_file(directory, "state.json"))
        value = os.stat("state.json", dir_fd=directory, follow_symlinks=False)
        require(
            seal.installation_id == anchor.installation_id
            and seal.revision == journal.revision
            and seal.state_identity == (value.st_dev, value.st_ino)
            and seal.state_digest == hashlib.sha256(canonical(journal)).hexdigest(),
            "storage_error",
        )
        require(anchor.installation_id == journal.installation_id, "storage_error")
        require(
            anchor.environment == journal.environment == self.environment, "configuration_changed"
        )
        return journal

    def read(self):
        """Read without initialization or effects; malformed private data gets a safe error."""
        try:
            with self.lock("control.lock"), self._directory() as directory:
                return self._read(directory)
        except GovernanceError:
            raise
        except Exception:
            raise GovernanceError() from None

    def _write(self, directory, journal):
        """Atomically replace only our own snapshot and retain reserved result space."""
        journal = Journal.model_validate(journal.model_dump())
        pending = sum(i.unresolved for i in journal.credentials) + sum(
            a.state in {"prepared", "submitted", "uncertain", "conflict"}
            for a in journal.registrations
        )
        require(len(canonical(journal)) + pending * RESERVE <= self.max_bytes, "capacity_exhausted")
        # The inherited writer verifies the old inode before replace. Accept only the
        # inode produced by that transaction, never an external replacement.
        try:
            super()._write(directory, journal)
            value = os.stat("state.json", dir_fd=directory, follow_symlinks=False)
            seal = Seal(
                installation_id=journal.installation_id,
                revision=journal.revision,
                state_identity=(value.st_dev, value.st_ino),
                state_digest=hashlib.sha256(canonical(journal)).hexdigest(),
            )
            self._seal(directory, seal)
        except Exception:
            self.failed = True
            raise GovernanceError() from None

    def _seal(self, directory, seal):
        """Fsync the commit seal in the fixed lock inode; interrupted sealing blocks restart."""
        fd = os.open("control.lock", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(fd, "wb") as file:
            value = os.fstat(file.fileno())
            check_stat(value)
            require(
                self.file_identities["control.lock"] == (value.st_dev, value.st_ino),
                "storage_error",
            )
            file.write(canonical(seal))
            file.truncate()
            file.flush()
            os.fsync(file.fileno())

    def change(self, operation, *, revision=None):
        """Apply a pure short state transform; provider I/O must occur outside this method."""
        try:
            with self.lock("control.lock"), self._directory() as directory:
                current = self._read(directory)
                require(revision is None or revision == current.revision, "review_stale")
                result = operation(current)
                updated = Journal.model_validate(
                    result.model_dump() | {"revision": current.revision + 1}
                )
                self._write(directory, updated)
                return updated
        except GovernanceError:
            raise
        except Exception:
            raise GovernanceError() from None

    def prepare(self):
        """Create an entirely absent installation exclusively; a partial setup is never reset."""
        require(not self.root.exists() and not self.root.is_symlink(), "storage_error")
        try:
            no_symlinks(self.root)
            self.root.parent.mkdir(mode=0o700, exist_ok=True)
            check_stat(self.root.parent.stat(), directory=True)
            self.root.mkdir(mode=0o700)
            installation = uuid4()
            for name in ("anchor.json", "state.json", *LOCKS):
                fd = os.open(
                    self.root / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
                )
                os.close(fd)
            root = self.root.stat()
            identities = {
                name: ((self.root / name).stat().st_dev, (self.root / name).stat().st_ino)
                for name in ("anchor.json", *LOCKS)
            }
            state = Journal(installation_id=installation, environment=self.environment)
            value = (self.root / "state.json").stat()
            values = {
                "anchor.json": Anchor(
                    installation_id=installation,
                    environment=self.environment,
                    root_identity=(root.st_dev, root.st_ino),
                    file_identities=identities,
                ),
                "state.json": state,
                "control.lock": Seal(
                    installation_id=installation,
                    revision=state.revision,
                    state_identity=(value.st_dev, value.st_ino),
                    state_digest=hashlib.sha256(canonical(state)).hexdigest(),
                ),
            }
            for name in ("anchor.json", "state.json", *LOCKS):
                fd = os.open(self.root / name, os.O_WRONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "wb") as file:
                    file.write(canonical(values[name]) if name in values else b"")
                    file.flush()
                    os.fsync(file.fileno())
            for location in (self.root, self.root.parent, self.project):
                fd = os.open(location, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            return self.read()
        except GovernanceError:
            raise
        except Exception:
            self.failed = True
            raise GovernanceError() from None

    def configure(self, sources, revision):
        """Activate reviewed projections only when no case or credential depends on them."""

        def update(journal):
            """Replace source projections only after proving no retained case depends on them."""
            require(all(c.state == "closed" for c in journal.candidates), "configuration_changed")
            from .models import now

            require(
                not any(
                    i.state != "denied" and (i.safe_after is None or i.safe_after > now())
                    for i in journal.credentials
                ),
                "issuance_unresolved",
            )
            previous = {s.alias: s for s in journal.sources}
            for profile in sources:
                old = previous.get(profile.alias)
                require(
                    old is None or profile == old or profile.generation == old.generation + 1,
                    "configuration_changed",
                )
            return journal.model_copy(update={"sources": tuple(sources)})

        with self.lock("effect.lock"):
            return self.change(update, revision=revision)

    def case(self, source):
        """Prepare a generated unbound local case without claiming native discovery."""
        candidate = None

        def update(journal):
            """Allocate an unbound case against the current enrolled source generation."""
            nonlocal candidate
            profile = next((s for s in journal.sources if s.alias == source), None)
            require(profile is not None, "source_not_ready")
            candidate = Candidate(
                alias="case-" + uuid4().hex[:20],
                source=source,
                source_generation=profile.generation,
                source_snapshot=profile,
            )
            return journal.model_copy(update={"candidates": (*journal.candidates, candidate)})

        self.change(update)
        return candidate

    def intent(self, candidate_id, kind, *, profile_digest=None):
        """Reserve a credential result before dispatch; unbounded uncertainty stays pinned."""
        intent = None

        def update(journal):
            """Append a pinned intent only after checking case status and unresolved capacity."""
            nonlocal intent
            candidate = next(
                (c for c in journal.candidates if c.candidate_id == candidate_id), None
            )
            require(candidate is not None)
            require(candidate.state != "closed", "closed")
            require(
                sum(i.unresolved for i in journal.credentials) < 16,
                "capacity_exhausted",
            )
            digest = profile_digest or hashlib.sha256(canonical(candidate.binding)).hexdigest()
            intent = CredentialIntent(
                candidate_id=candidate_id,
                generation=candidate.generation,
                profile_digest=digest,
                kind=kind,
            )
            return journal.model_copy(update={"credentials": (*journal.credentials, intent)})

        self.change(update)
        return intent

    def prune(self):
        """Remove complete closed cases only after thirty days and every issuance bound."""
        from datetime import timedelta

        from .models import now

        cutoff = now() - timedelta(days=30)
        current = now()

        def update(journal):
            """Remove eligible cases and all their references; retain unresolved work."""
            removable = {
                c.candidate_id
                for c in journal.candidates
                if c.state == "closed" and c.closed_at and c.closed_at < cutoff
            }
            for intent in journal.credentials:
                if intent.state in {"prepared", "submitted"} or (
                    intent.state != "denied"
                    and (intent.safe_after is None or intent.safe_after > current)
                ):
                    removable.discard(intent.candidate_id)
            for attempt in journal.registrations:
                if attempt.state in {"prepared", "submitted", "uncertain", "conflict"}:
                    removable.discard(attempt.candidate_id)
            changes = {
                name: tuple(
                    item for item in getattr(journal, name) if item.candidate_id not in removable
                )
                for name in (
                    "candidates",
                    "observations",
                    "reviews",
                    "registrations",
                    "credentials",
                    "evidence",
                    "challenges",
                    "verifications",
                )
            }
            return journal.model_copy(update=changes)

        with self.lock("effect.lock"):
            return self.change(update)

    def recover_submissions(self):
        """Normalize abandoned dispatches only while a new effect owner is quiescent.

        The caller already holds lifetime ownership, proving no prior child still runs.
        Worker exit does not prove non-issuance, so unknown expiry remains pinned.
        """
        state = self.read()
        if not any(a.state == "submitted" for a in (*state.registrations, *state.credentials)):
            return state

        def update(current):
            """Retain every dispatch and consumed review while marking its uncertainty."""
            candidates = {a.candidate_id for a in current.registrations if a.state == "submitted"}
            return current.model_copy(
                update={
                    "registrations": tuple(
                        a.model_copy(update={"state": "uncertain", "reason": "creation_uncertain"})
                        if a.state == "submitted"
                        else a
                        for a in current.registrations
                    ),
                    "credentials": tuple(
                        i.model_copy(update={"state": "uncertain", "reason": "issuance_unresolved"})
                        if i.state == "submitted"
                        else i
                        for i in current.credentials
                    ),
                    "candidates": tuple(
                        c.model_copy(
                            update={
                                "state": "blocked",
                                "reason": "creation_uncertain",
                                "revision": c.revision + 1,
                            }
                        )
                        if c.candidate_id in candidates
                        else c
                        for c in current.candidates
                    ),
                }
            )

        return self.change(update, revision=state.revision)
