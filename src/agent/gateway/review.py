"""Owner-only immutable control decisions and content-free attempt storage.

All paths are anchored to private directory descriptors. Reads never create state, and a
rejection never needs evidence or model credentials. These are local operator attestations,
not remote-policy authentication.
"""

import fcntl
import json
import os
import re
import stat
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from .config import digest, safe_name
from .models import ControlReview, EvidenceBundle, GatewayError, ModelAttempt, ReviewPointer, now


def checked(info, *, directory=False):
    """Refuse other owners, non-private permissions, links and unexpected file kinds."""
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (
        not valid
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or (not directory and info.st_nlink != 1)
    ):
        raise GatewayError("gateway_review_required")


class ReviewStore:
    """Private local Gateway state beneath a canonical trusted deployment root."""

    def __init__(self, root=None):
        """Accept a trusted test root or discover the canonical production root."""
        from agent.project import require_root

        self.root = Path(root) if root is not None else require_root()
        if not self.root.is_absolute() or self.root.resolve() != self.root:
            raise GatewayError("gateway_review_required")

    @contextmanager
    def directory(self, *, create=False):
        """Anchor private components without following links or writing during reads."""
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name in (".local", "gateway"):
                if create:
                    try:
                        os.mkdir(name, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                checked(os.fstat(fd), directory=True)
            yield fd
        except (OSError, ValueError):
            raise GatewayError("gateway_review_required") from None
        finally:
            os.close(fd)

    @staticmethod
    def read(fd, name, limit):
        """Read one bounded private regular file through an anchored descriptor."""
        if not safe_name(name):
            raise GatewayError("gateway_review_required")
        handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(handle)
            checked(info)
            if info.st_size > limit:
                raise GatewayError("gateway_review_required")
            raw = os.read(handle, limit + 1)
            after = os.fstat(handle)
            if len(raw) > limit or (
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) != (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns):
                raise GatewayError("gateway_review_required")
            return raw
        finally:
            os.close(handle)

    @staticmethod
    def write(fd, name, raw, *, replace=False):
        """Fsync a private immutable file or atomically replace the selected pointer."""
        if not safe_name(name):
            raise GatewayError("gateway_review_required")
        target = f"{uuid4()}.tmp" if replace else name
        handle = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
        )
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if replace:
                os.replace(target, name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            if replace:
                try:
                    os.unlink(target, dir_fd=fd)
                except FileNotFoundError:
                    pass

    def current(self):
        """Load exactly the pointer-selected immutable record; never sort filenames."""
        try:
            with self.directory() as fd:
                pointer = ReviewPointer.model_validate_json(self.read(fd, "current.json", 4096))
                review = ControlReview.model_validate_json(
                    self.read(fd, f"{pointer.review_id}.json", 65536)
                )
                if review.review_id != pointer.review_id:
                    raise GatewayError("gateway_review_required")
                return review
        except Exception:
            raise GatewayError("gateway_review_required") from None

    def evidence(self, directory):
        """Validate the full bounded manifest, never treating synthetic evidence as live."""
        if not safe_name(directory):
            raise GatewayError("gateway_review_required")
        try:
            with self.directory() as fd:
                child = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    checked(os.fstat(child), directory=True)
                    raw = self.read(child, "bundle.json", 1024 * 1024)
                    bundle = EvidenceBundle.model_validate_json(raw)
                    total = 0
                    for name, expected in bundle.manifest.items():
                        data = self.read(child, name, 8 * 1024 * 1024)
                        total += len(data)
                        if total > 32 * 1024 * 1024 or digest(data) != expected:
                            raise GatewayError("gateway_review_required")
                    return bundle, digest(raw)
                finally:
                    os.close(child)
        except Exception:
            raise GatewayError("gateway_review_required") from None

    def admit(self, expected):
        """Require fresh approval of unchanged private evidence and transport bindings."""
        review = self.current()
        if review.decision != "approved" or review.expires_at <= now():
            raise GatewayError("gateway_review_required")
        if any(getattr(review, key) != value for key, value in expected.items()):
            raise GatewayError("gateway_review_required")
        bundle, observed = self.evidence(review.evidence_directory)
        if observed != review.evidence_digest or bundle.administration != review.administration:
            raise GatewayError("gateway_review_required")
        return review

    def commit(self, review, *, expected=...):
        """Serialize pointer updates and reject concurrent approval/rejection changes."""
        try:
            with self.directory(create=True) as fd:
                lock = os.open(
                    "control.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd
                )
                try:
                    checked(os.fstat(lock))
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    try:
                        prior = self.current().review_id
                    except GatewayError:
                        prior = None
                    if expected is not ... and prior != expected:
                        raise GatewayError("gateway_review_required")
                    if review.decision == "approved":
                        _, current = self.evidence(review.evidence_directory)
                        if current != review.evidence_digest:
                            raise GatewayError("gateway_review_required")
                    self.write(fd, f"{review.review_id}.json", review.model_dump_json().encode())
                    pointer = ReviewPointer(review_id=review.review_id)
                    self.write(fd, "current.json", pointer.model_dump_json().encode(), replace=True)
                finally:
                    os.close(lock)
            return review
        except Exception:
            raise GatewayError("gateway_review_required") from None

    def reject(self, reviewer):
        """Disable subsequent dispatch without credentials, evidence or an expiring approval."""
        return self.commit(ControlReview(decision="rejected", reviewer=reviewer))

    def approve(self, directory, reviewer, expected, required_cases, hours=24):
        """Approve only exact complete live evidence, rechecked under the commit lock."""
        try:
            prior = self.current().review_id
        except GatewayError:
            prior = None
        bundle, evidence_digest = self.evidence(directory)
        if (
            bundle.source != "live"
            or any(getattr(bundle, k) != v for k, v in expected.items())
            or not 0 < hours <= 24
        ):
            raise GatewayError("gateway_review_required")
        observations = (*bundle.controls.values(), *bundle.observations)
        case_ids = [o.case_id for o in bundle.observations]
        if (
            any(o.disposition != "pass" for o in observations)
            or len(set(case_ids)) != len(case_ids)
            or set(case_ids) != set(required_cases)
        ):
            raise GatewayError("gateway_review_required")
        observed = min(o.observed_at for o in observations)
        review = ControlReview(
            decision="approved",
            administration=bundle.administration,
            reviewer=reviewer,
            observed_at=observed,
            expires_at=min(now() + timedelta(hours=hours), observed + timedelta(hours=24)),
            evidence_digest=evidence_digest,
            evidence_directory=directory,
            control_revision=bundle.control_revision,
            error_signatures=bundle.error_signatures,
            **expected,
        )
        return self.commit(review, expected=prior)

    def register(self, policy, policy_digest):
        """Persist the private route/model join once; reject a conflicting existing registry."""
        raw = json.dumps(
            {"gateway_policy_digest": policy_digest, "route_policy": policy.model_dump()},
            sort_keys=True,
        ).encode()
        name = f"route-{policy_digest}.json"
        try:
            with self.directory(create=True) as fd:
                try:
                    current = self.read(fd, name, 16384)
                except FileNotFoundError:
                    try:
                        self.write(fd, name, raw)
                    except FileExistsError:
                        current = self.read(fd, name, 16384)
                    else:
                        current = raw
                if current != raw:
                    raise GatewayError("gateway_observation_failed")
        except Exception:
            raise GatewayError("gateway_observation_failed") from None

    def record(self, event):
        """Persist one immutable bounded metadata event before dispatch or after completion."""
        try:
            raw = event.model_dump_json().encode()
            if len(raw) > 4096:
                raise ValueError()
            with self.directory(create=True) as fd:
                self.write(fd, f"{event.attempt_id}-{event.stage}.json", raw)
        except Exception:
            raise GatewayError("gateway_observation_failed") from None

    def attempts(self):
        """Read bounded attempt summaries without replay or modifying unfinished events.

        Missing terminal evidence means unknown, including during an active request.
        It never means success, failure, or permission to retry after a process crash.
        """
        grouped = {}
        try:
            with self.directory() as fd, os.scandir(fd) as entries:
                count = 0
                for entry in entries:
                    if not re.fullmatch(
                        r"[a-f0-9-]{36}-(admitted|dispatched|completed|denied|failed|cancelled|unknown)\.json",
                        entry.name,
                    ):
                        continue
                    count += 1
                    if count > 4096:
                        raise GatewayError("gateway_observation_failed")
                    event = ModelAttempt.model_validate_json(self.read(fd, entry.name, 4096))
                    if entry.name != f"{event.attempt_id}-{event.stage}.json":
                        raise GatewayError("gateway_observation_failed")
                    grouped.setdefault(event.attempt_id, []).append(event)
        except FileNotFoundError:
            return ()
        except Exception:
            raise GatewayError("gateway_observation_failed") from None
        result = []
        for events in grouped.values():
            terminal = [e for e in events if e.stage not in ("admitted", "dispatched")]
            if len(terminal) > 1:
                raise GatewayError("gateway_observation_failed")
            if terminal:
                result.append(terminal[0])
            else:
                latest = next((e for e in events if e.stage == "dispatched"), events[0])
                result.append(latest.model_copy(update={"stage": "unknown"}))
        return tuple(result)
