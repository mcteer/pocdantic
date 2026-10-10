"""Bounded process-local browser contexts and authenticated sessions.

Opaque cookies are indexed by digest. Credentials stay in memory and are rotated
into a fresh session after login. Closing contains work before asynchronous draining;
secrets are discarded only after that work can no longer use them.
"""

import asyncio
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from agent.security import SecurityError


def opaque():
    """Generate an unpredictable URL-safe cookie or CSRF token."""
    return secrets.token_urlsafe(32)


def digest(value):
    """Hash an opaque cookie for lookup without using its raw value as a registry key."""
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(repr=False)
class LoginAttempt:
    state: str
    nonce: str
    verifier: str
    deadline: float


@dataclass(repr=False)
class Browser:
    cookie: str = field(default_factory=opaque)
    csrf: str = field(default_factory=opaque)
    deadline: float = 0
    attempt: LoginAttempt | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    login_error: str | None = None


@dataclass(repr=False)
class Session(Browser):
    credentials: Any = None
    state: str = "active"
    created: float = 0
    touched: float = 0
    jobs: dict = field(default_factory=dict)
    submissions: dict = field(default_factory=dict)


class SessionStore:
    def __init__(self, *, clock=time.monotonic):
        """Initialize bounded browser/session registries and cleanup tracking."""
        self.clock, self.browsers, self.sessions = clock, {}, {}
        self.on_close = None
        self.subject_held = None
        self.drains = set()

    def prune(self):
        """Expire stale bootstrap contexts and close sessions past idle or absolute
        deadlines.
        """
        now = self.clock()
        for key, b in list(self.browsers.items()):
            if b.deadline <= now:
                del self.browsers[key]
        for s in list(self.sessions.values()):
            if (
                self.subject_held
                and s.credentials
                and self.subject_held(
                    s.credentials.principal.issuer, s.credentials.principal.subject
                )
            ):
                self.close(s)
            if s.state not in {"closing", "closed"} and (
                now - s.touched >= 1800 or now - s.created >= 28800
            ):
                self.close(s)

    def bootstrap(self, cookie):
        """Reuse an eligible browser context or create one within the bootstrap capacity
        bound.
        """
        self.prune()
        key = digest(cookie) if cookie else ""
        if key in self.browsers:
            return self.browsers[key]
        if len(self.browsers) >= 16:
            raise SecurityError("capacity_exceeded")
        b = Browser(deadline=self.clock() + 300)
        self.browsers[digest(b.cookie)] = b
        return b

    def session(self, cookie):
        """Resolve a cookie to its current server-held session after expiry checks."""
        self.prune()
        s = self.sessions.get(digest(cookie)) if cookie else None
        return s if s and s.state not in {"closing", "closed"} else None

    def authenticate(self, browser, credentials):
        """Rotate a completed browser login into a new authenticated session and cookie."""
        self.prune()
        if self.subject_held and self.subject_held(
            credentials.principal.issuer, credentials.principal.subject
        ):
            raise SecurityError("contained")
        if len(self.sessions) >= 4:
            raise SecurityError("capacity_exceeded")
        self.browsers.pop(digest(browser.cookie), None)
        now = self.clock()
        # Rotate cookie/CSRF so a bootstrap handle never becomes an authenticated handle.
        s = Session(credentials=credentials, created=now, touched=now)
        self.sessions[digest(s.cookie)] = s
        return s

    def touch(self, session):
        """Update session activity without extending its absolute lifetime."""
        session.touched = self.clock()

    def close(self, session):
        """Mark a session closing and contain its work before scheduling credential
        cleanup.
        """
        if session.state in {"closing", "closed"}:
            return
        session.state = "closing"
        if self.on_close:
            # The hook invalidates/contains synchronously before returning its drain coroutine.
            drain = self.on_close(session)
            task = asyncio.create_task(self._finish(session, drain))
            self.drains.add(task)
            task.add_done_callback(self.drains.discard)
        else:
            self._discard(session)

    async def _finish(self, session, drain):
        """Await the run-manager drain, then discard session credentials and registry
        entries.
        """
        if drain:
            await drain
        self._discard(session)

    def _discard(self, session):
        """Clear private credentials, jobs, and submission keys once draining has
        completed.
        """
        session.credentials = None
        session.jobs.clear()
        session.submissions.clear()
        session.state = "closed"
        self.sessions.pop(digest(session.cookie), None)

    async def shutdown(self):
        """Close all sessions, await their cleanup tasks, and clear remaining browser
        contexts.
        """
        for s in list(self.sessions.values()):
            self.close(s)
        if self.drains:
            await asyncio.gather(*self.drains, return_exceptions=True)
        self.browsers.clear()
