"""Trusted acquisition lifecycle with effect ownership retained through cleanup.

Write intent before sending, capture a handle before SQL, and resolve only after a
successful synchronous cleanup is durably recorded. Persistence failure never skips
best-effort cleanup of a handle already held in memory.
"""

from .models import Receipt
from .store import RecoveryError


class CredentialLifecycle:
    def __init__(self, store, owner, observer=None, *, on_completed=None):
        """Bind one acquisition to explicit effect ownership and an optional private observer."""
        self.store, self.owner, self.observer = store, owner, observer
        self.on_completed = on_completed
        self.item = None
        self.failure = False

    def start(self):
        """Durably reserve the acquisition before the credential HTTP request is sent."""
        self.item = self.store.begin(self.owner)
        if self.observer:
            self.observer.fact("recovery_incident", incident_id=self.item.incident_id)
        return self.item.operation_id

    def acquired(self, handle, native_request_id=None):
        """Persist the exact handle before returning usable credentials to SQL callers."""
        try:
            self.item = self.store.update(
                self.item.incident_id,
                self.item.revision,
                state="acquired",
                lease_handle=handle,
                native_request_id=native_request_id,
                reason_code="cleanup_unconfirmed",
            )
        except BaseException:
            self.failure = True
            raise

    def pending(self):
        """Record cleanup intent when storage remains valid; failure does not cancel cleanup."""
        try:
            self.item = self.store.update(
                self.item.incident_id,
                self.item.revision,
                state="cleanup_pending",
                reason_code="cleanup_unconfirmed",
            )
        except Exception:
            self.failure = True

    def uncertain(self, reason="acquisition_uncertain"):
        """Keep ambiguous issuance or cleanup unresolved without inventing a terminal receipt."""
        if not self.item or self.item.state == "resolved":
            return
        try:
            self.item = self.store.update(
                self.item.incident_id, self.item.revision, state="unresolved", reason_code=reason
            )
        except Exception:
            self.failure = True

    def completed(self):
        """Commit trusted synchronous cleanup proof before reporting operational completion."""
        if self.failure:
            raise RecoveryError()
        receipt = Receipt(
            outcome="revoked",
            incident_id=self.item.incident_id,
            incident_revision=self.item.revision,
            operation_id=self.item.operation_id,
            environment_digest=self.item.environment_digest,
        )
        try:
            self.item = self.store.update(
                self.item.incident_id,
                self.item.revision,
                state="resolved",
                resolution="revoked",
                receipt=receipt,
            )
            self.owner.used = False
        except Exception:
            self.failure = True
            raise

        if self.on_completed:
            self.on_completed()
        elif self.observer:
            self.observer.record("cleanup", "revoked")
