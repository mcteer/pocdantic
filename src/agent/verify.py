"""Verify push transactions bound to an exact approval and action digest.

Only a precise decision for the initiated transaction can satisfy approval. Provider
errors and ambiguous outcomes remain unconfirmed, and raw responses stay private.
"""

import asyncio
import json
import re
import time
from urllib.parse import urlparse

import httpx
from pydantic import SecretStr

from .approval import Approval, ApprovalOutcome, ApprovalStore
from .schemas import Action
from .security import SecurityError


def identifier(value: str) -> str:
    """Validate a provider identifier before interpolating it into an API path."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
        raise SecurityError("verify_identifier_invalid")
    return value


class VerifyClient:
    """Private API responses never pass directly to agent or telemetry."""

    def __init__(
        self, tenant: str, token: SecretStr, http: httpx.AsyncClient, *, operation_observer=None
    ):
        """Bind a validated tenant URL, API token, HTTP client, and optional private
        observer.
        """
        parsed = urlparse(tenant)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise SecurityError("verify_https_required")
        self.tenant, self.token, self.http = tenant.rstrip("/"), token, http
        self.operation_observer = operation_observer
        self._last_response = b""
        self.approval_context = None
        self.last_decision = None

    async def request(
        self, method: str, path: str, *, body: dict | None = None, params: dict | None = None
    ) -> dict:
        """Call the bounded Verify API with safe errors and private operation bindings."""
        if not re.fullmatch(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*", path):
            raise SecurityError("verify_path_invalid")
        observer = self.operation_observer
        binding = None
        if observer and observer.validation_id and observer.observation_id:
            binding = observer.begin_operation(
                validation_id=observer.validation_id,
                observation_id=observer.observation_id,
                phase="approval",
                source_kind="verify",
                source_instance=self.tenant,
                approval_ref=self.approval_context.id if self.approval_context else None,
                action_digest=self.approval_context.digest if self.approval_context else None,
            )
        if observer and observer.failed:
            raise SecurityError("storage_error")
        try:
            response = await self.http.request(
                method,
                self.tenant + "/" + path,
                headers={
                    "Authorization": "Bearer " + self.token.get_secret_value(),
                    "Accept": "application/json",
                },
                json=body,
                params=params,
            )
            if response.status_code >= 300:
                raise SecurityError(f"verify_http_{response.status_code}")
            self._last_response = response.content
            data = response.json()
            if binding:
                observer.finish_operation(binding, native_transaction_id=data.get("id"))
                if observer.failed:
                    raise SecurityError("storage_error")
            return data
        except (httpx.HTTPError, ValueError, TypeError):
            raise SecurityError("verify_request_failed") from None

    def capture_transaction(self, approval, data, approved):
        """Save raw and normalized transaction evidence only to a supported private sink."""
        self.last_decision = (
            "approved"
            if approved
            else "denied"
            if data.get("state") in {"DENIED", "VERIFY_DENIED", "USER_DENIED"}
            else "unverified"
        )
        observer = self.operation_observer
        if observer and observer.validation_id and observer.observation_id:
            try:
                observer.sink.transaction(
                    observer, self.tenant, approval, data, self._last_response, approved
                )
            except Exception:
                observer.failed = True
                raise SecurityError("storage_error") from None
            if observer.failed:
                raise SecurityError("storage_error")

    async def authenticators(self) -> dict:
        """Read enrolled device inventory; this alone proves neither identity nor consent."""
        return await self.request("GET", "v1.0/authenticators")

    async def initiate(
        self, authenticator_id: str, factor_id: str, approval: Approval, action: Action
    ) -> str:
        """Send a phone prompt containing the bound approval ID and exact-action digest."""
        self.approval_context = approval
        data = await self.request(
            "POST",
            f"v1.0/authenticators/{identifier(authenticator_id)}/verifications",
            body={
                "expiresIn": 120,
                "logic": "OR",
                "authenticationMethods": [{"methodType": "signature", "id": identifier(factor_id)}],
                "pushNotification": {
                    "send": True,
                    "sound": "default",
                    "title": "PoC action approval",
                    "message": f"Approve simulated restart: {action.resource}",
                },
                "transactionData": {
                    "message": f"SIMULATED {action.operation}: {action.resource}",
                    "originIpAddress": "127.0.0.1",
                    "originUserAgent": "pocdantic",
                    "additionalData": [
                        {"name": "approval_id", "value": str(approval.id)},
                        {"name": "action_digest", "value": approval.digest},
                    ],
                },
            },
        )
        if self.operation_observer and self.operation_observer.failed:
            raise SecurityError("storage_error")
        try:
            return identifier(data["id"])
        except (KeyError, TypeError):
            raise SecurityError("verify_transaction_invalid") from None

    async def _wait_for_outcome(
        self,
        authenticator_id: str,
        transaction_id: str,
        approval: Approval,
        store: ApprovalStore,
        *,
        timeout: float = 120,
        poll: float = 2,
    ) -> ApprovalOutcome:
        """Poll the initiated transaction until a bound terminal decision or deadline.

        Validate transaction ownership and approval binding before recording a decision;
        ambiguous failures cannot become a denial or an approval.
        """
        self.approval_context = approval
        deadline = min(approval.expires_at, time.monotonic() + timeout)
        path = (
            f"v1.0/authenticators/{identifier(authenticator_id)}/verifications/"
            f"{identifier(transaction_id)}"
        )
        while time.monotonic() < deadline:
            data = await self.request("GET", path)
            if data.get("id") != transaction_id:
                raise SecurityError("verify_transaction_mismatch")
            # Polling uses authenticated TLS and the exact server-created transaction. Fail closed
            # if transaction binding is absent or altered; do not accept generic MFA success.
            transaction_data = data.get("transactionData", {})
            if isinstance(transaction_data, str):
                try:
                    transaction_data = json.loads(transaction_data)
                except ValueError:
                    raise SecurityError("verify_transaction_data_invalid") from None
            if not isinstance(transaction_data, dict):
                raise SecurityError("verify_transaction_data_invalid")
            binding = {
                x.get("name"): x.get("value") for x in transaction_data.get("additionalData", [])
            }
            if (
                binding.get("approval_id") != str(approval.id)
                or binding.get("action_digest") != approval.digest
            ):
                raise SecurityError("verify_approval_binding")
            state = data.get("state")
            if state in {"SUCCESS", "VERIFY_SUCCESS"}:
                self.capture_transaction(approval, data, True)
                store.record_decision(
                    approval.id,
                    approved=True,
                    approver=approval.subject,
                    source_event=transaction_id,
                )
                return ApprovalOutcome("approved")
            if state in {"DENIED", "VERIFY_DENIED", "USER_DENIED"}:
                self.capture_transaction(approval, data, False)
                store.record_decision(
                    approval.id,
                    approved=False,
                    approver=approval.subject,
                    source_event=transaction_id,
                )
                return ApprovalOutcome("denied")
            if state in {"FAILED", "CANCELED", "TIMEOUT", "VERIFY_FAILED", "EXPIRED"}:
                self.capture_transaction(approval, data, False)
                store.invalidate(approval.id, "unconfirmed")
                return ApprovalOutcome("unconfirmed")
            if state not in {"PENDING", "VERIFY_PENDING"}:
                raise SecurityError("verify_transaction_state")
            await asyncio.sleep(min(poll, max(0, deadline - time.monotonic())))
        store.invalidate(approval.id, "unconfirmed")
        return ApprovalOutcome("unconfirmed")

    async def wait_for_outcome(
        self, authenticator_id, transaction_id, approval, store, **kwargs
    ) -> ApprovalOutcome:
        """Return the precise approval outcome, invalidating pending state on interruption."""
        try:
            return await self._wait_for_outcome(
                authenticator_id, transaction_id, approval, store, **kwargs
            )
        except BaseException:
            store.invalidate(approval.id)
            raise

    async def wait_for_decision(self, *args, **kwargs) -> bool:
        """Compatibility adapter; false does not establish a native denial."""
        return bool(await self.wait_for_outcome(*args, **kwargs))
