import asyncio
import json
import re
import time
from urllib.parse import urlparse

import httpx
from pydantic import SecretStr

from .approval import Approval, ApprovalStore
from .schemas import Action
from .security import SecurityError


def identifier(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
        raise SecurityError("verify_identifier_invalid")
    return value


class VerifyClient:
    """Private API responses never pass directly to agent or telemetry."""

    def __init__(self, tenant: str, token: SecretStr, http: httpx.AsyncClient):
        parsed = urlparse(tenant)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise SecurityError("verify_https_required")
        self.tenant, self.token, self.http = tenant.rstrip("/"), token, http

    async def request(
        self, method: str, path: str, *, body: dict | None = None, params: dict | None = None
    ) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*", path):
            raise SecurityError("verify_path_invalid")
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
            return response.json()
        except (httpx.HTTPError, ValueError, TypeError):
            raise SecurityError("verify_request_failed") from None

    async def authenticators(self) -> dict:
        return await self.request("GET", "v1.0/authenticators")

    async def initiate(
        self, authenticator_id: str, factor_id: str, approval: Approval, action: Action
    ) -> str:
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
        try:
            return identifier(data["id"])
        except (KeyError, TypeError):
            raise SecurityError("verify_transaction_invalid") from None

    async def wait_for_decision(
        self,
        authenticator_id: str,
        transaction_id: str,
        approval: Approval,
        store: ApprovalStore,
        *,
        timeout: float = 120,
        poll: float = 2,
    ) -> bool:
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
                store.record_decision(
                    approval.id,
                    approved=True,
                    approver=approval.subject,
                    source_event=transaction_id,
                )
                return True
            if state in {
                "DENIED",
                "FAILED",
                "CANCELED",
                "TIMEOUT",
                "VERIFY_FAILED",
                "VERIFY_DENIED",
                "EXPIRED",
            }:
                store.record_decision(
                    approval.id,
                    approved=False,
                    approver=approval.subject,
                    source_event=transaction_id,
                )
                return False
            if state not in {"PENDING", "VERIFY_PENDING"}:
                raise SecurityError("verify_transaction_state")
            await asyncio.sleep(min(poll, max(0, deadline - time.monotonic())))
        return False
