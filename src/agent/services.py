from dataclasses import dataclass, field

import httpx

from .approval import Approval, ApprovalOutcome
from .capabilities import Dependencies
from .oauth import OAuthClient
from .probe import oauth_config
from .schemas import Action
from .security import SecurityError
from .settings import Settings
from .verify import VerifyClient, identifier


@dataclass(frozen=True)
class VerifyApprovalBackend:
    settings: Settings = field(repr=False)

    async def __call__(
        self, deps: Dependencies, approval: Approval, action: Action
    ) -> ApprovalOutcome:
        s = self.settings
        if not s.verify_tenant_url or not s.verify_authenticator_id or not s.verify_user_id:
            raise SecurityError("verify_approval_configuration_missing")
        if deps.principal.subject != s.verify_user_id:
            raise SecurityError("verify_approver_mapping_mismatch")
        async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False) as http:
            token = await OAuthClient(oauth_config(s, api=True), http).client_credentials()
            client = VerifyClient(
                s.verify_tenant_url, token.access_token, http, operation_observer=deps.observer
            )
            device = await client.request(
                "GET", "v1.0/authenticators/" + identifier(s.verify_authenticator_id)
            )
            if (
                device.get("owner") != deps.principal.subject
                or not device.get("enabled")
                or device.get("state") != "ACTIVE"
            ):
                raise SecurityError("verify_device_owner_mismatch")
            data = await client.request("GET", "v1.0/authnmethods/signatures")
            factors = [
                item
                for item in data.get("signatures", [])
                if item.get("enabled")
                and item.get("validated")
                and item.get("owner") == deps.principal.subject
                and item.get("attributes", {}).get("authenticatorId") == s.verify_authenticator_id
                and item.get("subType") == "userPresence"
            ]
            if len(factors) != 1:
                raise SecurityError("verify_signing_factor_missing")
            deps.check_containment()
            transaction = await client.initiate(
                s.verify_authenticator_id, factors[0]["id"], approval, action
            )
            return await client.wait_for_outcome(
                s.verify_authenticator_id, transaction, approval, deps.approvals
            )
