"""Exact Verify tenant user and login-session controls.

These operations affect this tenant only. API-client authority is separate from actor
and human credentials; no upstream IBMid suspension or global logout is inferred.
"""

from urllib.parse import quote

from agent.oauth import OAuthClient
from agent.probe import oauth_config

from .common import Result, acknowledged, request
from .models import require


class VerifyAdapter:
    """Apply fixed SCIM suspension or exact tenant session revocation."""

    def __init__(self, settings, http):
        """Retain trusted administrative configuration and bounded injected HTTP."""
        self.settings, self.http = settings, http

    async def execute(self, action, *, read_only=False):
        """Dispatch one exact user operation, or read independent tenant state."""
        binding = action.binding
        require(
            binding.kind == "user" and binding.user_issuer and binding.user_subject,
            "mapping_missing",
        )
        require(
            self.settings.verify_tenant_url is not None
            and self.settings.verify_tenant_url.rstrip("/") == binding.origin.rstrip("/"),
            "provider_policy_changed",
        )
        require(
            self.settings.verify_api_client_id and self.settings.verify_api_client_secret,
            "missing_authority",
        )
        token = await OAuthClient(
            oauth_config(self.settings, api=True), self.http
        ).client_credentials()
        headers = {"Authorization": "Bearer " + token.access_token.get_secret_value()}
        native = quote(binding.native_id, safe="")
        body = None
        if action.kind == "suspend_user":
            path, method, proof_path = (
                f"v2.0/Users/{native}",
                "GET" if read_only else "PATCH",
                "tenant_user",
            )
            if not read_only:
                body = {
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [
                        {"op": "replace", "path": "active", "value": False},
                        {
                            "op": "add",
                            "path": (
                                "urn:ietf:params:scim:schemas:extension:ibm:2.0:"
                                "Notification:notifyType"
                            ),
                            "value": "NONE",
                        },
                    ],
                }
        else:
            require(action.kind == "revoke_user_sessions", "unsupported")
            path, method, proof_path = (
                f"v1.0/auth/sessions/{native}",
                "GET" if read_only else "DELETE",
                "tenant_session_readback",
            )
        status, data, fingerprint = await request(
            self.http, method, f"{binding.origin.rstrip('/')}/{path}", headers=headers, body=body
        )
        if not read_only:
            return acknowledged(status, fingerprint)
        proven = status == 200 and (
            isinstance(data, dict)
            and data.get("id") == binding.native_id
            and data.get("active") is False
            if action.kind == "suspend_user"
            else isinstance(data, list) and not data
        )
        return Result(
            state="reconciled" if proven else "acknowledged",
            reason="provider_reconciled" if proven else "proof_required",
            path=proof_path,
            proof="proven" if proven else "inconclusive",
            source_digest=fingerprint,
        )

    async def readiness(self, binding, review):
        """Read exact user/session metadata using independently reviewed tenant permissions.

        The API-client detail endpoint may return its secret, so readiness deliberately
        avoids it. Permission evidence is a sanitized private administrative review;
        neither that review nor metadata availability is proof of live enforcement.
        """
        import hashlib

        from agent.recovery.models import now
        from agent.validation.models import canonical

        fingerprints = []
        try:
            require(
                (
                    review.tenant_origin,
                    review.api_client_id,
                    review.user_id,
                    review.issuer,
                    review.subject,
                )
                == (
                    binding.origin,
                    self.settings.verify_api_client_id,
                    binding.native_id,
                    binding.user_issuer,
                    binding.user_subject,
                ),
                "mapping_missing",
            )
            require(0 <= (now() - review.reviewed_at).total_seconds() <= 300, "missing_authority")
            require(
                "listSessions" in review.entitlements
                and bool({"manageLoginSessions", "revokeAllSessions"} & review.entitlements)
                and bool(
                    {
                        "manageUsers",
                        "updateAnyUser",
                        "manageUserGroups",
                        "manageAllUserGroups",
                        "manageUserStandardGroups",
                        "manageUsersInStandardGroups",
                    }
                    & review.entitlements
                ),
                "missing_authority",
            )
            require(self.settings.verify_tenant_url == binding.origin, "provider_policy_changed")
            token = await OAuthClient(
                oauth_config(self.settings, api=True), self.http
            ).client_credentials()
            headers = {"Authorization": "Bearer " + token.access_token.get_secret_value()}
            for path in (
                f"v2.0/Users/{quote(binding.native_id, safe='')}",
                f"v1.0/auth/sessions/{quote(binding.native_id, safe='')}",
            ):
                status, data, fingerprint = await request(
                    self.http, "GET", f"{binding.origin}/{path}", headers=headers
                )
                require(status == 200, "missing_authority")
                fingerprints.append(fingerprint)
                if "Users" in path:
                    require(
                        isinstance(data, dict)
                        and data.get("id") == binding.native_id
                        and type(data.get("active")) is bool,
                        "mapping_missing",
                    )
                else:
                    require(isinstance(data, list), "unsupported")
            result = "supported"
        except Exception:
            result = "missing_authority"
        return type(binding).model_validate(
            binding.model_dump()
            | {
                "capability": result,
                "capability_digest": hashlib.sha256(canonical(fingerprints)).hexdigest(),
                "checked_at": now(),
                "entitlement_digest": hashlib.sha256(canonical(review)).hexdigest(),
            }
        )
