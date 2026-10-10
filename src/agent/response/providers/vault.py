"""Exact enrolled Vault controls with separate bounded metadata readback.

Administrative authority comes only from Settings. Resource IDs come from immutable
bindings; no broad listing, credential read, entity disable or mutation replay occurs.
"""

from urllib.parse import quote

from .common import Result, acknowledged, request
from .models import require


class VaultAdapter:
    """Apply registration, service-accessor and isolated static-role operations."""

    def __init__(self, settings, http):
        """Retain trusted authority and an injected bounded HTTP transport privately."""
        self.settings, self.http = settings, http

    async def execute(self, action, *, read_only=False):
        """Mutate one exact enrolled resource or observe metadata without fetching secrets."""
        binding = action.binding
        require(
            self.settings.vault_addr is not None and self.settings.vault_token is not None,
            "missing_authority",
        )
        require(
            self.settings.vault_addr.rstrip("/") == binding.origin.rstrip("/")
            and (self.settings.vault_namespace or "") == binding.namespace,
            "provider_policy_changed",
        )
        headers = {"X-Vault-Token": self.settings.vault_token.get_secret_value()}
        if binding.namespace:
            headers["X-Vault-Namespace"] = binding.namespace
        native = quote(binding.native_id, safe="")
        body = None
        if action.kind == "block_registration":
            path = f"agent-registry/registration/id/{native}"
            method = "GET" if read_only else "DELETE"
            proof_path = "registration"
        elif action.kind == "revoke_native_token":
            require(
                binding.token_type == "service"
                and binding.exclusive_tree
                and binding.ownership is not None,
                "unsupported",
            )
            path = "auth/token/lookup-accessor" if read_only else "auth/token/revoke-accessor"
            method, body, proof_path = (
                "POST",
                {"accessor": binding.native_id},
                "native_token_readback",
            )
        elif action.kind == "rotate_static":
            require(binding.isolated and binding.mount is not None, "unsupported")
            path = (
                f"{binding.mount}/static-roles/{native}"
                if read_only
                else f"{binding.mount}/rotate-role/{native}"
            )
            method, proof_path = ("GET" if read_only else "POST"), None
        else:
            require(False, "unsupported")
        status, data, fingerprint = await request(
            self.http, method, f"{binding.origin.rstrip('/')}/v1/{path}", headers=headers, body=body
        )
        if read_only:
            absent = (
                status == 404
                if action.kind == "block_registration"
                else (
                    status == 400
                    and isinstance(data, dict)
                    and data.get("errors") == ["invalid accessor"]
                )
            )
            return Result(
                state="reconciled" if absent else "acknowledged",
                reason="provider_reconciled" if absent else "proof_required",
                path=proof_path,
                proof="proven" if absent else "inconclusive",
                source_digest=fingerprint,
            )
        # A successful control request is deliberately not a same-JWT or DB proof.
        return acknowledged(status, fingerprint)

    async def readiness(self, binding):
        """Read exact metadata and self-capabilities without credential or control issuance."""
        import hashlib
        import re

        from agent.recovery.models import now
        from agent.response.models import ResponseError
        from agent.validation.models import canonical

        fingerprints = []
        try:
            require(self.settings.vault_addr and self.settings.vault_token, "missing_authority")
            require(
                (self.settings.vault_addr.rstrip("/"), self.settings.vault_namespace or "")
                == (binding.origin.rstrip("/"), binding.namespace),
                "provider_policy_changed",
            )
            headers = {"X-Vault-Token": self.settings.vault_token.get_secret_value()}
            if binding.namespace:
                headers["X-Vault-Namespace"] = binding.namespace

            async def read(path, method="GET", body=None):
                """Read one compiled metadata target and retain only its private fingerprint."""
                status, data, fingerprint = await request(
                    self.http, method, f"{binding.origin}/v1/{path}", headers=headers, body=body
                )
                require(
                    status == 200, "missing_authority" if status in {401, 403} else "unsupported"
                )
                require(isinstance(data, dict), "unsupported")
                fingerprints.append(fingerprint)
                return data.get("data", data)

            native = quote(binding.native_id, safe="")
            if binding.kind == "registration":
                require(binding.oauth_profile is not None, "mapping_missing")
                health = await read("sys/health")
                version = re.fullmatch(
                    r"(\d+)\.(\d+)\.(\d+)\+ent.*", str(health.get("version", ""))
                )
                require(
                    version
                    and tuple(map(int, version.groups())) >= (2, 1, 0)
                    and not health.get("sealed", True),
                    "unsupported",
                )
                path = f"agent-registry/registration/id/{native}"
                metadata = await read(path)
                require(
                    metadata.get("id") == binding.native_id
                    and metadata.get("entity_id") == binding.entity_id,
                    "mapping_missing",
                )
                entity = await read(f"identity/entity/id/{quote(binding.entity_id, safe='')}")
                require(
                    entity.get("id") == binding.entity_id
                    and any(
                        alias.get("external_id") == binding.actor_subject
                        and str(alias.get("issuer", "")).rstrip("/").lower()
                        == binding.actor_issuer.rstrip("/").lower()
                        for alias in entity.get("aliases", [])
                        if isinstance(alias, dict)
                    ),
                    "mapping_missing",
                )
                profile = await read(f"sys/config/oauth-resource-server/{binding.oauth_profile}")
                require(
                    profile.get("enabled") is True
                    and str(profile.get("issuer_id", "")).rstrip("/").lower()
                    == binding.actor_issuer.rstrip("/").lower()
                    and self.settings.vault_audience in profile.get("audiences", []),
                    "mapping_missing",
                )
                needed = {path: {"read", "delete"}}
            elif binding.kind == "static_role":
                require(binding.mount and binding.isolated, "mapping_missing")
                path = f"{binding.mount}/static-roles/{native}"
                metadata = await read(path)
                require(
                    metadata.get("username") == binding.username
                    and metadata.get("db_name")
                    and (metadata.get("rotation_period") or metadata.get("rotation_schedule")),
                    "mapping_missing",
                )
                needed = {path: {"read"}, f"{binding.mount}/rotate-role/{native}": {"update"}}
            elif binding.kind == "native_token":
                require(
                    binding.token_type == "service"
                    and binding.exclusive_tree
                    and binding.ownership,
                    "unsupported",
                )
                needed = {
                    "auth/token/lookup-accessor": {"update"},
                    "auth/token/revoke-accessor": {"update"},
                }
            else:
                require(False, "unsupported")
            caps = await read("sys/capabilities-self", "POST", {"paths": list(needed)})
            require(
                all(
                    expected
                    <= set(caps.get(path, caps.get("capabilities", []) if len(needed) == 1 else []))
                    or "root" in caps.get(path, caps.get("capabilities", []))
                    for path, expected in needed.items()
                ),
                "missing_authority",
            )
            result = "supported"
        except ResponseError as error:
            result = "unsupported" if str(error) == "unsupported" else "missing_authority"
        fingerprint = hashlib.sha256(canonical(fingerprints)).hexdigest()
        return type(binding).model_validate(
            binding.model_dump()
            | {"capability": result, "capability_digest": fingerprint, "checked_at": now()}
        )

    async def dynamic_readiness(self, policy):
        """Compare installed exact dynamic-role revocation SQL with its private operator review.

        Read only role metadata using administrative authority. The digest confirms the
        reviewed configuration is still installed; it does not execute SQL or certify
        that existing sessions will be terminated. No legacy DB attribution is inferred.
        """
        import hashlib

        from agent.response.models import ResponseError
        from agent.validation.models import canonical
        from agent.vault import validate_path

        settings = self.settings
        try:
            require(settings.vault_addr and settings.vault_token, "missing_authority")
            path = validate_path(settings.vault_read_path)
            mount, separator, role = path.rpartition("/creds/")
            require(separator and mount and role and "/" not in role, "mapping_missing")
            headers = {"X-Vault-Token": settings.vault_token.get_secret_value()}
            if settings.vault_namespace:
                headers["X-Vault-Namespace"] = settings.vault_namespace
            status, data, _ = await request(
                self.http,
                "GET",
                f"{settings.vault_addr.rstrip('/')}/v1/{mount}/roles/{role}",
                headers=headers,
            )
            require(status == 200 and isinstance(data, dict), "missing_authority")
            statements = data.get("data", {}).get("revocation_statements")
            require(
                isinstance(statements, list)
                and 0 < len(statements) <= 16
                and all(isinstance(s, str) and 0 < len(s) <= 16384 for s in statements),
                "mapping_missing",
            )
            fingerprint = hashlib.sha256(canonical(statements)).hexdigest()
            require(policy.dynamic_revocation_review_digest == fingerprint, "proof_required")
            return "provider_state_observed"
        except ResponseError as error:
            return str(error)
