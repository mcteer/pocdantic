"""Exact Vault registry and reviewed metadata adapter; never update, list or delete.

A present record can be foreign even when all fields match. Only an acknowledged create
plus exact independent reads can confirm this attempt; reconciliation never resubmits.
"""

import re
from urllib.parse import quote

from .config import binding_digest
from .models import GovernanceError, require, segment_id
from .network import request


def payload(binding):
    """Build only the fixed registration create fields with explicit security defaults."""
    return {
        "display_name": binding.registry_name,
        "entity_id": binding.entity_id,
        "owner": binding.owner,
        "description": binding.purpose,
        "ceiling_policies": list(binding.ceiling_policies),
        "no_default_ceiling_policy": True,
        "optional_authorization_details": False,
    }


class Registry:
    """Keep operator authority private and restrict requests to the exact reviewed origin."""

    def __init__(
        self,
        http,
        operator,
        *,
        entitlement=None,
        audience=None,
        registration_id=None,
        check=lambda: None,
    ):
        """Inject transport and administrative credential; neither comes from an observation."""
        self.http, self.operator = http, operator
        self.entitlement = entitlement
        self.audience = audience
        self.registration_id = registration_id
        self.check = check
        self.acknowledge = None
        require(not http.follow_redirects, "invalid_input")

    async def call(self, binding, method, target, body=None):
        """Use bounded fixed Vault paths and discard upstream bodies on every failure."""
        self.check()
        headers = {"X-Vault-Token": self.operator}
        if binding.namespace:
            headers["X-Vault-Namespace"] = binding.namespace
        try:
            status, value, digest = await request(
                self.http,
                method,
                binding.vault_origin + "/v1/" + target,
                headers=headers,
                body=body,
            )
            require(status not in {401, 403}, "provider_denied")
            require(status in {200, 204, 404}, "effect_uncertain")
            require(isinstance(value, dict), "effect_uncertain")
            self.check()
            return status, value.get("data", value), digest
        except GovernanceError:
            raise
        except Exception:
            raise GovernanceError("effect_uncertain") from None

    async def absence(self, binding):
        """Read exact entity and reserved name; unauthorized/unreachable is never absence."""
        digests = []
        for selector, value in (
            ("entity-id", binding.entity_id),
            ("display-name", binding.registry_name),
        ):
            status, _data, digest = await self.call(
                binding, "GET", f"agent-registry/registration/{selector}/{quote(value, safe='')}"
            )
            require(status == 404, "registry_conflict")
            digests.append(digest)
        return {"absent": True, "digest": binding_digest(digests)}

    def match(self, binding, value):
        """Require every reviewed field and a provider ID; reject implicit provider defaults."""
        require(
            isinstance(value, dict)
            and type(value.get("id")) is str
            and 1 <= len(value["id"]) <= 256,
            "registry_conflict",
        )
        segment_id(value["id"])
        for key, expected in payload(binding).items():
            actual = value.get(key)
            require(type(actual) is type(expected) and actual == expected, "registry_conflict")
        return value["id"]

    async def readback(self, binding, registration_id):
        """Join ID/entity/name reads to the same exact record without broad registry listing."""
        segment_id(registration_id)
        digests = []
        for selector, value in (
            ("id", registration_id),
            ("entity-id", binding.entity_id),
            ("display-name", binding.registry_name),
        ):
            status, data, digest = await self.call(
                binding, "GET", f"agent-registry/registration/{selector}/{quote(value, safe='')}"
            )
            require(
                status == 200 and self.match(binding, data) == registration_id, "registry_conflict"
            )
            digests.append(digest)
        return {"registration_id": registration_id, "digest": binding_digest(digests)}

    async def create(self, binding):
        """Make exactly one POST and confirm every returned binding through independent reads."""
        status, data, digest = await self.call(
            binding, "POST", "agent-registry/register", payload(binding)
        )
        require(status == 200, "creation_uncertain")
        require(
            isinstance(data, dict)
            and type(data.get("id")) is str
            and 1 <= len(data["id"]) <= 256
            and data.get("display_name") == binding.registry_name,
            "registry_conflict",
        )
        registration_id = segment_id(data["id"])
        if self.acknowledge is not None:
            self.acknowledge(registration_id, digest)
        result = await self.readback(binding, registration_id)
        return result | {"source_digest": digest}

    async def reconcile(self, binding, registration_id=None):
        """Report presence without claiming ownership or permitting any repeat creation."""
        if registration_id:
            return await self.readback(binding, registration_id) | {"owned": False}
        status, data, digest = await self.call(
            binding,
            "GET",
            "agent-registry/registration/entity-id/" + quote(binding.entity_id, safe=""),
        )
        if status == 404:
            return {"present": False, "owned": False, "digest": digest}
        registration_id = self.match(binding, data)
        return await self.readback(binding, registration_id) | {"present": True, "owned": False}

    async def metadata(self, binding, *, require_absent=None):
        """Check exact supported metadata, policy contents, alias mapping and SPIFFE role."""

        if require_absent is None:
            require_absent = self.registration_id is None

        async def read(target):
            """Read one compiled metadata target, never a credential endpoint."""
            status, data, _digest = await self.call(binding, "GET", target)
            require(status == 200 and isinstance(data, dict), "missing_authority")
            return data

        self.stage = "enterprise"
        health = await read("sys/health")
        version = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)\+ent.*", str(health.get("version", "")))
        require(
            version
            and tuple(map(int, version.groups())) >= (2, 1, 0)
            and health.get("sealed") is False,
            "unsupported",
        )
        self.stage = "entity"
        entity = await read("identity/entity/id/" + quote(binding.entity_id, safe=""))
        require(
            entity.get("id") == binding.entity_id and entity.get("disabled") is False,
            "bootstrap_mismatch",
        )
        require(
            isinstance(entity.get("policies", []), list)
            and "root" not in entity.get("policies", [])
            and set(entity.get("policies", [])) <= binding.policies.keys()
            and not any(
                entity.get(name)
                for name in ("direct_group_ids", "inherited_group_ids", "group_ids")
            ),
            "configuration_changed",
        )
        self.stage = "alias"
        aliases = [
            a
            for a in entity.get("aliases", [])
            if isinstance(a, dict) and a.get("id") == binding.alias_id
        ]
        require(
            len(aliases) == 1
            and aliases[0].get("external_id") == binding.actor_subject
            and aliases[0].get("issuer") == binding.actor_issuer,
            "bootstrap_mismatch",
        )
        self.stage = "oauth"
        profile = await read("sys/config/oauth-resource-server/" + binding.oauth_profile)
        require(
            profile.get("enabled") is True
            and profile.get("issuer_id") == binding.actor_issuer
            and self.audience is not None
            and profile.get("audiences") == [self.audience]
            and profile.get("optional_authorization_details", False) is False
            and profile.get("groups_claim") in {None, ""}
            and profile.get("user_claim", "sub") == "sub"
            and profile.get("actor_claim", "act.sub") == "act.sub"
            and profile.get("jwt_type", "access_token") == "access_token"
            and type(profile.get("clock_skew_leeway", 0)) is int
            and 0 <= profile.get("clock_skew_leeway", 0) <= 30,
            "bootstrap_mismatch",
        )
        self.stage = "spiffe"
        config = await read(binding.trust.mount + "/config")
        role = await read(binding.trust.mount + "/role/" + binding.trust.role)
        require(role.get("ttl") is not None, "trust_unavailable")
        ttl = role["ttl"]
        if isinstance(ttl, str) and ttl.isdigit():
            ttl = int(ttl)
        elif isinstance(ttl, str) and ttl.endswith("s") and ttl[:-1].isdigit():
            ttl = int(ttl[:-1])
        require(type(ttl) is int and 0 < ttl <= binding.trust.max_ttl, "trust_unavailable")
        # The entitlement digest is reviewed out-of-band. A version string is not
        # license evidence; operators must import a correlated entitlement receipt.
        from .config import Entitlement
        from .models import now

        self.stage = "license"
        require(self.entitlement is not None, "native_evidence_missing")
        receipt = Entitlement.model_validate(self.entitlement)
        require(
            receipt.digest == binding.entitlement_digest
            and receipt.digest == binding_digest(receipt.model_dump(exclude={"digest"}))
            and receipt.origin == binding.vault_origin
            and receipt.namespace == binding.namespace
            and receipt.product_version == health.get("version")
            and receipt.registry is True
            and receipt.spiffe is True
            and receipt.reviewed_at <= now() < receipt.expires_at,
            "native_evidence_missing",
        )
        # Verify dedicated KV-v2 fixture mounts without reading their values.
        self.stage = "mounts"
        for mount in sorted({p.split("/")[0] for p in binding.paths.values()}):
            mounted = await read("sys/mounts/" + mount)
            require(
                mounted.get("type") == "kv" and mounted.get("options", {}).get("version") == "2",
                "configuration_changed",
            )
        result = {
            "entity": binding_digest(entity),
            "alias": binding_digest(aliases[0]),
            "oauth_profile": binding_digest(profile),
            "role": binding_digest(role),
            "config": binding_digest(config),
            "entitlement": receipt.digest,
        }
        self.stage = "policies"
        for policy in binding.policies:
            require(re.fullmatch(r"[A-Za-z0-9_-]+", policy), "invalid_input")
            data = await read("sys/policies/acl/" + policy)
            result["policy-" + policy] = binding_digest(data)
        self.stage = "registry"
        if require_absent:
            await self.absence(binding)
        else:
            current = await self.reconcile(binding, self.registration_id)
            require(
                self.registration_id is not None
                and current.get("registration_id") == self.registration_id,
                "registry_conflict",
            )
        self.stage = "operator"
        status, capabilities, _digest = await self.call(
            binding, "POST", "sys/capabilities-self", {"paths": ["agent-registry/register"]}
        )
        require(
            status == 200
            and bool({"create", "update"} & set(capabilities.get("capabilities", [])))
            and "root" not in capabilities.get("capabilities", []),
            "missing_authority",
        )
        expected = {
            "role": binding.trust.role_digest,
            "config": binding.trust.config_digest,
            "entitlement": binding.entitlement_digest,
            **{"policy-" + name: value for name, value in binding.policies.items()},
        }
        for name, digest in expected.items():
            self.stage = (
                "policies"
                if name.startswith("policy-")
                else "license"
                if name == "entitlement"
                else "spiffe"
            )
            require(result.get(name) == digest, "configuration_changed")
        return result
