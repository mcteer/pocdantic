"""Isolated governance contracts and fake providers; no ambient credentials or state."""

from uuid import uuid4


def binding(**changes):
    """Return one synthetic candidate identity with exact reviewed proof resources."""
    from agent.governance.models import Binding, Trust

    values = dict(
        owner_issuer="https://id.example",
        owner_subject="owner",
        owner="test-team",
        purpose="isolated proof",
        definition="test-agent",
        actor_issuer="https://id.example",
        actor_subject="candidate",
        source_object="unknown-object",
        client="candidate",
        entity_id="entity",
        alias_id="alias",
        oauth_profile="test-profile",
        registry_name="case-" + uuid4().hex,
        vault_origin="https://vault.example",
        namespace="test",
        ceiling_policies=("test-ceiling",),
        policies={"test-ceiling": "0" * 64, "candidate-acl": "0" * 64, "human-acl": "0" * 64},
        paths={
            "preregistration": "proof/data/allowed",
            "obo_allowed": "proof/data/allowed",
            "obo_beyond_ceiling": "proof/data/excessive",
            "direct_allowed": "proof/data/allowed",
            "direct_denied": "proof/data/forbidden",
        },
        healthy_client="healthy",
        trust=Trust(
            issuer="https://vault.example/v1/spiffe",
            subject="spiffe://test.example/agent",
            audience="test-relying",
            entity_id="entity",
            namespace="test",
            mount="spiffe",
            role="test-role",
            discovery_url="https://vault.example/v1/spiffe/.well-known/openid-configuration",
            jwks_url="https://vault.example/v1/spiffe/.well-known/keys",
            role_digest="0" * 64,
            config_digest="0" * 64,
        ),
        exclusive=True,
        entitlement_digest="0" * 64,
        registry_clock_bound=1,
    )
    return Binding(**(values | changes))


def source():
    """Return an observation-only source; fixture provenance never certifies a vendor."""
    from agent.governance.models import Source

    return Source(
        alias="fixture",
        product="synthetic",
        version="test",
        instance="collector",
        issuer="https://id.example",
        subject="relay",
        audience="discovery",
        schema_digest="0" * 64,
        fixture_digest="0" * 64,
        collector_digest="0" * 64,
        pointers={"event": "/id", "object": "/object", "kind": "/kind", "time": "/time"},
        kinds={
            "unknown": "unknown",
            "managed": "managed",
            "triaged": "triaged",
            "notice": "notification",
        },
        provenance="synthetic",
        clock_bound=1,
    )


def installed(tmp_path):
    """Create a fresh private test installation with no response/recovery bypass in production."""
    from agent.governance.store import GovernanceStore

    store = GovernanceStore(project=tmp_path, environment="0" * 64)
    store.prepare()
    return store


def anchors(tmp_path):
    """Install actual response/recovery anchors against synthetic settings only."""
    from recovery_support import settings

    from agent.governance.store import GovernanceStore
    from agent.recovery.store import RecoveryStore, environment_digest
    from agent.response.store import ResponseStore

    config = settings(tmp_path)
    recovery = RecoveryStore(config, project=tmp_path)
    recovery.initialize()
    response = ResponseStore(config, project=tmp_path, recovery=recovery)
    response.prepare()
    response.initialize()
    # The existing response upgrade creates its compiled probe lock.
    response.migrate()
    governance = GovernanceStore(project=tmp_path, environment=environment_digest(config))
    governance.prepare()
    return config, governance, response, recovery


class FakeRegistry:
    """Exact synthetic native-adapter surface, with one create and no update/delete."""

    def __init__(self):
        """Keep request history isolated so tests can assert effects were not replayed."""
        self.posts = 0
        self.present = False
        self.acknowledge = None

    async def metadata(self, binding, **_kwargs):
        """Return reviewed fingerprints without accessing a provider."""
        return {
            "role": binding.trust.role_digest,
            "config": binding.trust.config_digest,
            "entitlement": binding.entitlement_digest,
            **{"policy-" + k: v for k, v in binding.policies.items()},
            "entity": "0" * 64,
            "alias": "0" * 64,
            "oauth_profile": "0" * 64,
        }

    async def absence(self, _binding):
        """Record current controlled absence; a present record is a conflict."""
        from agent.governance.models import require

        require(not self.present, "registry_conflict")
        return {"absent": True, "digest": "0" * 64}

    async def create(self, _binding):
        """Acknowledge exactly once, then return an independently matched synthetic readback."""
        self.posts += 1
        self.present = True
        if self.acknowledge:
            self.acknowledge("fixture-registration", "1" * 64)
        return {
            "registration_id": "fixture-registration",
            "digest": "0" * 64,
            "source_digest": "1" * 64,
        }
