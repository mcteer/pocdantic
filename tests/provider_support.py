"""Isolated provider enrollment fixtures; never load customer settings or credentials."""

from uuid import uuid4

from response_support import enrolled


def provider_store(settings, project):
    """Create a temporary v2 control installation with no provider configuration."""
    return enrolled(settings, project)


def resource(settings, kind="registration", **changes):
    """Construct exact synthetic provider metadata with configurable boundary cases."""
    from agent.recovery.models import now
    from agent.response.providers.models import ResourceBinding

    data = dict(
        binding_id=uuid4(),
        alias="fixture-resource",
        kind=kind,
        workload_definition=settings.workload_definition,
        origin="https://provider.example",
        native_id="resource-one",
        actor_issuer=settings.oauth_issuer or "offline",
        actor_subject="fixture-actor",
        entity_id="entity-one",
        capability="supported",
        capability_digest="1" * 64,
        checked_at=now(),
        enabled=True,
    )
    if kind == "static_role":
        data.update(mount="database", database="fixture", isolated=True, username="isolated")
    if kind == "user":
        data.update(user_issuer=settings.oauth_issuer or "offline", user_subject="fixture-user")
    if kind == "teams":
        data.update(secret_alias="teams-hook", owner_confirmed=True)
    return ResourceBinding.model_validate(data | changes)


def enrollment(store, bindings=(), rules=(), sources=(), **changes):
    """Build a draft pinned to this synthetic installation, never a live tenant."""
    from agent.response.providers.models import Enrollment

    state = store.read()
    return Enrollment.model_validate(
        dict(
            installation_id=state.installation_id,
            environment_digest=state.environment_digest,
            source_policy_digest=state.policy_digest,
            workload_definition=store.settings.workload_definition,
            issuer=store.settings.oauth_issuer or "offline",
            bindings=bindings,
            rules=rules,
            sources=sources,
        )
        | changes
    )


def activate(store, policy):
    """Inject already-reviewed synthetic capability metadata through the real transaction."""
    from agent.response.providers.enrollment import enroll

    if any(b.secret_alias for b in policy.bindings):
        from agent.validation.models import canonical

        file = (
            store.path / "provider-secrets.json"
            if hasattr(store, "path")
            else store.root / "provider-secrets.json"
        )
        values = {
            b.secret_alias: "https://provider.example/workflow?sig=fixture"
            for b in policy.bindings
            if b.secret_alias
        }
        file.write_bytes(canonical(values))
        file.chmod(0o600)
    if any(b.enabled for b in policy.bindings):
        from agent.response.providers.enrollment import digest, write_private
        from agent.response.providers.models import ReadinessRecord

        state = store.read()
        write_private(
            store,
            "providers.readiness.json",
            ReadinessRecord(
                installation_id=state.installation_id,
                environment_digest=state.environment_digest,
                draft_digest=digest(policy),
                bindings=policy.bindings,
            ),
        )
    return enroll(store, policy, store.read().revision)


class Clock:
    """Deterministic monotonic clock for budgets, expiry and cross-restart tests."""

    def __init__(self, seconds=0):
        """Start at an injected synthetic offset without reading machine time."""
        self.seconds = seconds

    def __call__(self):
        """Return the current deterministic monotonic reading."""
        return self.seconds

    def advance(self, seconds):
        """Move forward explicitly; callers can inject invalid readings separately."""
        self.seconds += seconds


def process_result(stdout=b"", code=0):
    """Build a bounded synthetic process result without invoking a shell or provider."""
    from types import SimpleNamespace

    return SimpleNamespace(returncode=code, stdout=stdout, stderr=b"")
