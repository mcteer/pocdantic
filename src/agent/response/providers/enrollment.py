"""Explicit owner-only provider enrollment and read-only setup diagnostics.

A draft never changes active authority. Enrollment is one snapshot transaction after
worker/root drain. Provider credentials remain in fixed private files or existing settings.
"""

import hashlib
import os
from contextlib import ExitStack

from pydantic import SecretStr, TypeAdapter

from agent.recovery.store import RecoveryError, check_stat
from agent.response.models import ResponseError
from agent.validation.models import canonical
from agent.validation.store import decode_json

from .models import Alias, Enrollment, require


def digest(value):
    """Fingerprint canonical authority/observations without publishing private metadata."""
    return hashlib.sha256(canonical(value)).hexdigest()


def private_read(store, name, limit=1024 * 1024):
    """Read a fixed private file through verified descriptors and reject replacement races."""
    try:
        with store._directory() as directory:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, "rb") as file:
                before = os.fstat(file.fileno())
                check_stat(before)
                raw = file.read(limit + 1)
                after = os.stat(name, dir_fd=directory, follow_symlinks=False)
                require(
                    len(raw) <= limit
                    and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                    "provider_evidence_invalid",
                )
                return raw
    except ResponseError:
        raise
    except Exception:
        raise ResponseError("provider_evidence_invalid") from None


def read_secrets(store):
    """Read only bounded alias-to-secret material, never ambient variable/path references."""
    try:
        data = decode_json(private_read(store, "provider-secrets.json", 65536))
        values = TypeAdapter(dict[Alias, SecretStr]).validate_python(data)
        require(
            len(values) <= 64
            and all(0 < len(v.get_secret_value()) <= 8192 for v in values.values())
        )
        return values
    except ResponseError:
        raise
    except Exception:
        raise ResponseError("provider_evidence_invalid") from None


def prepare(store):
    """Create non-overwriting private templates derived only from current enrollment identity."""
    state = store.read()
    require(state.schema_version == 2, "response_schema_migration_required")
    policy = Enrollment(
        installation_id=state.installation_id,
        environment_digest=state.environment_digest,
        source_policy_digest=state.policy_digest,
        workload_definition=store.settings.workload_definition,
        issuer=store.settings.oauth_issuer or "offline",
    )
    created = False
    try:
        with store._directory() as directory:
            for name, raw in (
                ("providers.draft.json", canonical(policy)),
                ("provider-secrets.json", b"{}"),
                ("probe.lock", b""),
            ):
                try:
                    fd = os.open(
                        name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                except FileExistsError:
                    private_read(store, name)
                    continue
                with os.fdopen(fd, "wb") as file:
                    file.write(raw)
                    file.flush()
                    os.fsync(file.fileno())
                created = True
            os.fsync(directory)
    except ResponseError:
        raise
    except Exception:
        raise ResponseError("response_storage_error") from None
    return created


def draft(store):
    """Validate the inactive local draft without exposing its raw values on failure."""
    try:
        return Enrollment.model_validate(decode_json(private_read(store, "providers.draft.json")))
    except Exception:
        raise ResponseError("provider_evidence_invalid") from None


def enroll(store, policy, revision):
    """Activate reviewed enrollment; malformed private input yields only a closed error."""
    from pydantic import ValidationError

    try:
        return _enroll(store, policy, revision)
    except ValidationError:
        raise ResponseError("provider_evidence_invalid") from None


def _enroll(store, policy, revision):
    """Activate exact reviewed authority after nonblocking maintenance/drain checks."""
    policy = Enrollment.model_validate(policy.model_dump())
    if any(b.enabled for b in policy.bindings):
        from agent.recovery.models import now

        from .models import ReadinessRecord

        review = ReadinessRecord.model_validate(
            decode_json(private_read(store, "providers.readiness.json"))
        )
        current = store.read()
        require(
            (review.installation_id, review.environment_digest, review.draft_digest)
            == (current.installation_id, current.environment_digest, digest(policy))
            and 0 <= (now() - review.checked_at).total_seconds() <= 300,
            "missing_authority",
        )
        if policy.dynamic_revocation_review_digest:
            require(review.dynamic_reason == "provider_state_observed", "missing_authority")
        checked = {b.binding_id: b for b in review.bindings}
        bindings = []
        fields = {"capability", "capability_digest", "checked_at", "entitlement_digest"}
        for binding in policy.bindings:
            result = checked.get(binding.binding_id)
            require(
                result is not None
                and binding.model_dump(exclude=fields) == result.model_dump(exclude=fields),
                "provider_policy_changed",
            )
            bindings.append(
                type(binding).model_validate(
                    binding.model_dump() | {key: getattr(result, key) for key in fields}
                )
            )
        policy = Enrollment.model_validate(policy.model_dump() | {"bindings": tuple(bindings)})

    for source in policy.sources:
        if source.provenance == "native":
            schema = decode_json(private_read(store, f"native-{source.alias}.schema.json"))
            fixture = private_read(store, f"native-{source.alias}.fixture.json", 65536)
            collector = private_read(store, f"native-{source.alias}.receipt.json")
            require(
                isinstance(schema, dict)
                and schema.get("schema_ref") == source.schema_ref
                and hashlib.sha256(fixture).hexdigest() == source.fixture_digest
                and hashlib.sha256(collector).hexdigest() == source.collector_digest,
                "source_evidence_missing",
            )
            from types import SimpleNamespace

            from ..native import project

            project(fixture, source, SimpleNamespace(enrollment=policy, runs=store.read().runs))

    if any(
        b.secret_alias or b.proof_secret_alias or b.healthy_secret_alias for b in policy.bindings
    ):
        values = read_secrets(store)
        bindings = []
        for binding in policy.bindings:
            changes = {}
            for purpose in ("secret", "proof_secret", "healthy_secret"):
                alias = getattr(binding, purpose + "_alias")
                if alias:
                    secret = values.get(alias)
                    require(secret is not None, "missing_authority")
                    fingerprint = hashlib.sha256(secret.get_secret_value().encode()).hexdigest()
                    require(
                        getattr(binding, purpose + "_digest") in {None, fingerprint},
                        "provider_policy_changed",
                    )
                    changes[purpose + "_digest"] = fingerprint
            if binding.kind == "teams":
                from .teams import destination_digest

                secret = values.get(binding.secret_alias)
                require(secret is not None, "missing_authority")
                destination = destination_digest(secret.get_secret_value(), binding.origin)
                require(
                    binding.destination_digest in {None, destination}, "provider_policy_changed"
                )
                changes["destination_digest"] = destination
            bindings.append(type(binding).model_validate(binding.model_dump() | changes))
        policy = Enrollment.model_validate(policy.model_dump() | {"bindings": tuple(bindings)})
    if policy.dynamic_healthy_secret_alias:
        values = read_secrets(store)
        secret = values.get(policy.dynamic_healthy_secret_alias)
        require(secret is not None, "missing_authority")
        fingerprint = hashlib.sha256(secret.get_secret_value().encode()).hexdigest()
        require(
            policy.dynamic_healthy_secret_digest in {None, fingerprint}, "provider_policy_changed"
        )
        policy = Enrollment.model_validate(
            policy.model_dump() | {"dynamic_healthy_secret_digest": fingerprint}
        )
    mode = store.anchor().recovery_mode
    try:
        with ExitStack() as locks:
            if mode == "configured":
                locks.enter_context(store.recovery.workspace())
            locks.enter_context(store.workspace())
            locks.enter_context(store._lock("worker.lock"))
            locks.enter_context(store._lock("probe.lock"))
            locks.enter_context(store.recovery.effect() if mode == "configured" else store.effect())
            with store.transaction() as (fd, state):
                require(state.schema_version == 2, "response_schema_migration_required")
                require(state.revision == revision, "revision_conflict")
                require(
                    not any(r.state == "active" or store.busy(r.root_run_id) for r in state.runs),
                    "provider_busy",
                )
                from .proof import complete
                from .retention import acquisition_roots

                require(not acquisition_roots(state), "provider_busy")
                current_actions = {aid for plan in state.provider_plans for aid in plan.action_ids}
                require(
                    not any(
                        a.state in {"planned", "submitted", "uncertain"}
                        or (a.action_id in current_actions and a.required and not complete(a))
                        for a in state.provider_actions
                    )
                    and not (state.enrollment and state.holds),
                    "provider_busy",
                )
                require(
                    not any(
                        a.state in {"intent", "submitted", "uncertain"}
                        for a in state.native_acquisitions
                    )
                    and not any(
                        a.state not in {"denied_no_issuance", "cleaned"}
                        for a in state.probe_acquisitions
                    ),
                    "provider_busy",
                )
                require(
                    (policy.installation_id, policy.environment_digest, policy.source_policy_digest)
                    == (state.installation_id, state.environment_digest, state.policy_digest),
                    "provider_policy_changed",
                )
                require(
                    policy.issuer == store.policy().issuer
                    and policy.workload_definition == store.settings.workload_definition,
                    "provider_policy_changed",
                )
                if state.enrollment:
                    require(policy.revision == state.enrollment.revision + 1, "revision_conflict")
                    old_resources = {b.key(): b for b in state.enrollment.bindings}
                    for binding in policy.bindings:
                        previous = old_resources.get(binding.key())
                        if previous and binding.enabled:
                            require(
                                binding.generation == previous.generation + 1,
                                "provider_policy_changed",
                            )
                denied_audiences = {
                    store.settings.oauth_audience,
                    store.settings.actor_audience,
                    store.settings.vault_audience,
                    store.settings.oauth_client_id,
                    store.settings.login_client_id,
                    store.policy().audience,
                }
                require(
                    all(s.audience not in denied_audiences for s in policy.sources),
                    "source_invalid",
                )
                require(
                    not {s.alias for s in policy.sources}
                    & {s.alias for s in store.policy().sources},
                    "source_invalid",
                )
                from agent.recovery.models import now

                selected = {bid for rule in policy.rules for bid in rule.bindings}
                selected.update(
                    bid for profile in policy.sources for bid in profile.object_bindings.values()
                )
                require(
                    all(
                        not b.enabled
                        or b.binding_id not in selected
                        or (
                            b.capability_digest
                            and b.checked_at
                            and 0 <= (now() - b.checked_at).total_seconds() <= 300
                        )
                        for b in policy.bindings
                    ),
                    "missing_authority",
                )
                require(
                    all(
                        not b.enabled or b.binding_id not in selected or b.capability == "supported"
                        for b in policy.bindings
                    ),
                    "missing_authority",
                )
                return store.commit(fd, state, enrollment=policy)
    except RecoveryError as error:
        raise ResponseError(
            "provider_busy" if str(error) == "recovery_busy" else "response_storage_error"
        ) from None


def local_readiness(store, policy):
    """Report missing exact prerequisites before any provider query or mutation."""
    results = []
    for source in policy.sources:
        reason = (
            "source_evidence_missing"
            if source.provenance != "native"
            else "provider_state_observed"
        )
        results.append(
            {
                "alias": source.alias,
                "reason": reason,
                "owner_role": "VIP operator",
                "next_action": (
                    "Enroll the exact schema, relay authentication and collector receipt; "
                    "rerun providers readiness."
                ),
            }
        )
    for binding in policy.bindings:
        results.append(
            {
                "alias": binding.alias,
                "reason": "not_enrolled" if not binding.enabled else "proof_required",
                "owner_role": "integration operator",
                "next_action": (
                    "Verify exact target and read-only provider capabilities; "
                    "rerun providers readiness."
                ),
            }
        )
    return results


def native_begin(store, guard, mount, role, origin, namespace):
    """Reserve prospective native-token attribution before any credential-issuing call."""
    from .models import NativeTokenAcquisition

    guard.check()
    with store.transaction() as (fd, state):
        policy = state.enrollment
        require(
            policy is not None
            and policy.native_exclusive_tree
            and (policy.native_login_mount, policy.native_login_role) == (mount, role),
            "mapping_missing",
        )
        run = next((r for r in state.runs if r.root_run_id == guard.binding.root_run_id), None)
        require(run is not None and run.actor_issuer and run.actor_subject, "mapping_missing")
        require(
            any(
                b.enabled
                and b.kind == "registration"
                and (b.origin.rstrip("/"), b.namespace, b.actor_issuer, b.actor_subject)
                == (origin.rstrip("/"), namespace, run.actor_issuer, run.actor_subject)
                for b in policy.bindings
            ),
            "mapping_missing",
        )
        item = NativeTokenAcquisition(
            ownership=run.ownership(),
            actor_issuer=run.actor_issuer,
            actor_subject=run.actor_subject,
            mount=mount,
            role=role,
            enrollment_digest=digest(policy),
        )
        store.commit(fd, state, native_acquisitions=(*state.native_acquisitions, item))
        return item


def native_update(store, item, state_name, *, auth=None, origin=None, namespace=""):
    """Record exact accessor before token exposure; unknown or unsupported replies stay pinned."""
    from agent.recovery.models import now

    from .models import NativeTokenAcquisition, ResourceBinding

    with store.transaction() as (fd, state):
        current = next(
            a for a in state.native_acquisitions if a.acquisition_id == item.acquisition_id
        )
        require(current.state in {"intent", "submitted", "uncertain"}, "provider_policy_changed")
        changes = {"state": state_name}
        if state_name == "submitted":
            changes["submitted_at"] = now()
        if state_name == "bound":
            require(
                isinstance(auth, dict)
                and auth.get("token_type") == "service"
                and isinstance(auth.get("accessor"), str)
                and isinstance(auth.get("client_token"), str)
                and 0 < len(auth["client_token"]) <= 65536,
                "mapping_missing",
            )
            require(
                not any(
                    a.binding
                    and a.binding.kind == "native_token"
                    and (a.binding.origin, a.binding.namespace, a.binding.native_id)
                    == (origin, namespace, auth["accessor"])
                    for a in state.native_acquisitions
                    if a.acquisition_id != item.acquisition_id
                ),
                "mapping_missing",
            )
            changes["binding"] = ResourceBinding(
                alias="native-" + item.acquisition_id.hex[:24],
                kind="native_token",
                workload_definition=current.ownership.workload_definition,
                origin=origin,
                namespace=namespace,
                native_id=auth["accessor"],
                actor_issuer=current.actor_issuer,
                actor_subject=current.actor_subject,
                root_run_id=current.ownership.root_run_id,
                ownership=current.ownership,
                token_type="service",
                exclusive_tree=True,
                enabled=True,
                capability="supported",
            )
        updated = NativeTokenAcquisition.model_validate(current.model_dump() | changes)
        from .planner import bind_pending_native

        plans = bind_pending_native(state, updated) if state_name == "bound" else {}
        store.commit(
            fd,
            state,
            **plans,
            native_acquisitions=tuple(
                updated if a.acquisition_id == item.acquisition_id else a
                for a in state.native_acquisitions
            ),
        )
        return updated


def write_private(store, name, value):
    """Atomically write one compiled private artifact; never accept arbitrary destination paths."""
    from uuid import uuid4

    allowed = {"providers.readiness.json"}
    require(name in allowed, "provider_evidence_invalid")
    raw = canonical(value)
    require(len(raw) <= 1048576, "provider_capacity")
    temporary = f".provider-{uuid4()}.tmp"
    try:
        with store._directory() as directory:
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            try:
                with os.fdopen(fd, "wb") as file:
                    file.write(raw)
                    file.flush()
                    os.fsync(file.fileno())
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
    except ResponseError:
        raise
    except Exception:
        raise ResponseError("response_storage_error") from None


async def readiness(store, *, transport=None):
    """Review one inactive draft with bounded exact metadata queries; never activate authority."""
    import asyncio

    import httpx

    from .models import AuthorityReview, ReadinessRecord
    from .vault import VaultAdapter
    from .verify import VerifyAdapter

    policy = draft(store)
    original = digest(policy)
    checked = []
    async with asyncio.timeout(120):
        async with httpx.AsyncClient(
            timeout=10, trust_env=False, follow_redirects=False, transport=transport
        ) as http:
            for binding in policy.bindings:
                if binding.kind in {"registration", "native_token", "static_role"}:
                    result = await VaultAdapter(store.settings, http).readiness(binding)
                elif binding.kind == "user":
                    try:
                        review = AuthorityReview.model_validate(
                            decode_json(
                                private_read(store, f"verify-{binding.alias}.authority.json")
                            )
                        )
                        result = await VerifyAdapter(store.settings, http).readiness(
                            binding, review
                        )
                    except Exception:
                        result = type(binding).model_validate(
                            binding.model_dump() | {"capability": "missing_authority"}
                        )
                else:
                    values = read_secrets(store)
                    secret = values.get(binding.secret_alias)
                    supported = binding.owner_confirmed and secret is not None
                    if supported:
                        from urllib.parse import urlsplit

                        parts = urlsplit(secret.get_secret_value())
                        supported = (
                            parts.scheme == "https"
                            and not parts.username
                            and not parts.password
                            and not parts.fragment
                            and f"https://{parts.netloc}" == binding.origin
                        )
                    from agent.recovery.models import now

                    result = type(binding).model_validate(
                        binding.model_dump()
                        | {
                            "capability": "supported" if supported else "missing_authority",
                            "checked_at": now(),
                            "capability_digest": hashlib.sha256(
                                secret.get_secret_value().encode()
                            ).hexdigest()
                            if secret
                            else None,
                        }
                    )
                if binding.kind == "static_role" and any(
                    "terminate_static_sessions" in rule.actions
                    and binding.binding_id in rule.bindings
                    for rule in policy.rules
                ):
                    from .database import DatabaseAdapter

                    database = await DatabaseAdapter(read_secrets(store)).readiness(binding)
                    if database.capability != "supported":
                        result = type(binding).model_validate(
                            result.model_dump() | {"capability": database.capability}
                        )
                    result = type(binding).model_validate(
                        result.model_dump()
                        | {
                            "capability_digest": hashlib.sha256(
                                canonical([result.capability_digest, database.capability_digest])
                            ).hexdigest()
                        }
                    )
                checked.append(result)
            dynamic_reason = None
            if policy.dynamic_revocation_review_digest:
                dynamic_reason = await VaultAdapter(store.settings, http).dynamic_readiness(policy)
    require(digest(draft(store)) == original, "revision_conflict")
    state = store.read()
    record = ReadinessRecord(
        installation_id=state.installation_id,
        environment_digest=state.environment_digest,
        draft_digest=original,
        bindings=tuple(checked),
        dynamic_reason=dynamic_reason,
    )
    write_private(store, "providers.readiness.json", record)
    findings = [
        {
            "alias": b.alias,
            "reason_code": "provider_state_observed"
            if b.capability == "supported"
            else b.capability,
            "owner_role": "integration operator",
            "next_action": (
                "Review the exact private draft target and grant the required permissions. "
                "Readiness observes settings without changing them."
            ),
            "rerun_command": "agent respond providers readiness",
        }
        for b in checked
    ]

    if dynamic_reason is not None:
        findings.append(
            {
                "alias": "dynamic-cleanup",
                "reason_code": dynamic_reason,
                "owner_role": "Vault/database operator",
                "next_action": (
                    "Review revocation_statements on the configured dynamic role: require "
                    "generated-session termination, grant revocation and role removal. "
                    "Put the canonical statements SHA-256 in dynamic_revocation_review_digest; "
                    "rerun readiness. Readiness leaves the role unchanged."
                ),
                "rerun_command": "agent respond providers readiness",
            }
        )
    for source in policy.sources:
        reason = "source_evidence_missing"
        try:
            require(source.provenance == "native", "source_evidence_missing")
            schema = decode_json(private_read(store, f"native-{source.alias}.schema.json"))
            fixture = private_read(store, f"native-{source.alias}.fixture.json", 65536)
            collector = private_read(store, f"native-{source.alias}.receipt.json")
            require(
                isinstance(schema, dict)
                and schema.get("schema_ref") == source.schema_ref
                and hashlib.sha256(fixture).hexdigest() == source.fixture_digest
                and hashlib.sha256(collector).hexdigest() == source.collector_digest,
                "source_evidence_missing",
            )
            from types import SimpleNamespace

            from ..native import project

            project(fixture, source, SimpleNamespace(enrollment=policy, runs=state.runs))
            reason = "provider_state_observed"
        except Exception:
            pass
        findings.append(
            {
                "alias": source.alias,
                "reason_code": reason,
                "owner_role": "VIP operator",
                "next_action": "Export the rule schema and sample; save native-ALIAS.schema.json, "
                "native-ALIAS.fixture.json and native-ALIAS.receipt.json privately. "
                "Pin their digests and the separate relay identity in the draft.",
                "rerun_command": "agent respond providers readiness",
            }
        )
    return findings
