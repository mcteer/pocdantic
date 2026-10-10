"""Independent provider proof predicates and conservative release safety.

Control acknowledgments never establish credential invalidation. Synthetic observations
remain synthetic and cannot authorize live release or native acceptance.
"""

from datetime import timedelta

from agent.recovery.models import now

from .enrollment import digest

READBACKS = {
    "revoke_native_token": {"native_token_readback"},
    "revoke_user_sessions": {"tenant_session_readback"},
    "terminate_static_sessions": {"static_session_readback"},
}

PATHS = {
    "block_registration": {"registration", "same_jwt", "fresh_issuance"},
    "revoke_native_token": {"native_token"},
    "suspend_user": {"tenant_user", "fresh_issuance"},
    "revoke_user_sessions": {"tenant_sessions"},
    "rotate_static": {"static_old", "static_new"},
    "terminate_static_sessions": {"static_session"},
    "notify_teams": {"notification"},
}


def complete(action, *, live=False, fresh=False, lifetime_safe=False):
    """Require latest independent results; contradictory new observations supersede old proof."""
    for path in PATHS[action.kind]:
        observations = [o for o in action.observations if o.path == path]
        latest = max(observations, key=lambda o: o.observed_at) if observations else None
        if latest is None or latest.result != "proven":
            return False
        if live:
            from agent.validation.models import implementation_revision

            if (
                latest.source == "synthetic"
                or latest.implementation_digest != implementation_revision()
                or not latest.reviewer
                or latest.reviewed_at is None
            ):
                return False
        if latest.observed_at > now():
            return False
        if fresh and not now() - timedelta(seconds=300) <= latest.observed_at <= now():
            immutable_negative = (
                lifetime_safe
                and path in {"same_jwt", "fresh_issuance"}
                and latest.reviewer
                and latest.reviewed_at
                and latest.source in {"native_evidence", "live_probe"}
            )
            if not immutable_negative:
                return False
    return action.state in {"acknowledged", "reconciled"}


def lifetime_safe(action, policy):
    """Require proven same-actor minting cessation and the full enrolled lifetime plus skew."""
    values = [
        o
        for o in action.observations
        if o.path == "old_credential_safety" and o.source == "native_evidence"
    ]
    latest = max(values, key=lambda o: o.observed_at) if values else None
    return bool(
        latest
        and latest.result == "proven"
        and latest.reviewer
        and latest.reviewed_at
        and latest.minting_stopped_at is not None
        and latest.maximum_lifetime_seconds is not None
        and latest.maximum_lifetime_seconds == policy.max_token_lifetime_seconds
        and not any(
            o.path in {"same_jwt", "fresh_issuance"}
            and o.credential_expires_at
            and o.credential_expires_at
            > latest.minting_stopped_at + timedelta(seconds=latest.maximum_lifetime_seconds)
            for o in action.observations
            if o.source != "synthetic"
        )
        and now()
        >= latest.minting_stopped_at + timedelta(seconds=latest.maximum_lifetime_seconds + 30)
    )


def release_safe(state, incident_ids):
    """Reject incomplete inventory, stale authority and missing old-credential safety."""
    if any(a.state in {"intent", "submitted", "uncertain"} for a in state.native_acquisitions):
        return False
    if any(a.state not in {"cleaned", "denied_no_issuance"} for a in state.probe_acquisitions):
        return False
    if any(p.missing_controls for p in state.provider_plans if p.incident_id in incident_ids):
        return False
    fingerprint = digest(state.enrollment)
    current_refs = {
        ref for p in state.provider_plans if p.incident_id in incident_ids for ref in p.action_ids
    }
    for action in state.provider_actions:
        if action.action_id not in current_refs or not action.required:
            continue
        safe = (
            lifetime_safe(action, state.enrollment)
            if action.kind in {"block_registration", "suspend_user"}
            else False
        )
        if action.kind in {"block_registration", "suspend_user"} and not safe:
            return False
        if action.enrollment_digest != fingerprint or not complete(
            action, live=True, fresh=True, lifetime_safe=safe
        ):
            return False
    return True


def import_observation(store, raw, revision):
    """Import at most 1 MiB into exact current authority; conflicting IDs never overwrite.

    Reviewed native receipts are local operator attestations, not authentication supplied
    by event sources. This command retains typed evidence privately and does not promote
    acceptance criteria or resolve a possibly submitted mutation by itself.
    """
    from agent.response.models import ResponseError
    from agent.validation.models import implementation_revision
    from agent.validation.store import decode_json

    from .models import Observation, ProviderAction, require

    try:
        require(len(raw) <= 1048576, "provider_evidence_invalid")
        observation = Observation.model_validate(decode_json(raw))
        with store.transaction() as (fd, state):
            require(state.schema_version == 2 and state.enrollment is not None, "not_enrolled")
            require(state.revision == revision, "revision_conflict")
            action = next(
                (a for a in state.provider_actions if a.action_id == observation.action_id), None
            )
            require(
                (
                    observation.installation_id,
                    observation.environment_digest,
                    observation.implementation_digest,
                    observation.enrollment_digest,
                )
                == (
                    state.installation_id,
                    state.environment_digest,
                    implementation_revision(),
                    digest(state.enrollment),
                ),
                "provider_evidence_invalid",
            )
            if action is None:
                return import_dynamic(store, fd, state, observation)
            extra_paths = {"native_intake"}
            if action.kind in {"block_registration", "suspend_user"}:
                extra_paths.add("old_credential_safety")
            if action.kind in {"suspend_user", "revoke_user_sessions"}:
                extra_paths.add("upstream_sessions")
            require(
                observation.incident_id in action.incidents
                and observation.binding_id == action.binding.binding_id
                and observation.resource_generation == action.binding.generation
                and observation.path
                in PATHS[action.kind] | READBACKS.get(action.kind, set()) | extra_paths,
                "provider_evidence_invalid",
            )
            if observation.path == "native_intake":
                incident = next(
                    i for i in state.incidents if i.incident_id == observation.incident_id
                )
                profile = next(
                    (s for s in state.enrollment.sources if s.alias == incident.source), None
                )
                require(
                    observation.source == "native_evidence"
                    and profile is not None
                    and profile.provenance == "native"
                    and observation.event_digest == incident.payload_digest
                    and observation.observed_at == incident.received_at,
                    "provider_evidence_invalid",
                )
            if observation.path == "notification" and observation.result == "proven":
                require(
                    observation.source == "native_evidence"
                    and observation.notice_id == action.notice_id
                    and observation.notice_revision == action.notice_revision,
                    "provider_evidence_invalid",
                )
            require(
                observation.observed_at <= now()
                and (
                    observation.reviewed_at is None
                    or observation.observed_at <= observation.reviewed_at <= now()
                ),
                "provider_evidence_invalid",
            )
            if observation.source == "native_evidence":
                require(
                    observation.reviewer and observation.reviewed_at, "provider_evidence_invalid"
                )
            existing = next(
                (
                    o
                    for a in (*state.provider_actions, *state.probe_acquisitions)
                    for o in a.observations
                    if o.observation_id == observation.observation_id
                ),
                None,
            )
            if existing:
                require(digest(existing) == digest(observation), "provider_evidence_invalid")
                return False
            updated = ProviderAction.model_validate(
                action.model_dump() | {"observations": (*action.observations, observation)}
            )
            store.commit(
                fd,
                state,
                provider_actions=tuple(
                    updated if a.action_id == action.action_id else a
                    for a in state.provider_actions
                ),
            )
            return True
    except ResponseError:
        raise
    except Exception:
        raise ResponseError("provider_evidence_invalid") from None


def import_dynamic(store, fd, state, observation):
    """Import evidence only for a prospective lease already joined to exact local cleanup.

    The enclosing transaction has validated current installation/environment/revision
    and implementation. Native usernames and backend IDs are never retroactively
    inferred for legacy leases; only the trusted original probe supplies attribution.
    """
    from .models import ProbeAcquisition, require

    incident = next((i for i in state.incidents if i.incident_id == observation.incident_id), None)
    require(
        incident is not None and observation.path in {"dynamic_fresh", "dynamic_session"},
        "provider_evidence_invalid",
    )
    action = next(
        (
            a
            for a in incident.actions
            if a.action_id == observation.action_id
            and a.kind == "revoke_exact"
            and a.target_id == observation.binding_id
        ),
        None,
    )
    probes = [
        p
        for p in state.probe_acquisitions
        if p.scenario == "dynamic_database"
        and p.credential_class == "vault_lease"
        and p.recovery_incident_id == observation.binding_id
        and p.ownership.generation == observation.resource_generation
        and p.enrollment_digest == observation.enrollment_digest
    ]
    require(
        action is not None
        and len(probes) == 1
        and any(incident.matches(r) and r.ownership() == probes[0].ownership for r in state.runs),
        "provider_evidence_invalid",
    )
    require(
        observation.observed_at <= now()
        and (
            observation.reviewed_at is None
            or observation.observed_at <= observation.reviewed_at <= now()
        ),
        "provider_evidence_invalid",
    )
    existing = next(
        (
            o
            for a in (*state.provider_actions, *state.probe_acquisitions)
            for o in a.observations
            if o.observation_id == observation.observation_id
        ),
        None,
    )
    if existing:
        require(digest(existing) == digest(observation), "provider_evidence_invalid")
        return False
    current = probes[0]
    updated = ProbeAcquisition.model_validate(
        current.model_dump() | {"observations": (*current.observations, observation)}
    )
    store.commit(
        fd,
        state,
        probe_acquisitions=tuple(
            updated if p.acquisition_id == current.acquisition_id else p
            for p in state.probe_acquisitions
        ),
    )
    return True


def probe_change(store, acquisition_id, **changes):
    """Persist only narrow probe lifecycle changes while retaining original attribution."""
    from .models import ProbeAcquisition, require

    require(
        not set(changes)
        - {
            "state",
            "submitted_at",
            "lease_handle",
            "recovery_incident_id",
            "observations",
            "credential_digest",
            "credential_expires_at",
        },
        "provider_evidence_invalid",
    )
    with store.transaction() as (fd, state):
        current = next(p for p in state.probe_acquisitions if p.acquisition_id == acquisition_id)
        updated = ProbeAcquisition.model_validate(current.model_dump() | changes)
        store.commit(
            fd,
            state,
            probe_acquisitions=tuple(
                updated if p.acquisition_id == acquisition_id else p
                for p in state.probe_acquisitions
            ),
        )
        return updated


async def acquisition_probe(store, ownership, http, token, *, scenario):
    """Run a fixed explicitly authorized Vault credential proof with its own durable intent.

    Only this trusted validation path bypasses the root guard after containment. It uses
    the installation's fixed credential path, never a URL/path supplied in event input.
    Returned credential data stays in trusted ephemeral memory. Successful issuance is
    adopted into normal exact recovery before callers may use the credential.
    """
    import asyncio

    from agent.recovery.models import valid_handle
    from agent.recovery.workers import descriptor_scope

    from .common import request
    from .models import ProbeAcquisition, require

    recovery = store.recovery
    with recovery.effect() as owner:
        with descriptor_scope(owner.fd):
            recovery_state = recovery.read()
            from agent.recovery.store import MAX_BYTES, RECEIPT_RESERVE
            from agent.validation.models import canonical

            require(
                len(canonical(recovery_state)) <= MAX_BYTES - 16 * RECEIPT_RESERVE,
                "provider_capacity",
            )
            require(
                sum(a.state != "resolved" for a in recovery_state.attempts) < 84,
                "provider_capacity",
            )
            with store.transaction() as (fd, state):
                require(
                    state.enrollment is not None
                    and scenario in {"same_jwt", "fresh_issuance", "dynamic_database"},
                    "unsupported",
                )
                require(any(r.ownership() == ownership for r in state.runs), "mapping_missing")
                probe = ProbeAcquisition(
                    ownership=ownership,
                    credential_path=store.settings.vault_read_path,
                    enrollment_digest=digest(state.enrollment),
                    scenario=scenario,
                )
                store.commit(fd, state, probe_acquisitions=(*state.probe_acquisitions, probe))
            probe_change(store, probe.acquisition_id, state="submitted", submitted_at=now())
            data = None
            try:
                headers = {"X-Vault-Token": token}
                if store.settings.vault_namespace:
                    headers["X-Vault-Namespace"] = store.settings.vault_namespace
                async with asyncio.timeout(10):
                    status, data, _ = await request(
                        http,
                        "GET",
                        f"{store.settings.vault_addr.rstrip('/')}/v1/{probe.credential_path}",
                        headers=headers,
                    )
                if (
                    status in {401, 403}
                    and isinstance(data, dict)
                    and set(data) <= {"errors", "request_id"}
                ):
                    item = probe_change(store, probe.acquisition_id, state="denied_no_issuance")
                    return item, None
                require(
                    200 <= status < 300
                    and isinstance(data, dict)
                    and valid_handle(probe.credential_path, data.get("lease_id")),
                    "probe_uncertain",
                )
                probe_change(
                    store, probe.acquisition_id, state="issued", lease_handle=data["lease_id"]
                )
                item = recovery.adopt_probe(owner, store, probe.acquisition_id)
                probe = probe_change(
                    store,
                    probe.acquisition_id,
                    state="cleanup_pending",
                    recovery_incident_id=item.incident_id,
                )
                return probe, data
            except asyncio.CancelledError:
                current = next(
                    p
                    for p in store.read().probe_acquisitions
                    if p.acquisition_id == probe.acquisition_id
                )
                if current.state not in {"issued", "cleanup_pending"}:
                    probe_change(store, probe.acquisition_id, state="uncertain")
                raise
            except Exception:
                current = next(
                    p
                    for p in store.read().probe_acquisitions
                    if p.acquisition_id == probe.acquisition_id
                )
                if current.state not in {"issued", "cleanup_pending"}:
                    current = probe_change(store, probe.acquisition_id, state="uncertain")
                return current, None


async def clean_probe(store, acquisition_id, *, transport=None):
    """Rediscover an adopted operation after crashes and require a real exact-cleanup receipt."""
    from agent.recovery.commands import revoke_exact

    recovery = store.recovery
    with recovery.effect() as owner:
        from agent.recovery.workers import descriptor_scope

        with descriptor_scope(owner.fd):
            item = recovery.adopt_probe(owner, store, acquisition_id)
            probe_change(
                store,
                acquisition_id,
                state="cleanup_pending",
                recovery_incident_id=item.incident_id,
            )
            if item.state != "resolved":
                await revoke_exact(recovery, item, transport=transport)
                item = next(
                    a for a in recovery.read().attempts if a.incident_id == item.incident_id
                )
            if item.state == "resolved" and item.receipt and item.resolution == "revoked":
                return probe_change(store, acquisition_id, state="cleaned")
            return next(
                p for p in store.read().probe_acquisitions if p.acquisition_id == acquisition_id
            )


def database_failure(error, *, path, before, healthy):
    """Classify exact server SQLSTATE with an independent before/health control.

    Password denial (28P01) and backend termination (57P01) are different paths.
    Timeout, network bans, cancellation, process loss and errors without a native
    SQLSTATE stay inconclusive. Callers must keep the healthy connection open across
    the event so a server restart cannot masquerade as selective session loss.
    """
    expected = {"fresh": "28P01", "session": "57P01"}.get(path)
    return (
        "proven"
        if before and healthy and expected and getattr(error, "sqlstate", None) == expected
        else "inconclusive"
    )


class DatabaseProbe:
    """Hold independent old/healthy connections and keep passwords exclusively in memory.

    This object belongs to the explicitly authorized proof process, outside the
    application root's cancellation tree. It performs fixed read-only queries and
    exact logins, never chooses a role, edits SQL or terminates a backend itself.
    """

    def __init__(self, parameters, healthy_parameters, *, connect=None):
        """Capture one direct database target and a distinct healthy role on that target."""
        from .models import require

        require(
            all(parameters.get(k) == healthy_parameters.get(k) for k in ("host", "port", "dbname"))
            and parameters.get("user") != healthy_parameters.get("user")
            and parameters.get("user")
            and healthy_parameters.get("user"),
            "mapping_missing",
        )
        self.parameters, self.healthy_parameters = parameters, healthy_parameters
        self.connect = connect
        self.old = self.healthy = None
        self.before = False

    async def open(self, parameters):
        """Open one bounded exact TLS login, using synthetic transport only when injected."""
        import asyncio

        import psycopg

        from .models import require

        require(self.connect or parameters.get("sslmode") == "verify-full", "missing_authority")
        async with asyncio.timeout(10):
            return await (
                self.connect(parameters)
                if self.connect
                else psycopg.AsyncConnection.connect(
                    **parameters, connect_timeout=5, autocommit=True
                )
            )

    async def query(self, connection):
        """Read one fixed liveness value with a short statement and wall-clock deadline."""
        import asyncio

        async with asyncio.timeout(10):
            await connection.execute("SET statement_timeout = '5000ms'")
            cursor = await connection.execute("SELECT 1")
            row = await cursor.fetchone()
            return row == (1,)

    async def prepare(self):
        """Establish both pre-event sessions; any failure leaves the probe inconclusive."""
        self.old = await self.open(self.parameters)
        self.healthy = await self.open(self.healthy_parameters)
        from .models import require

        # Authenticate the healthy role from the server, not merely its DSN spelling.
        identities = []
        for connection in (self.old, self.healthy):
            import asyncio

            async with asyncio.timeout(10):
                await connection.execute("SET statement_timeout = '5000ms'")
                cursor = await connection.execute("SELECT current_user, current_database()")
                identities.append(await cursor.fetchone())
        require(
            len(identities) == 2
            and all(isinstance(row, tuple) and len(row) == 2 for row in identities)
            and identities[0][0] != identities[1][0]
            and identities[0][1] == identities[1][1] == self.parameters["dbname"],
            "mapping_missing",
        )
        self.before = await self.query(self.old) and await self.query(self.healthy)
        return self.before

    async def observe(self, *, replacement=None):
        """Check old login, held session and optional replacement independently after an event."""
        healthy = False
        try:
            healthy = self.healthy is not None and await self.query(self.healthy)
        except Exception:
            pass
        results = {"fresh": "inconclusive", "session": "inconclusive", "new": "not_run"}
        fresh = None
        try:
            fresh = await self.open(self.parameters)
            if await self.query(fresh) and self.before and healthy:
                results["fresh"] = "disproven"
        except Exception as error:
            results["fresh"] = database_failure(
                error, path="fresh", before=self.before, healthy=healthy
            )
        finally:
            if fresh is not None:
                await fresh.close()
        try:
            if self.old is not None and await self.query(self.old) and self.before and healthy:
                results["session"] = "disproven"
        except Exception as error:
            results["session"] = database_failure(
                error, path="session", before=self.before, healthy=healthy
            )
        if replacement is not None:
            new = None
            try:
                from .models import require

                require(
                    all(
                        replacement.get(k) == self.parameters.get(k)
                        for k in ("host", "port", "dbname", "user")
                    ),
                    "mapping_missing",
                )
                new = await self.open(replacement)
                results["new"] = (
                    "proven"
                    if self.before and healthy and await self.query(new)
                    else "inconclusive"
                )
            except Exception:
                results["new"] = "inconclusive"
            finally:
                if new is not None:
                    await new.close()
        return results, healthy

    async def close(self):
        """Dispose private connections even after cancellation; closure is never evidence."""
        for connection in (self.old, self.healthy):
            if connection is not None:
                await connection.close()
        self.old = self.healthy = None
        self.parameters = self.healthy_parameters = {}


def expire_known_probe_jwts(store):
    """Dispose only signature-verified finite JWT acquisitions after expiry plus skew.

    This closes ephemeral issuance inventory, not an enforcement observation. Unknown
    replies and native leases cannot use this route and remain pinned for exact recovery.
    Caller holds effect ownership so a still-running acquisition cannot be overwritten.
    """
    from .models import ProbeAcquisition

    with store.transaction() as (fd, state):
        updated = tuple(
            ProbeAcquisition.model_validate(p.model_dump() | {"state": "cleaned"})
            if p.credential_class == "oauth_jwt"
            and p.state == "issued"
            and p.credential_digest
            and p.credential_expires_at is not None
            and p.credential_expires_at + timedelta(seconds=30) <= now()
            else p
            for p in state.probe_acquisitions
        )
        if updated != state.probe_acquisitions:
            store.commit(fd, state, probe_acquisitions=updated)
