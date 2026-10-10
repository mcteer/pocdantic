"""Compiled before/event/after proof workflow for explicitly authorized local operators.

Credentials and independent connections live only in this bounded process. The process
releases effect ownership while waiting for an event and reacquires it for privileged
requests. A missing before-state is recorded as inconclusive rather than reconstructed
from current metadata. No scenario dispatches remediation, notification or arbitrary SQL.
"""

import asyncio
import hashlib
import time
from datetime import UTC, datetime
from typing import get_args
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from agent.broker import validate_delegation
from agent.oauth import JWTVerifier, OAuthClient
from agent.probe import oauth_config
from agent.recovery.models import now
from agent.recovery.workers import descriptor_scope
from agent.validation.models import canonical, implementation_revision

from .common import request
from .enrollment import digest, read_secrets
from .models import Observation, ProofInput, Scenario, require
from .proof import DatabaseProbe, acquisition_probe, clean_probe, import_observation, probe_change

SCENARIO_PATHS = {
    "same_jwt": {"block_registration": ("same_jwt",)},
    "fresh_issuance": {
        "block_registration": ("fresh_issuance",),
        "suspend_user": ("fresh_issuance",),
    },
    "native_token": {"revoke_native_token": ("native_token",)},
    "user_sessions": {"revoke_user_sessions": ("tenant_sessions",)},
    "static_database": {
        "rotate_static": ("static_old", "static_new"),
        "terminate_static_sessions": ("static_session",),
    },
    "notification_delivery": {"notify_teams": ("notification",)},
    "dynamic_database": {},
}


def selected_actions(state, incident_id, scenario):
    """Resolve only current immutable incident references, excluding replaced retry attempts."""
    plan = next((p for p in state.provider_plans if p.incident_id == incident_id), None)
    require(plan is not None, "mapping_missing")
    return tuple(
        a
        for a in state.provider_actions
        if a.action_id in plan.action_ids and a.kind in SCENARIO_PATHS[scenario]
    )


def record_results(
    store,
    incident,
    scenario,
    outcomes,
    operator,
    *,
    before=False,
    healthy=False,
    credential_digest=None,
    expires=None,
    source="live_probe",
    binding_ids=None,
):
    """Persist independently classified, reviewed outcomes against exact current actions."""
    state = store.read()
    for action in selected_actions(state, incident.incident_id, scenario):
        if binding_ids is not None and action.binding.binding_id not in binding_ids:
            continue
        for path in SCENARIO_PATHS[scenario][action.kind]:
            result = outcomes.get(path, "inconclusive")
            stamp = now()
            observation = Observation(
                installation_id=state.installation_id,
                environment_digest=state.environment_digest,
                implementation_digest=implementation_revision(),
                enrollment_digest=action.enrollment_digest,
                incident_id=incident.incident_id,
                action_id=action.action_id,
                binding_id=action.binding.binding_id,
                resource_generation=action.binding.generation,
                path=path,
                result=result,
                source=source,
                reviewer=operator,
                observed_at=stamp,
                reviewed_at=stamp,
                source_digest=hashlib.sha256(
                    canonical(
                        {
                            "path": path,
                            "result": result,
                            "before": before,
                            "healthy": healthy,
                            "credential": credential_digest,
                        }
                    )
                ).hexdigest(),
                before_succeeded=before,
                healthy_control=healthy,
                credential_digest=credential_digest,
                credential_expires_at=expires,
            )
            import_observation(store, canonical(observation), store.read().revision)


class Session:
    """Keep one prospective proof's private before-state across an attributable event."""

    def __init__(self, store, run, scenario, inputs, http, *, connect=None):
        """Capture enrolled authority and host ownership; no incoming event chooses targets."""
        self.store, self.run, self.scenario, self.inputs, self.http = (
            store,
            run,
            scenario,
            inputs,
            http,
        )
        self.policy_digest = digest(store.read().enrollment)
        self.before = self.healthy_before = False
        self.expires = self.credential_digest = None
        self.native_accessor = None
        self.sessions = self.healthy_sessions = None
        self.database = self.dynamic_probe = None
        self.static_binding = self.static_metadata = self.static_credentials = None
        self.connect = connect
        self.transport = None
        self.pending = []

    def fence(self):
        """Reject authority replacement or lost root attribution without relying on a live guard."""
        state = self.store.read()
        require(
            state.enrollment is not None and digest(state.enrollment) == self.policy_digest,
            "provider_policy_changed",
        )
        require(any(r.ownership() == self.run.ownership() for r in state.runs), "mapping_missing")
        return state

    async def privileged(self, callback):
        """Serialize one active privileged request; never retain the owner across event waiting."""
        mode = self.store.anchor().recovery_mode
        with self.store.recovery.effect() if mode == "configured" else self.store.effect() as owner:
            with descriptor_scope(owner.fd):
                self.fence()
                async with asyncio.timeout(10):
                    return await callback()

    def binding(self, kind, *, healthy=False):
        """Require one exact configured target, with user/actor mapping derived from the root."""
        policy = self.fence().enrollment
        candidates = [b for b in policy.bindings if b.kind == kind and b.enabled]
        if healthy:
            candidates = [b for b in candidates if b.binding_id == self.inputs.healthy_binding]
        elif kind == "user":
            candidates = [
                b
                for b in candidates
                if (b.user_issuer, b.user_subject) == (self.run.issuer, self.run.subject)
            ]
        elif kind == "registration":
            candidates = [
                b
                for b in candidates
                if (b.actor_issuer, b.actor_subject)
                == (self.run.actor_issuer, self.run.actor_subject)
            ]
        require(len(candidates) == 1, "mapping_missing")
        return candidates[0]

    async def delegated_claims(self, token, run):
        """Verify signature, expiry, human/actor and exact fixed read delegation before use."""
        require(token is not None and run.actor_issuer and run.actor_subject, "missing_authority")
        settings = self.store.settings
        claims = await JWTVerifier(
            OAuthClient(oauth_config(settings), self.http),
            settings.vault_audience,
            token_typ=settings.oauth_access_token_typ,
        ).verify_claims(token)
        require(
            claims.get("iss") == run.issuer and claims.get("sub") == run.subject, "mapping_missing"
        )
        validate_delegation(
            claims,
            run.subject,
            {"iss": run.actor_issuer, "sub": run.actor_subject},
            [
                {
                    "type": "vault:path_access",
                    "path": settings.vault_read_path,
                    "capabilities": ["read"],
                }
            ],
        )
        require(
            type(claims.get("exp")) in (int, float) and claims["exp"] > time.time(),
            "provider_evidence_invalid",
        )
        return claims

    def healthy_root(self):
        """Resolve a distinct registered actor peer; reject arbitrary healthy tokens."""
        root = next(
            (r for r in self.fence().runs if r.root_run_id == self.inputs.healthy_root), None
        )
        require(
            root is not None
            and root.root_run_id != self.run.root_run_id
            and root.workload_definition == self.run.workload_definition
            and (
                self.scenario == "native_token"
                or (root.actor_issuer, root.actor_subject)
                != (self.run.actor_issuer, self.run.actor_subject)
            ),
            "mapping_missing",
        )
        return root

    async def credential_request(self, token, run):
        """Acquire through durable probe/recovery intent, keeping any returned material private."""
        probe, data = await acquisition_probe(
            self.store,
            run.ownership(),
            self.http,
            token.get_secret_value(),
            scenario=self.scenario
            if self.scenario in {"same_jwt", "fresh_issuance", "dynamic_database"}
            else "same_jwt",
        )
        if probe.state in {"issued", "cleanup_pending"}:
            self.pending.append(probe.acquisition_id)
        return probe, data

    async def credential_control(self):
        """Require fresh peer acquisition and confirmed exact cleanup on this provider."""
        root = self.healthy_root()
        await self.delegated_claims(self.inputs.healthy_delegated_token, root)
        probe, data = await self.credential_request(self.inputs.healthy_delegated_token, root)
        if not data:
            return False
        cleaned = await clean_probe(self.store, probe.acquisition_id, transport=self.transport)
        return cleaned.state == "cleaned"

    async def native_lookup(self, token):
        """Use the token itself for a fixed lookup-self; accessor metadata alone is insufficient."""
        settings = self.store.settings
        require(token is not None and settings.vault_addr, "missing_authority")
        headers = {"X-Vault-Token": token.get_secret_value()}
        if settings.vault_namespace:
            headers["X-Vault-Namespace"] = settings.vault_namespace
        return await self.privileged(
            lambda: request(
                self.http,
                "GET",
                settings.vault_addr.rstrip("/") + "/v1/auth/token/lookup-self",
                headers=headers,
            )
        )

    async def tenant_sessions(self, binding):
        """Read only exact enrolled tenant sessions, retaining private IDs solely in memory."""
        settings = self.store.settings
        require(
            settings.verify_tenant_url and binding.origin == settings.verify_tenant_url.rstrip("/"),
            "provider_policy_changed",
        )

        async def read():
            """Authenticate as the fixed admin client and read one exact session list."""
            token = await OAuthClient(
                oauth_config(settings, api=True), self.http
            ).client_credentials()
            return await request(
                self.http,
                "GET",
                f"{binding.origin}/v1.0/auth/sessions/{quote(binding.native_id, safe='')}",
                headers={"Authorization": "Bearer " + token.access_token.get_secret_value()},
            )

        status, data, _ = await self.privileged(read)
        require(
            status == 200 and isinstance(data, list) and len(data) <= 256,
            "provider_evidence_invalid",
        )
        require(binding.session_id_field and binding.session_schema_digest, "proof_required")
        field = binding.session_id_field
        ids = (
            {row for row in data if isinstance(row, str)}
            if field == "@"
            else {
                row.get(field)
                for row in data
                if isinstance(row, dict) and isinstance(row.get(field), str)
            }
        )
        require(
            len(ids) == len(data) and all(0 < len(i) <= 256 for i in ids),
            "provider_evidence_invalid",
        )
        return ids

    def private_dsn(self, binding, purpose):
        """Resolve a pinned secret alias, never a caller-selected database destination."""
        from .database import connection_parameters

        values = read_secrets(self.store)
        alias, expected = (
            getattr(binding, purpose + "_alias"),
            getattr(binding, purpose + "_digest"),
        )
        secret = values.get(alias)
        require(
            secret is not None
            and expected == hashlib.sha256(secret.get_secret_value().encode()).hexdigest(),
            "provider_policy_changed",
        )
        return connection_parameters(
            binding, secret.get_secret_value(), synthetic=self.connect is not None
        )

    async def static_read(self, binding):
        """Read static credentials only in this authorized proof process."""
        settings = self.store.settings
        require(
            settings.vault_token
            and settings.vault_addr
            and (binding.origin, binding.namespace)
            == (settings.vault_addr.rstrip("/"), settings.vault_namespace or ""),
            "provider_policy_changed",
        )
        headers = {"X-Vault-Token": settings.vault_token.get_secret_value()}
        if binding.namespace:
            headers["X-Vault-Namespace"] = binding.namespace

        async def read():
            """Read one isolated static role's ephemeral password and rotation metadata."""
            return await request(
                self.http,
                "GET",
                f"{binding.origin}/v1/{binding.mount}/static-creds/"
                f"{quote(binding.native_id, safe='')}",
                headers=headers,
            )

        status, data, _ = await self.privileged(read)
        require(
            status == 200 and isinstance(data, dict) and isinstance(data.get("data"), dict),
            "provider_evidence_invalid",
        )
        value = data["data"]
        require(
            value.get("username") == binding.username
            and isinstance(value.get("password"), str)
            and 0 < len(value["password"]) <= 8192,
            "mapping_missing",
        )
        return value

    async def prepare(self):
        """Capture actual before-state and independent health before any matching event exists."""
        self.store.check(self.run)
        if self.scenario in {"same_jwt", "dynamic_database"}:
            claims = await self.delegated_claims(self.inputs.delegated_token, self.run)
            self.expires = datetime.fromtimestamp(claims["exp"], UTC)
            self.credential_digest = hashlib.sha256(
                self.inputs.delegated_token.get_secret_value().encode()
            ).hexdigest()
            self.healthy_before = await self.credential_control()
            probe, data = await self.credential_request(self.inputs.delegated_token, self.run)
            self.before = data is not None
            if self.scenario == "same_jwt" and data:
                cleaned = await clean_probe(
                    self.store, probe.acquisition_id, transport=self.transport
                )
                self.before = cleaned.state == "cleaned"
            elif data:
                require(
                    self.store.settings.database_host and self.store.settings.database_name,
                    "missing_authority",
                )
                from types import SimpleNamespace

                from .database import connection_parameters

                policy = self.fence().enrollment
                values = read_secrets(self.store)
                secret = values.get(policy.dynamic_healthy_secret_alias)
                require(
                    secret is not None
                    and policy.dynamic_healthy_secret_digest
                    == hashlib.sha256(secret.get_secret_value().encode()).hexdigest(),
                    "missing_authority",
                )
                healthy = connection_parameters(
                    SimpleNamespace(database=self.store.settings.database_name),
                    secret.get_secret_value(),
                    synthetic=self.connect is not None,
                )
                params = dict(
                    host=self.store.settings.database_host,
                    port=str(self.store.settings.database_port),
                    dbname=self.store.settings.database_name,
                    sslmode="verify-full",
                    sslrootcert=self.store.settings.database_sslrootcert,
                    user=data["data"]["username"] + self.store.settings.database_username_suffix,
                    password=data["data"]["password"],
                )
                healthy.setdefault("port", "5432")
                self.database = DatabaseProbe(params, healthy, connect=self.connect)
                self.before = await self.database.prepare()
                self.dynamic_probe = probe
        elif self.scenario == "native_token":
            status, data, _ = await self.native_lookup(self.inputs.native_token)
            require(status == 200 and isinstance(data, dict), "proof_required")
            value = data.get("data", {})
            owned = [
                a
                for a in self.fence().native_acquisitions
                if a.state == "bound"
                and a.ownership == self.run.ownership()
                and a.binding.native_id == value.get("accessor")
            ]
            require(len(owned) == 1 and value.get("type") == "service", "mapping_missing")
            self.native_accessor = value["accessor"]
            ttl = value.get("ttl")
            require(type(ttl) is int and ttl > 120, "proof_required")
            from datetime import timedelta

            self.expires = now() + timedelta(seconds=ttl)
            self.credential_digest = hashlib.sha256(
                self.inputs.native_token.get_secret_value().encode()
            ).hexdigest()
            peer = self.healthy_root()
            healthy_status, healthy_data, _ = await self.native_lookup(
                self.inputs.healthy_native_token
            )
            healthy_value = healthy_data.get("data", {}) if isinstance(healthy_data, dict) else {}
            require(
                any(
                    a.state == "bound"
                    and a.ownership == peer.ownership()
                    and a.binding.native_id == healthy_value.get("accessor")
                    and a.binding.native_id != self.native_accessor
                    for a in self.fence().native_acquisitions
                ),
                "mapping_missing",
            )
            self.peer_accessor = healthy_value.get("accessor")
            self.before, self.healthy_before = (
                True,
                (
                    healthy_status == 200
                    and healthy_value.get("type") == "service"
                    and type(healthy_value.get("ttl")) is int
                    and healthy_value["ttl"] > 0
                ),
            )
        elif self.scenario == "user_sessions":
            target, healthy = self.binding("user"), self.binding("user", healthy=True)
            require(target.key() != healthy.key(), "mapping_missing")
            self.sessions = await self.tenant_sessions(target)
            self.healthy_sessions = await self.tenant_sessions(healthy)
            self.before, self.healthy_before = bool(self.sessions), bool(self.healthy_sessions)
        elif self.scenario == "static_database":
            binding = self.binding("static_role")
            self.static_binding = binding
            value = await self.static_read(binding)
            params = self.private_dsn(binding, "proof_secret") | {
                "user": binding.username,
                "password": value["password"],
            }
            healthy = self.private_dsn(binding, "healthy_secret")
            self.database = DatabaseProbe(params, healthy, connect=self.connect)
            self.before = await self.database.prepare()
            self.healthy_before = self.before
            self.static_credentials = value
            self.static_metadata = time.monotonic()
        elif self.scenario == "fresh_issuance":
            await self.prepare_fresh()
        else:
            require(False, "proof_required")
        require(self.before and self.healthy_before, "proof_required")

    async def prepare_fresh(self):
        """Verify the supplied human/actor and a baseline fresh delegated issuance."""
        require(self.inputs.subject_token and self.inputs.actor_token, "missing_authority")
        oauth = OAuthClient(oauth_config(self.store.settings), self.http)
        user = await JWTVerifier(
            oauth,
            self.store.settings.oauth_audience,
            token_typ=self.store.settings.oauth_access_token_typ,
        ).verify_claims(self.inputs.subject_token)
        actor = await JWTVerifier(
            oauth,
            self.store.settings.actor_audience or self.store.settings.oauth_client_id,
            token_typ=self.store.settings.oauth_access_token_typ,
        ).verify_claims(self.inputs.actor_token)
        require(
            (user["iss"], user["sub"]) == (self.run.issuer, self.run.subject)
            and (actor["iss"], actor["sub"]) == (self.run.actor_issuer, self.run.actor_subject),
            "mapping_missing",
        )
        self.healthy_before = await self.credential_control()
        token = await self.fresh_exchange()
        if token is not None:
            probe, data = await self.credential_request(token, self.run)
            self.before = (
                data is not None
                and (
                    await clean_probe(self.store, probe.acquisition_id, transport=self.transport)
                ).state
                == "cleaned"
            )

    async def fresh_exchange(self):
        """Track possible OAuth JWT issuance durably before the fixed delegated exchange.

        Returned tokens remain memory-only. Their signed finite expiry is recorded for
        conservative disposal; reply loss remains uncertain with no guessed lifetime.
        """
        from agent.response.models import ResponseError
        from agent.security import SecurityError

        from .models import ProbeAcquisition

        settings = self.store.settings
        # Both supplied credentials must still be valid at the actual dispatch boundary.
        oauth = OAuthClient(oauth_config(settings), self.http)
        user = await JWTVerifier(
            oauth, settings.oauth_audience, token_typ=settings.oauth_access_token_typ
        ).verify_claims(self.inputs.subject_token)
        actor = await JWTVerifier(
            oauth,
            settings.actor_audience or settings.oauth_client_id,
            token_typ=settings.oauth_access_token_typ,
        ).verify_claims(self.inputs.actor_token)
        require(
            (user["iss"], user["sub"]) == (self.run.issuer, self.run.subject)
            and (actor["iss"], actor["sub"]) == (self.run.actor_issuer, self.run.actor_subject),
            "mapping_missing",
        )

        async def exchange():
            """Submit one captured subject/actor pair without client or target substitution."""
            with self.store.transaction() as (fd, state):
                probe = ProbeAcquisition(
                    ownership=self.run.ownership(),
                    credential_path=settings.vault_read_path,
                    enrollment_digest=self.policy_digest,
                    scenario="fresh_issuance",
                    credential_class="oauth_jwt",
                )
                self.store.commit(fd, state, probe_acquisitions=(*state.probe_acquisitions, probe))
            probe_change(self.store, probe.acquisition_id, state="submitted", submitted_at=now())
            try:
                issuing_client = OAuthClient(oauth_config(settings), self.http)
                token = await issuing_client.exchange(
                    self.inputs.subject_token,
                    self.inputs.actor_token,
                    settings.vault_read_path,
                    settings.vault_audience,
                )
                claims = await self.delegated_claims(token.access_token, self.run)
                probe_change(
                    self.store,
                    probe.acquisition_id,
                    state="issued",
                    credential_digest=hashlib.sha256(
                        token.access_token.get_secret_value().encode()
                    ).hexdigest(),
                    credential_expires_at=datetime.fromtimestamp(claims["exp"], UTC),
                )
                self.pending.append(probe.acquisition_id)
                return token.access_token
            except SecurityError as error:
                # Only an actual authenticated HTTP denial closes this dedicated probe.
                if (
                    str(error) in {"oauth_http_401", "oauth_http_403"}
                    and issuing_client.definitive_token_denial
                ):
                    probe_change(self.store, probe.acquisition_id, state="denied_no_issuance")
                    self.fresh_denial_authorization = (
                        issuing_client.token_denial_category is not None
                    )
                    return None
                probe_change(self.store, probe.acquisition_id, state="uncertain")
                raise ResponseError("probe_uncertain") from None
            except BaseException:
                probe_change(self.store, probe.acquisition_id, state="uncertain")
                raise

        return await self.privileged(exchange)

    async def observe(self, incident):
        """Observe each path after requested effects settle, retaining contradictions separately."""
        self.fence()
        healthy = False
        outcomes = {}
        if self.scenario == "same_jwt":
            healthy = await self.credential_control()
            if self.expires <= now():
                outcomes["same_jwt"] = "inconclusive"
            else:
                probe, data = await self.credential_request(self.inputs.delegated_token, self.run)
                outcomes["same_jwt"] = (
                    "proven"
                    if probe.state == "denied_no_issuance" and healthy
                    else "disproven"
                    if data and healthy
                    else "inconclusive"
                )
                if data:
                    await clean_probe(self.store, probe.acquisition_id, transport=self.transport)
        elif self.scenario == "fresh_issuance":
            healthy = await self.credential_control()
            token = await self.fresh_exchange()
            if token is None:
                outcomes["fresh_issuance"] = (
                    "proven"
                    if healthy and getattr(self, "fresh_denial_authorization", False)
                    else "inconclusive"
                )
            else:
                probe, data = await self.credential_request(token, self.run)
                outcomes["fresh_issuance"] = (
                    "proven"
                    if probe.state == "denied_no_issuance" and healthy
                    else "disproven"
                    if data and healthy
                    else "inconclusive"
                )
                if data:
                    await clean_probe(self.store, probe.acquisition_id, transport=self.transport)
        elif self.scenario == "native_token":
            status, data, _ = await self.native_lookup(self.inputs.native_token)
            healthy_status, healthy_data, _ = await self.native_lookup(
                self.inputs.healthy_native_token
            )
            peer = healthy_data.get("data", {}) if isinstance(healthy_data, dict) else {}
            healthy = (
                healthy_status == 200
                and peer.get("accessor") == self.peer_accessor
                and peer.get("type") == "service"
                and type(peer.get("ttl")) is int
                and peer["ttl"] > 0
            )
            definitive = (
                status in {401, 403}
                and isinstance(data, dict)
                and set(data) <= {"errors", "request_id"}
            )
            outcomes["native_token"] = (
                "proven"
                if definitive and healthy and self.expires > now()
                else "disproven"
                if status == 200 and healthy
                else "inconclusive"
            )
        elif self.scenario == "user_sessions":
            remaining = await self.tenant_sessions(self.binding("user"))
            peers = await self.tenant_sessions(self.binding("user", healthy=True))
            healthy = self.healthy_sessions <= peers
            outcomes["tenant_sessions"] = (
                "proven"
                if not self.sessions & remaining and healthy
                else "disproven"
                if healthy
                else "inconclusive"
            )
        elif self.scenario in {"static_database", "dynamic_database"}:
            replacement = None
            if self.scenario == "static_database":
                value = await self.static_read(self.static_binding)
                replacement = self.database.parameters | {"password": value["password"]}
            results, healthy = await self.database.observe(replacement=replacement)
            if self.scenario == "static_database":
                ttl = self.static_credentials.get("ttl")
                # A scheduled rotation that could overlap the attempt prevents attribution.
                attributable = (
                    type(ttl) is int and ttl > time.monotonic() - self.static_metadata + 30
                )
                outcomes = {
                    "static_old": results["fresh"] if attributable else "inconclusive",
                    "static_new": results["new"] if attributable else "inconclusive",
                    "static_session": results["session"],
                }
            else:
                outcomes = {
                    "dynamic_fresh": results["fresh"],
                    "dynamic_session": results["session"],
                }
                record_dynamic(
                    self.store,
                    incident,
                    self.dynamic_probe,
                    outcomes,
                    self.before,
                    healthy,
                    source="synthetic" if self.transport is not None else "live_probe",
                )
        binding_ids = set()
        for action in selected_actions(self.fence(), incident.incident_id, self.scenario):
            binding = action.binding
            if (
                (
                    binding.kind == "registration"
                    and (binding.actor_issuer, binding.actor_subject)
                    == (self.run.actor_issuer, self.run.actor_subject)
                )
                or (
                    binding.kind == "user"
                    and (binding.user_issuer, binding.user_subject)
                    == (self.run.issuer, self.run.subject)
                )
                or (binding.kind == "native_token" and binding.native_id == self.native_accessor)
                or (
                    binding.kind == "static_role"
                    and self.static_binding is not None
                    and binding.key() == self.static_binding.key()
                )
            ):
                binding_ids.add(binding.binding_id)
        record_results(
            self.store,
            incident,
            self.scenario,
            outcomes,
            self.operator,
            before=self.before,
            healthy=healthy,
            credential_digest=self.credential_digest,
            expires=self.expires,
            source="synthetic" if self.transport is not None else "live_probe",
            binding_ids=binding_ids,
        )
        return outcomes

    async def close(self):
        """Dispose connections and attempt exact cleanup; unknown issuance stays pinned."""
        try:
            if self.database is not None:
                await self.database.close()
            for aid in self.pending:
                probe = next(
                    p for p in self.store.read().probe_acquisitions if p.acquisition_id == aid
                )
                if probe.credential_class == "vault_lease" and probe.state in {
                    "issued",
                    "cleanup_pending",
                }:
                    await clean_probe(self.store, aid, transport=self.transport)
        finally:
            self.inputs = ProofInput()
            self.static_credentials = None


def record_dynamic(store, incident, probe, outcomes, before, healthy, *, source="live_probe"):
    """Join a prospective exact-lease database proof to its existing local cleanup action."""
    state = store.read()
    current = next(p for p in state.probe_acquisitions if p.acquisition_id == probe.acquisition_id)
    action = next(
        (
            a
            for a in incident.actions
            if a.kind == "revoke_exact" and a.target_id == current.recovery_incident_id
        ),
        None,
    )
    require(action is not None, "mapping_missing")
    observations = tuple(
        Observation(
            installation_id=state.installation_id,
            environment_digest=state.environment_digest,
            implementation_digest=implementation_revision(),
            enrollment_digest=probe.enrollment_digest,
            incident_id=incident.incident_id,
            action_id=action.action_id,
            binding_id=current.recovery_incident_id,
            resource_generation=probe.ownership.generation,
            path=path,
            result=result,
            source=source,
            before_succeeded=before,
            healthy_control=healthy,
            source_digest=hashlib.sha256(
                canonical({"path": path, "result": result, "probe": str(probe.acquisition_id)})
            ).hexdigest(),
        )
        for path, result in outcomes.items()
    )
    probe_change(store, probe.acquisition_id, observations=(*current.observations, *observations))


async def run_probe(
    store,
    *,
    revision,
    scenario,
    operator,
    inputs,
    root_id=None,
    incident_id=None,
    transport=None,
    connect=None,
    ready=None,
):
    """Run one allowlisted proof for at most 120 seconds; return only closed safe outcomes."""
    import re

    require(
        isinstance(operator, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", operator),
        "provider_evidence_invalid",
    )
    require(scenario in get_args(Scenario), "provider_evidence_invalid")
    inputs = ProofInput.model_validate(inputs.model_dump())
    state = store.read()
    require(state.revision == revision, "revision_conflict")
    require(state.enrollment is not None, "not_enrolled")
    if incident_id is not None:
        incident = next((i for i in state.incidents if i.incident_id == incident_id), None)
        require(incident is not None, "target_unknown")
        outcomes = {
            path: "inconclusive" for paths in SCENARIO_PATHS[scenario].values() for path in paths
        }
        if scenario == "notification_delivery":
            # Delivery is imported native receipt only; probing never resends.
            outcomes = {"notification": "unsupported"}
        else:
            record_results(store, incident, scenario, outcomes, operator)
        return {"schema_version": 1, "reason_code": "proof_required", "outcomes": outcomes}
    run = next((r for r in state.runs if r.root_run_id == root_id), None)
    require(run is not None and run.state == "active", "mapping_missing")
    session = None
    deadline = time.monotonic() + 120
    try:
        async with asyncio.timeout(120):
            async with httpx.AsyncClient(
                transport=transport, timeout=10, trust_env=False, follow_redirects=False
            ) as http:
                session = Session(store, run, scenario, inputs, http, connect=connect)
                session.operator = operator
                session.transport = transport
                await session.prepare()
                prepared = now()
                if ready:
                    ready(
                        {
                            "schema_version": 1,
                            "reason_code": "probe_ready",
                            "root_run_id": str(root_id),
                        }
                    )
                while True:
                    current = session.fence()
                    incident = next(
                        (
                            i
                            for i in current.incidents
                            if i.received_at >= prepared and i.matches(run)
                        ),
                        None,
                    )
                    if incident is not None:
                        actions = selected_actions(current, incident.incident_id, scenario)
                        local_pending = any(
                            a.kind == "revoke_exact"
                            and a.status not in {"confirmed", "failed", "denied", "uncertain"}
                            for a in incident.actions
                        )
                        if scenario == "dynamic_database":
                            exact = next(
                                (
                                    a
                                    for a in incident.actions
                                    if a.kind == "revoke_exact"
                                    and a.target_id == session.dynamic_probe.recovery_incident_id
                                ),
                                None,
                            )
                            # The local worker discovers prospective probe leases after intake.
                            # Do not observe before that exact cleanup has joined and finished.
                            local_pending = (
                                local_pending or exact is None or exact.status == "planned"
                            )
                        if (
                            not any(a.state in {"planned", "submitted"} for a in actions)
                            and not local_pending
                        ):
                            break
                    await asyncio.sleep(0.1)
                outcomes = await session.observe(incident)
                return {
                    "schema_version": 1,
                    "reason_code": "provider_state_observed"
                    if outcomes and all(v == "proven" for v in outcomes.values())
                    else "proof_required",
                    "incident_id": str(incident.incident_id),
                    "outcomes": outcomes,
                }
    except TimeoutError:
        from agent.response.models import ResponseError

        raise ResponseError("provider_timeout") from None
    finally:
        if session is not None:
            # Cleanup is part of the original budget, never an unbounded second attempt.
            try:
                async with asyncio.timeout(max(0.001, deadline - time.monotonic())):
                    await session.close()
            except Exception:
                pass


async def isolated_probe(store, *, inputs, **options):
    """Run the compiled workflow through a bounded private pipe and inherited lifetime lock."""
    import json

    from agent.recovery.workers import network_process
    from agent.response.models import ResponseError

    settings = {
        key: value.get_secret_value() if isinstance(value, SecretStr) else value
        for key, value in store.settings.model_dump().items()
    }
    from uuid import UUID

    settings["google_api_key"] = settings["logfire_token"] = None
    private = {
        key: value.get_secret_value()
        if isinstance(value, SecretStr)
        else str(value)
        if isinstance(value, UUID)
        else value
        for key, value in inputs.model_dump().items()
    }
    payload = json.dumps(
        {
            "settings": settings,
            "project": str(store.project),
            "inputs": private,
            "options": {
                k: str(v) if k in {"root_id", "incident_id"} and v else v
                for k, v in options.items()
            },
        }
    ).encode()
    require(len(payload) <= 1048576, "provider_evidence_invalid")
    try:
        with store._lock("probe.lock") as fd:
            async with asyncio.timeout(120):
                async with network_process(__name__, ownership_fds=(fd,)) as process:
                    process.stdin.write(payload)
                    await process.stdin.drain()
                    process.stdin.close()
                    line = await process.stdout.readline()
                    require(len(line) <= 8192, "provider_uncertain")
                    from agent.validation.store import decode_json

                    output = decode_json(line)
                    if output.get("reason_code") == "probe_ready":
                        print(json.dumps(output), flush=True)
                        line = await process.stdout.readline()
                        require(len(line) <= 8192, "provider_uncertain")
                        output = decode_json(line)
                    await process.wait()
                    require(
                        process.returncode == 0 and isinstance(output, dict), "provider_uncertain"
                    )
                    if output.get("error"):
                        raise ResponseError(output["reason_code"])
                    return output
    except TimeoutError:
        raise ResponseError("provider_timeout") from None
    except ResponseError:
        raise
    except Exception as error:
        from agent.recovery.store import RecoveryError

        reason = "provider_busy" if isinstance(error, RecoveryError) else "provider_uncertain"
        raise ResponseError(reason) from None


async def child():
    """Read private bounded stdin and emit only fixed readiness/results; discard native errors."""
    import json
    import sys
    from uuid import UUID

    from agent.response.models import ResponseError
    from agent.response.store import ResponseStore
    from agent.settings import Settings
    from agent.validation.store import decode_json

    try:
        raw = sys.stdin.buffer.read(1048577)
        require(len(raw) <= 1048576, "provider_evidence_invalid")
        data = decode_json(raw)
        store = ResponseStore(Settings(_env_file=None, **data["settings"]), project=data["project"])
        options = data["options"]
        for key in ("incident_id", "root_id"):
            if options.get(key):
                options[key] = UUID(options[key])
        if options.pop("operation", None) == "readiness":
            from .enrollment import readiness

            mode = store.anchor().recovery_mode
            with store.recovery.effect() if mode == "configured" else store.effect() as owner:
                with descriptor_scope(owner.fd):
                    findings = await readiness(store)
            output = {
                "schema_version": 1,
                "instructions": findings,
                "revision": store.read().revision,
            }
        else:
            output = await run_probe(
                store,
                inputs=ProofInput.model_validate(data["inputs"]),
                ready=lambda result: print(json.dumps(result), flush=True),
                **options,
            )
    except ResponseError as error:
        output = {"schema_version": 1, "error": True, "reason_code": str(error)}
    except Exception:
        output = {"schema_version": 1, "error": True, "reason_code": "provider_uncertain"}
    print(json.dumps(output), flush=True)


if __name__ == "__main__":
    asyncio.run(child())
