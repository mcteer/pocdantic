"""Trusted database credential flow using human and workload token delegation.

The model supplies only a bounded record ID. This adapter verifies both identities,
requests narrowly scoped Vault credentials, runs fixed SQL, and arranges cleanup.

The human token identifies whose permission is used; the actor token identifies the
agent client acting for them. Authorization details describe the exact provider path
and operations requested, rather than asking for a general-purpose Vault token.
"""

import json
import re
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass, field
from functools import partial
from uuid import uuid4

import httpx
from pydantic import SecretStr

from .oauth import JWTVerifier, OAuthClient
from .probe import oauth_config
from .security import SecurityError
from .settings import Settings
from .vault import VaultClient, read_postgres, validate_path


def validate_delegation(claims: dict, subject: str, actor: dict, details: list[dict]):
    """Require the exchanged claims to bind the human, actor, issuer, and requested rights.

    A signed token alone is insufficient: its delegation fields must match the
    identities and authorization details used for this exchange.
    """
    act = claims.get("act")
    if (
        claims.get("sub") != subject
        or not isinstance(act, dict)
        or act.get("sub") != actor["sub"]
        or act.get("iss", actor["iss"]) != actor["iss"]
        or "act" in act
        or json.dumps(
            claims.get("authorization_details"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        != json.dumps(details, sort_keys=True, separators=(",", ":"), allow_nan=False)
    ):
        raise SecurityError("delegation_claims_invalid")


@dataclass(frozen=True)
class DatabaseBroker:
    settings: Settings = field(repr=False)
    subject_token: SecretStr = field(repr=False)
    subject: str = field(repr=False)
    observer: Callable[[str], None] | None = field(default=None, repr=False)

    operation_observer: object = field(default=None, repr=False)
    cleanup_timeout: float = 30
    recovery_store: object = field(default=None, repr=False)
    effect_owner: object = field(default=None, repr=False)

    http: httpx.AsyncClient | None = field(default=None, repr=False)

    def __post_init__(self):
        """Keep one shared store instance so durability failures remain latched across calls."""
        if self.recovery_store is None:
            from .recovery.store import RecoveryStore

            object.__setattr__(self, "recovery_store", RecoveryStore(self.settings))

    def observe(self, stage: str) -> None:
        """Publish a bounded lifecycle stage to the optional trusted observer callback."""
        if self.observer:
            try:
                self.observer(stage)
            except Exception:
                if self.operation_observer:
                    self.operation_observer.failed = True
        typed = {
            "subject_verified": ("identity", "verified"),
            "actor_verified": ("identity", "verified"),
            "read_delegation_verified": ("credential", "verified"),
            "cleanup_delegation_verified": ("cleanup", "verified"),
            "database_read_completed": ("database", "completed"),
            "lease_revoked": ("cleanup", "revoked"),
        }
        if self.operation_observer and stage in typed:
            self.operation_observer.record(*typed[stage])

    async def __call__(self, record_id: int) -> list[dict]:
        """Read one record through verified delegation, rejecting incomplete configuration."""
        from .recovery.store import RecoveryStore

        store = self.recovery_store or RecoveryStore(self.settings)
        ownership = nullcontext(self.effect_owner) if self.effect_owner else store.effect()
        try:
            with ownership as owner:
                owner.require(store)
                journal = store.read()
                unfinished = [a for a in journal.attempts if a.state != "resolved"]
                if unfinished:
                    from .recovery.store import RecoveryError

                    raise RecoveryError(unfinished[0].reason_code)
                return await self._read(record_id, store, owner)
        except SecurityError as error:
            self.observe("denied:" + str(error))
            raise

    async def _read(self, record_id: int, store, owner) -> list[dict]:
        """Exchange human-plus-actor authority, acquire a lease, and read within its
        lifetime.

        Cleanup obtains separate authority scoped to the exact lease. Native tokens and
        credentials remain inside this adapter and are not returned with the rows.
        """
        s = self.settings
        if not all(
            (s.vault_addr, s.vault_audience, s.oauth_audience, s.database_host, s.database_name)
        ):
            raise SecurityError("database_integration_not_configured")
        context = (
            nullcontext(self.http)
            if self.http is not None
            else httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False)
        )
        async with context as http:
            oauth = OAuthClient(oauth_config(s), http)
            user_verifier = JWTVerifier(oauth, s.oauth_audience, token_typ=s.oauth_access_token_typ)
            principal = await user_verifier.verify(self.subject_token)
            if principal.subject != self.subject or "database:read" not in principal.scopes:
                raise SecurityError("database_subject_invalid")
            self.observe("subject_verified")
            operation_observer = self.operation_observer

            def begin_identity():
                """Record private identity-operation metadata before making its token
                request.
                """
                if (
                    operation_observer
                    and operation_observer.validation_id
                    and operation_observer.observation_id
                ):
                    return operation_observer.begin_operation(
                        validation_id=operation_observer.validation_id,
                        observation_id=operation_observer.observation_id,
                        phase="identity",
                        source_kind="verify",
                        source_instance=s.oauth_issuer or s.verify_tenant_url or "verify",
                    )
                return None

            actor_binding = begin_identity()
            actor = await oauth.client_credentials()
            actor_claims = await JWTVerifier(
                oauth, s.actor_audience or s.oauth_client_id, token_typ=s.oauth_access_token_typ
            ).verify_claims(actor.access_token)
            if actor_claims["sub"] == self.subject or (
                "client_id" in actor_claims and actor_claims["client_id"] != s.oauth_client_id
            ):
                raise SecurityError("database_actor_invalid")
            if actor_binding:
                operation_observer.finish_operation(actor_binding)
            self.observe("actor_verified")
            verifier = JWTVerifier(oauth, s.vault_audience, token_typ=s.oauth_access_token_typ)

            async def delegated(details):
                """Exchange and verify a token for the exact authorization details
                supplied.
                """
                exchange_binding = begin_identity()
                exchanged = await oauth.exchange_details(
                    self.subject_token, actor.access_token, details, s.vault_audience
                )
                claims = await verifier.verify_claims(exchanged.access_token)
                validate_delegation(claims, self.subject, actor_claims, details)
                if exchange_binding:
                    operation_observer.finish_operation(exchange_binding)
                return exchanged.access_token

            # Reading a credential and revoking it are different rights; do not widen this token.
            read_details = [
                {
                    "type": "vault:path_access",
                    "path": validate_path(s.vault_read_path),
                    "capabilities": ["read"],
                }
            ]
            read_token = await delegated(read_details)
            self.observe("read_delegation_verified")
            from .recovery.lifecycle import CredentialLifecycle

            vault = VaultClient(
                s.vault_addr,
                s.vault_namespace,
                http,
                operation_observer=self.operation_observer,
                credential_lifecycle=CredentialLifecycle(
                    store,
                    owner,
                    self.operation_observer,
                    on_completed=partial(self.observe, "lease_revoked"),
                ),
            )

            async def revoke(lease_id):
                """Validate the lease handle and obtain exact-lease authority for
                revocation.

                Require synchronous provider completion. Publish cleanup completion
                only after the lifecycle commits its durable receipt.
                """
                prefix = s.vault_read_path + "/"
                if not lease_id.startswith(prefix) or not re.fullmatch(
                    r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", lease_id.removeprefix(prefix)
                ):
                    raise SecurityError("vault_lease_scope_invalid")
                # Bind cleanup authority to this native lease, not the whole credentials role.
                cleanup_details = [
                    {
                        "type": "vault:path_access",
                        "path": "sys/leases/revoke",
                        "capabilities": ["update"],
                        "required_parameters": ["lease_id", "sync"],
                        "allowed_parameters": {"lease_id": [lease_id], "sync": [True]},
                    }
                ]
                cleanup_token = await delegated(cleanup_details)
                self.observe("cleanup_delegation_verified")
                await vault.revoke(cleanup_token, lease_id)

            async with vault.credentials(
                read_token, s.vault_read_path, revoke=revoke, cleanup_timeout=self.cleanup_timeout
            ) as lease:
                self.observe("lease_acquired")
                if operation_observer:
                    operation_observer.record("database", "attempted", operation_ref=uuid4())
                rows = await read_postgres(
                    lease,
                    host=s.database_host,
                    port=s.database_port,
                    database=s.database_name,
                    record_id=record_id,
                    sslrootcert=s.database_sslrootcert,
                    username_suffix=s.database_username_suffix,
                )
                self.observe("database_read_completed")
                return rows
