from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
from pydantic import SecretStr

from .oauth import JWTVerifier, OAuthClient
from .probe import oauth_config
from .security import SecurityError
from .settings import Settings
from .vault import VaultClient, read_postgres, validate_path


def validate_delegation(claims: dict, subject: str, actor: dict, details: list[dict]):
    act = claims.get("act")
    if (
        claims.get("sub") != subject
        or not isinstance(act, dict)
        or act.get("sub") != actor["sub"]
        or act.get("iss", actor["iss"]) != actor["iss"]
        or "act" in act
        or claims.get("authorization_details") != details
    ):
        raise SecurityError("delegation_claims_invalid")


@dataclass(frozen=True)
class DatabaseBroker:
    settings: Settings = field(repr=False)
    subject_token: SecretStr = field(repr=False)
    subject: str = field(repr=False)
    observer: Callable[[str], None] | None = field(default=None, repr=False)

    def observe(self, stage: str) -> None:
        if self.observer:
            self.observer(stage)

    async def __call__(self, record_id: int) -> list[dict]:
        try:
            return await self._read(record_id)
        except SecurityError as error:
            self.observe("denied:" + str(error))
            raise

    async def _read(self, record_id: int) -> list[dict]:
        s = self.settings
        if not all(
            (s.vault_addr, s.vault_audience, s.oauth_audience, s.database_host, s.database_name)
        ):
            raise SecurityError("database_integration_not_configured")
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as http:
            oauth = OAuthClient(oauth_config(s), http)
            user_verifier = JWTVerifier(oauth, s.oauth_audience, token_typ=s.oauth_access_token_typ)
            principal = await user_verifier.verify(self.subject_token)
            if principal.subject != self.subject or "database:read" not in principal.scopes:
                raise SecurityError("database_subject_invalid")
            self.observe("subject_verified")
            actor = await oauth.client_credentials()
            actor_claims = await JWTVerifier(
                oauth, s.actor_audience or s.oauth_client_id, token_typ=s.oauth_access_token_typ
            ).verify_claims(actor.access_token)
            if actor_claims["sub"] == self.subject or (
                "client_id" in actor_claims and actor_claims["client_id"] != s.oauth_client_id
            ):
                raise SecurityError("database_actor_invalid")
            self.observe("actor_verified")
            verifier = JWTVerifier(oauth, s.vault_audience, token_typ=s.oauth_access_token_typ)

            async def delegated(details):
                exchanged = await oauth.exchange_details(
                    self.subject_token, actor.access_token, details, s.vault_audience
                )
                claims = await verifier.verify_claims(exchanged.access_token)
                validate_delegation(claims, self.subject, actor_claims, details)
                return exchanged.access_token

            read_details = [
                {
                    "type": "vault:path_access",
                    "path": validate_path(s.vault_read_path),
                    "capabilities": ["read"],
                }
            ]
            read_token = await delegated(read_details)
            self.observe("read_delegation_verified")
            vault = VaultClient(s.vault_addr, s.vault_namespace, http)

            async def revoke(lease_id):
                validate_path(lease_id)
                if not lease_id.startswith(s.vault_read_path + "/"):
                    raise SecurityError("vault_lease_scope_invalid")
                cleanup_details = [
                    {
                        "type": "vault:path_access",
                        "path": "sys/leases/revoke",
                        "capabilities": ["update"],
                        "required_parameters": ["lease_id"],
                        "allowed_parameters": {"lease_id": [lease_id]},
                    }
                ]
                cleanup_token = await delegated(cleanup_details)
                self.observe("cleanup_delegation_verified")
                await vault.revoke(cleanup_token, lease_id)
                self.observe("lease_revoked")

            async with vault.credentials(read_token, s.vault_read_path, revoke=revoke) as lease:
                self.observe("lease_acquired")
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
