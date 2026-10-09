from dataclasses import dataclass, field

import httpx
from pydantic import SecretStr

from .oauth import JWTVerifier, OAuthClient
from .probe import oauth_config
from .security import SecurityError
from .settings import Settings
from .vault import VaultClient, read_postgres


@dataclass(frozen=True)
class DatabaseBroker:
    settings: Settings = field(repr=False)
    subject_token: SecretStr = field(repr=False)
    subject: str = field(repr=False)

    async def __call__(self, record_id: int) -> list[dict]:
        s = self.settings
        if not all((s.vault_addr, s.vault_audience, s.database_host, s.database_name)):
            raise SecurityError("database_integration_not_configured")
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as http:
            oauth = OAuthClient(oauth_config(s), http)
            actor = await oauth.client_credentials()
            verifier = JWTVerifier(oauth, s.vault_audience, token_typ=s.oauth_access_token_typ)
            exchanged = await oauth.exchange(
                self.subject_token, actor.access_token, s.vault_read_path, s.vault_audience
            )
            claims = await verifier.verify_claims(exchanged.access_token)
            # Verify subject and actor identities independently, plus exact granted constraints.
            metadata = await oauth.metadata()
            actor_verifier = JWTVerifier(
                oauth, s.actor_audience or s.oauth_client_id, token_typ=s.oauth_access_token_typ
            )
            actor_claims = await actor_verifier.verify_claims(actor.access_token)
            expected = [
                {"type": "vault:path_access", "path": s.vault_read_path, "capabilities": ["read"]}
            ]
            if (
                claims["sub"] != self.subject
                or claims.get("act", {}).get("sub") != actor_claims["sub"]
                or claims.get("authorization_details") != expected
                or claims["iss"] != metadata["issuer"]
            ):
                raise SecurityError("delegation_claims_invalid")
            vault = VaultClient(s.vault_addr, s.vault_namespace, http)
            async with vault.credentials(exchanged.access_token, s.vault_read_path) as lease:
                return await read_postgres(
                    lease,
                    host=s.database_host,
                    port=s.database_port,
                    database=s.database_name,
                    record_id=record_id,
                    sslrootcert=s.database_sslrootcert,
                    username_suffix=s.database_username_suffix,
                )
