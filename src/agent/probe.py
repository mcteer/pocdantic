"""Explicit live configuration probe with sanitized connectivity summaries.

This command may issue an API token and save a private device inventory. It does
not provision providers; its summary is not proof of delegated user authorization.
"""

import httpx

from .oauth import OAuthClient, OAuthConfig
from .security import SecurityError
from .settings import Settings
from .vault import VaultClient
from .verify import VerifyClient


def oauth_config(settings: Settings, *, api: bool = False) -> OAuthConfig:
    """Select API-client or agent OAuth settings and derive the configured provider
    endpoints.
    """
    client_id = settings.verify_api_client_id if api else settings.oauth_client_id
    secret = settings.verify_api_client_secret if api else settings.oauth_client_secret
    if not client_id or not secret:
        raise SecurityError("oauth_client_missing")
    discovery = settings.oauth_discovery_url
    if not discovery and settings.oauth_provider == "verify" and settings.verify_tenant_url:
        discovery = (
            settings.verify_tenant_url + "/v1.0/endpoint/default/.well-known/openid-configuration"
        )
    token_endpoint, issuer = settings.oauth_token_endpoint, settings.oauth_issuer
    if api and settings.oauth_provider == "verify" and settings.verify_tenant_url:
        # Privileged Verify API clients use the administrative provider independently.
        discovery = (
            settings.verify_tenant_url + "/v1.0/endpoint/default/.well-known/openid-configuration"
        )
        token_endpoint, issuer = None, None
    return OAuthConfig(
        discovery_url=discovery,
        token_endpoint=token_endpoint,
        issuer=issuer,
        client_id=client_id,
        client_secret=secret,
        auth_method=settings.oauth_auth_method,
    )


async def probe(settings: Settings) -> dict:
    """Read-only checks. Only safe summaries leave this function."""
    result = {"verify": {}, "vault": {}, "logfire": {"configured": bool(settings.logfire_token)}}
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as http:
        try:
            oauth = OAuthClient(oauth_config(settings, api=True), http)
            metadata = await oauth.metadata()
            result["verify"]["discovery"] = "reachable"
            result["verify"]["token_exchange_advertised"] = (
                "urn:ietf:params:oauth:grant-type:token-exchange"
                in metadata.get("grant_types_supported", [])
            )
            result["verify"]["rar_types"] = metadata.get(
                "authorization_details_types_supported", []
            )
            token = await oauth.client_credentials()
            result["verify"]["api_client_auth"] = "accepted"
            if settings.verify_tenant_url:
                client = VerifyClient(settings.verify_tenant_url, token.access_token, http)
                for key, path in [
                    ("profiles", "v1.0/authenticators/clients"),
                    ("authenticators", "v1.0/authenticators"),
                ]:
                    try:
                        data = await client.request("GET", path)
                        records = data.get("authenticators", data.get("clients", []))
                        result["verify"][key] = {
                            "status": "readable",
                            "count": len(records) if isinstance(records, list) else None,
                        }
                        # Private inventory assists local enrollment/configuration; never stdout.
                        from pathlib import Path

                        directory = Path(".local")
                        directory.mkdir(mode=0o700, exist_ok=True)
                        file = directory / f"verify-{key}.json"
                        import json

                        file.write_text(json.dumps(data, indent=2))
                        file.chmod(0o600)
                    except SecurityError as error:
                        result["verify"][key] = {"status": str(error)}
        except SecurityError as error:
            result["verify"]["status"] = str(error)
        if settings.vault_addr:
            try:
                vault = VaultClient(settings.vault_addr, settings.vault_namespace, http)
                health = await http.get(
                    settings.vault_addr + "/v1/sys/health", params={"standbyok": "true"}
                )
                result["vault"]["health_http"] = health.status_code
                if health.status_code == 200:
                    data = health.json()
                    result["vault"]["version"] = data.get("version")
                    result["vault"]["sealed"] = data.get("sealed")
                if settings.vault_token:
                    data = await vault.read(settings.vault_token, "auth/token/lookup-self")
                    result["vault"]["operator_token"] = "accepted"
                    result["vault"]["has_entity"] = bool(data.get("data", {}).get("entity_id"))
                    mounts = await vault.read(settings.vault_token, "sys/mounts")
                    result["vault"]["database_engine"] = any(
                        x.get("type") == "database" for x in mounts.get("data", {}).values()
                    )
            except (SecurityError, httpx.HTTPError, ValueError) as error:
                result["vault"]["status"] = (
                    str(error) if isinstance(error, SecurityError) else "unreachable"
                )
    return result
