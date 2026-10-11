"""Observation-only loopback API with separate relay authentication.

The ingress cannot issue credentials or change provider settings. It acknowledges only
a durable safe receipt and hides rejected bodies, claims and private source identifiers.
"""

import asyncio

from pydantic import SecretStr

from .models import GovernanceError
from .source import ingest

STATUS = {
    "capacity_exhausted": 413,
    "identity_rejected": 401,
    "replay_conflict": 409,
    "configuration_changed": 409,
    "source_invalid": 422,
    "invalid_input": 400,
    "source_not_ready": 503,
    "storage_error": 503,
    "workspace_busy": 503,
    "not_initialized": 503,
}


def create_app(store, verifier_factory):
    """Build a separate source API; verifier construction uses enrolled trust only."""
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/governance/native/{alias}")
    async def observation(alias: str, request: Request):
        """Authenticate before parsing and recheck profile generation at durable commit."""
        try:
            if request.headers.get("content-encoding", "identity") not in {"", "identity"}:
                raise GovernanceError("invalid_input")
            if request.headers.get("content-type", "").split(";")[0] != "application/json":
                raise GovernanceError("invalid_input")
            authorization = request.headers.get("authorization", "")
            if not authorization.startswith("Bearer ") or len(authorization) > 16391:
                raise GovernanceError("identity_rejected")
            state = store.read()
            profile = next((s for s in state.sources if s.alias == alias), None)
            if profile is None:
                raise GovernanceError("source_not_ready")
            verifier = verifier_factory(profile)
            async with asyncio.timeout(10):
                claims = await verifier.verify_claims(SecretStr(authorization[7:]))
            raw = b""
            async with asyncio.timeout(10):
                async for chunk in request.stream():
                    raw += chunk
                    if len(raw) > 65536:
                        raise GovernanceError("capacity_exhausted")
            result = ingest(store, alias, raw, claims, expected_source=profile)
            return JSONResponse(result, status_code=202)
        except GovernanceError as error:
            reason = str(error)
            return JSONResponse(
                {"schema_version": 1, "reason_code": reason}, status_code=STATUS.get(reason, 422)
            )
        except Exception:
            return JSONResponse(
                {"schema_version": 1, "reason_code": "identity_rejected"}, status_code=401
            )

    return app


async def serve(store, settings, port):
    """Bind observation intake to numeric loopback using the already configured issuer.

    Enrolled relay authority must use a separate audience from task/actor/Vault tokens;
    source configuration cannot make this server trust an additional issuer.
    """
    import httpx
    import uvicorn

    from agent.oauth import JWTVerifier, OAuthClient, OAuthConfig

    from .models import require

    require(type(port) is int and 1 <= port <= 65535)
    require(settings.oauth_issuer and settings.oauth_discovery_url, "missing_authority")
    async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as http:
        oauth = OAuthClient(
            OAuthConfig(
                issuer=settings.oauth_issuer,
                discovery_url=settings.oauth_discovery_url,
                client_id="observation-verifier",
                client_secret=SecretStr("unused"),
            ),
            http,
        )

        def verifier_factory(profile):
            """Use enrolled audience only after checking separation from existing authority."""
            require(
                profile.issuer == settings.oauth_issuer
                and profile.audience
                not in {
                    settings.oauth_audience,
                    settings.actor_audience,
                    settings.vault_audience,
                    settings.oauth_client_id,
                    settings.login_client_id,
                },
                "identity_rejected",
            )
            return JWTVerifier(oauth, profile.audience, token_typ=settings.oauth_access_token_typ)

        server = uvicorn.Server(
            uvicorn.Config(
                create_app(store, verifier_factory),
                host="127.0.0.1",
                port=port,
                log_config=None,
                access_log=False,
            )
        )
        await server.serve()
