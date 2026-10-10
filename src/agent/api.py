"""Bearer-authenticated HTTP entry point for programmatic callers.

Unlike the browser workspace, this API accepts a token on each request. Identity is
verified before the runtime receives a task; provider credentials stay in adapters.
"""

from contextlib import asynccontextmanager
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr

from .broker import DatabaseBroker
from .cli import selected_model
from .oauth import JWTVerifier, OAuthClient
from .probe import oauth_config
from .runtime import Runtime
from .schemas import AgentResponse, RequestEnvelope
from .security import SecurityError
from .services import VerifyApprovalBackend
from .settings import Settings
from .telemetry import configure_telemetry


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the optional FastAPI service, rejecting missing audience configuration.

    The returned app owns one runtime and a lifespan-managed token verifier.
    """
    config = settings or Settings()
    if not config.oauth_audience:
        raise SecurityError("oauth_audience_missing")
    oauth_settings = oauth_config(config)
    configure_telemetry(config)
    runtime = Runtime(
        config,
        model=selected_model(config),
        approval_backend=VerifyApprovalBackend(config) if config.verify_push_enabled else None,
    )
    bearer = HTTPBearer()

    @asynccontextmanager
    async def lifespan(app):
        """Keep the HTTP client and JWT verifier alive only while the service is running."""
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as http:
            app.state.verifier = JWTVerifier(
                OAuthClient(oauth_settings, http),
                config.oauth_audience,
                token_typ=config.oauth_access_token_typ,
            )
            yield

    app = FastAPI(title="PoCdantic", lifespan=lifespan)

    @app.get("/health")
    async def health():
        """Report process availability; this does not check remote providers."""
        return {"status": "ok"}

    @app.post("/runs", response_model=AgentResponse)
    async def run(
        request: RequestEnvelope,
        credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)],
    ):
        """Verify the supplied bearer token and execute a task with its human identity.

        Invalid identity becomes a generic 401. Database access uses the same token in
        a trusted broker, never a model-supplied credential.
        """
        try:
            principal = await app.state.verifier.verify(SecretStr(credentials.credentials))
        except SecurityError:
            raise HTTPException(status_code=401, detail="identity_invalid") from None
        return await runtime.run(
            request,
            principal,
            database_reader=DatabaseBroker(
                config, SecretStr(credentials.credentials), principal.subject
            )
            if config.database_host
            else None,
        )

    return app
