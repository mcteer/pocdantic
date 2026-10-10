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
        return {"status": "ok"}

    @app.post("/runs", response_model=AgentResponse)
    async def run(
        request: RequestEnvelope,
        credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)],
    ):
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
