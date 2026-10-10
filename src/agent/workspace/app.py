"""Single-worker local application; the bearer service stays independent."""

import asyncio
from contextlib import asynccontextmanager
from importlib.resources import files
from uuid import UUID

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import ValidationError

from agent.cli import selected_model
from agent.runtime import Runtime
from agent.security import SecurityError
from agent.settings import Settings
from agent.telemetry import configure_telemetry
from agent.workspace.auth import WorkspaceAuth
from agent.workspace.models import (
    EmptyRequest,
    LoginStart,
    RetrySubmission,
    SessionView,
    TaskSubmission,
    WorkflowError,
)
from agent.workspace.runs import RunsManager
from agent.workspace.security import Boundary, check_csrf, cookie_value
from agent.workspace.sessions import SessionStore, digest


def prerequisites(config, *, supplied_model=False):
    missing = [
        name
        for name in ("LOGIN_CLIENT_ID", "LOGIN_CLIENT_SECRET", "OAUTH_AUDIENCE")
        if not getattr(config, name.lower())
    ]
    if not (config.oauth_discovery_url or config.verify_tenant_url):
        missing.append("OAUTH_DISCOVERY_URL")
    if not 1 <= config.timeout_seconds <= 180:
        missing.append("TIMEOUT_SECONDS")
    if not supplied_model and config.model.startswith("google-gla:") and not config.google_api_key:
        missing.append("GOOGLE_API_KEY")
    return missing


def create_workspace_app(
    settings=None,
    *,
    port=8000,
    model=None,
    http_transport=None,
    database_reader_factory=None,
    approval_backend=None,
):
    config = settings or Settings()
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise SecurityError("invalid_request")
    if prerequisites(config, supplied_model=model is not None):
        raise SecurityError("configuration_missing")
    origin = f"http://127.0.0.1:{port}"
    cookie_name = f"agent_workspace_{port}"
    telemetry = configure_telemetry(config)
    runtime = Runtime(config, model=model or selected_model(config), telemetry=telemetry)
    store = SessionStore()

    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(
            timeout=15, follow_redirects=False, trust_env=False, transport=http_transport
        ) as http:
            app.state.auth = WorkspaceAuth(config, http, origin)
            app.state.store = store
            app.state.manager = RunsManager(
                runtime,
                app.state.auth,
                store,
                database_reader_factory=database_reader_factory,
                approval_backend=approval_backend,
            )

            async def expire():
                while True:
                    store.prune()
                    await asyncio.sleep(1)

            timer = asyncio.create_task(expire())
            try:
                yield
            finally:
                timer.cancel()
                await asyncio.gather(timer, return_exceptions=True)
                await store.shutdown()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(Boundary, origin=origin)
    app.state.runtime = runtime
    app.state.config = config

    @app.exception_handler(SecurityError)
    async def safe_error(request, error):
        code = str(error)
        try:
            value = WorkflowError.of(code)
        except ValueError:
            value = WorkflowError.of("task_failed")
        status = {
            "sign_in_required": 401,
            "run_not_found": 404,
            "workspace_busy": 409,
            "submission_conflict": 409,
            "retry_unavailable": 409,
            "capacity_exceeded": 409,
            "workspace_unavailable": 503,
            "identity_unavailable": 503,
        }.get(value.code, 400)
        return JSONResponse({"error": value.model_dump()}, status_code=status)

    @app.exception_handler(RequestValidationError)
    async def bad_request(request, error):
        return JSONResponse(
            {"error": WorkflowError.of("invalid_request").model_dump()}, status_code=400
        )

    def cookie(request):
        raw = request.headers.getlist("cookie")
        if len(raw) > 1:
            raise SecurityError("request_forbidden")
        return cookie_value(raw[0] if raw else "", cookie_name)

    def context(request, *, signed=False):
        key = cookie(request)
        session = store.session(key)
        if signed and (not session or session.state != "active"):
            raise SecurityError("sign_in_required")
        return (session or store.browsers.get(digest(key))) if key else None

    def mutation(request, *, signed=False):
        value = context(request, signed=signed)
        if not value:
            raise SecurityError("sign_in_required" if signed else "request_forbidden")
        check_csrf(request.headers.get("x-csrf-token"), value.csrf)
        return value

    async def body(request, model):
        try:
            return model.model_validate_json(await request.body())
        except (ValidationError, ValueError):
            raise SecurityError("invalid_request") from None

    app.state.context = context
    app.state.mutation = mutation
    app.state.body = body

    @app.get("/")
    async def index():
        return Response(
            files("agent.workspace").joinpath("static/index.html").read_bytes(),
            media_type="text/html",
        )

    @app.get("/assets/{name}")
    async def asset(name):
        if name not in {"app.js", "style.css"}:
            return Response(status_code=404)
        return Response(
            files("agent.workspace").joinpath("static/" + name).read_bytes(),
            media_type="text/javascript" if name == "app.js" else "text/css",
        )

    @app.get("/workspace/session")
    async def session_view(request: Request):
        current = context(request)
        if current is None:
            try:
                current = store.bootstrap(None)
            except SecurityError as error:
                if str(error) != "capacity_exceeded":
                    raise
                return JSONResponse(
                    {"error": WorkflowError.of("capacity_exceeded").model_dump()}, status_code=429
                )
        signed = getattr(current, "state", None) == "active"
        code = current.login_error
        current.login_error = None
        issues = []
        for setting in (
            "DATABASE_HOST",
            "DATABASE_NAME",
            "VAULT_ADDR",
            "VAULT_AUDIENCE",
            "OAUTH_CLIENT_ID",
            "OAUTH_CLIENT_SECRET",
        ):
            if not getattr(config, setting.lower()):
                issues.append(setting)
        if not config.verify_push_enabled:
            issues.append("VERIFY_PUSH_ENABLED")
        view = SessionView(
            signed_in=signed,
            requires_sign_in=not signed,
            csrf_token=current.csrf,
            profiles=list(runtime.definitions),
            configuration_issues=issues,
            login_error=WorkflowError.of(code) if code else None,
        )
        response = JSONResponse(view.model_dump(mode="json"))
        response.set_cookie(cookie_name, current.cookie, httponly=True, samesite="lax", path="/")
        return response

    @app.post("/auth/login")
    async def login(request: Request):
        current = mutation(request)
        await body(request, EmptyRequest)
        manager = app.state.manager
        if manager and manager.busy:
            raise SecurityError("workspace_busy")
        if hasattr(current, "state"):
            store.close(current)
            current = store.bootstrap(None)
        try:
            url = await app.state.auth.start(current)
        except (SecurityError, KeyError, ValueError, httpx.HTTPError):
            raise SecurityError("identity_unavailable") from None
        response = JSONResponse(LoginStart(authorization_url=url).model_dump())
        response.set_cookie(cookie_name, current.cookie, httponly=True, samesite="lax", path="/")
        return response

    @app.get("/auth/callback")
    async def callback(request: Request):
        current = context(request)
        query = request.query_params
        if (
            not current
            or any(len(query.getlist(k)) > 1 for k in query)
            or any(len(v) > 8192 for _, v in query.multi_items())
            or not query.get("state")
            or bool(query.get("code")) == bool(query.get("error"))
        ):
            raise SecurityError("login_invalid")
        try:
            if query.get("error"):
                app.state.auth.consume(current, query["state"])
                current.login_error = "login_cancelled"
                return RedirectResponse("/", status_code=303)
            credentials = await app.state.auth.complete(current, query["code"], query["state"])
            session = store.authenticate(current, credentials)
        except SecurityError as error:
            if current.attempt is not None:
                raise SecurityError("login_invalid") from None
            current.login_error = (
                "login_invalid" if str(error) != "capacity_exceeded" else "capacity_exceeded"
            )
            return RedirectResponse("/", status_code=303)
        except (httpx.HTTPError, ValueError, TypeError):
            current.login_error = "identity_unavailable"
            return RedirectResponse("/", status_code=303)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(cookie_name, session.cookie, httponly=True, samesite="lax", path="/")
        return response

    @app.post("/auth/logout")
    async def logout(request: Request):
        session = mutation(request)
        if not hasattr(session, "state"):
            raise SecurityError("sign_in_required")
        await body(request, EmptyRequest)
        store.close(session)
        response = Response(status_code=204)
        response.delete_cookie(cookie_name, path="/", httponly=True, samesite="lax")
        return response

    @app.post("/workspace/runs")
    async def submit(request: Request):
        session = mutation(request, signed=True)
        value = await body(request, TaskSubmission)
        existing = value.submission_id in session.submissions
        job = await app.state.manager.submit(session, value)
        return JSONResponse(job.view.model_dump(mode="json"), status_code=200 if existing else 202)

    @app.get("/workspace/runs")
    async def list_runs(request: Request):
        session = context(request, signed=True)
        return {
            "schema_version": 1,
            "jobs": [
                job.view.model_dump(mode="json") for job in reversed(list(session.jobs.values()))
            ],
        }

    @app.get("/workspace/runs/{job_id}")
    async def status(request: Request, job_id: str):
        session = context(request, signed=True)
        try:
            identifier = UUID(job_id)
        except ValueError:
            raise SecurityError("run_not_found") from None
        return app.state.manager.get(session, identifier).view.model_dump(mode="json")

    @app.post("/workspace/runs/{job_id}/retry")
    async def retry(request: Request, job_id: str):
        session = mutation(request, signed=True)
        value = await body(request, RetrySubmission)
        try:
            identifier = UUID(job_id)
        except ValueError:
            raise SecurityError("run_not_found") from None
        parent = app.state.manager.get(session, identifier)
        existing = (
            value.submission_id in session.submissions
            or len(parent.candidates) == 1
            and parent.candidates[0].child is not None
        )
        job = await app.state.manager.retry(session, identifier, value)
        return JSONResponse(job.view.model_dump(mode="json"), status_code=200 if existing else 202)

    return app
