"""Single-worker loopback browser application with server-held credentials.

The browser receives opaque session cookies, CSRF tokens, and public job views.
OAuth completion, admission, effects, and cleanup remain in trusted Python code.
The separate bearer-token API does not share this browser authentication flow.
"""

import asyncio
import time
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
    """List missing or unsupported workspace settings without making provider requests."""
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
    recovery_store=None,
    response_store=None,
    governance_store=None,
):
    """Build the loopback workspace with isolated sessions and one bounded run manager.

    Tests may inject models and transports. Production credentials remain in the
    server; shutdown drains session work before discarding secrets.
    """
    config = settings or Settings()
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise SecurityError("invalid_request")
    if prerequisites(config, supplied_model=model is not None):
        raise SecurityError("configuration_missing")
    origin = f"http://127.0.0.1:{port}"
    cookie_name = f"agent_workspace_{port}"
    telemetry = configure_telemetry(config)
    runtime = Runtime(
        config,
        model=model or selected_model(config),
        telemetry=telemetry,
        response_store=response_store,
    )
    store = SessionStore()
    from agent.recovery.store import RecoveryStore
    from agent.workspace.diagnostics import Diagnostics

    recovery_store = recovery_store or RecoveryStore(config)
    diagnostics = Diagnostics(config, recovery_store, transport=http_transport)
    recovery_store.workspace_required = True

    if governance_store is None:
        from agent.governance.store import GovernanceStore
        from agent.recovery.store import environment_digest

        governance_store = GovernanceStore(
            project=recovery_store.project, environment=environment_digest(config)
        )

    @asynccontextmanager
    async def lifespan(app):
        """Own the HTTP client, auth manager, expiry timer, and orderly session shutdown."""
        try:
            recovery_store.claim_workspace()
            recovery_store.normalize()
        except SecurityError as error:
            # A second initialized workspace cannot start. Missing/damaged state remains
            # visible so an operator can inspect it, and effects still fail closed.
            if str(error) == "recovery_busy":
                recovery_store.release_workspace()
                raise
        async with httpx.AsyncClient(
            timeout=15, follow_redirects=False, trust_env=False, transport=http_transport
        ) as http:
            app.state.auth = WorkspaceAuth(config, http, origin)
            app.state.diagnostics = diagnostics
            app.state.recovery = recovery_store
            app.state.governance = governance_store
            app.state.response = runtime.response_store
            store.subject_held = getattr(runtime.response_store, "subject_held", None)
            app.state.store = store
            app.state.manager = RunsManager(
                runtime,
                app.state.auth,
                store,
                database_reader_factory=database_reader_factory,
                approval_backend=approval_backend,
                recovery_store=recovery_store,
            )

            async def expire():
                """Prune expired bootstrap/session records once per second until shutdown."""
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
                await diagnostics.shutdown()
                recovery_store.release_workspace()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(Boundary, origin=origin)
    app.state.runtime = runtime
    app.state.config = config

    @app.exception_handler(SecurityError)
    async def safe_error(request, error):
        """Convert trusted error codes into the closed public error mapping and HTTP
        status.
        """
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
        if value.code in {"diagnostics_busy", "recovery_busy"}:
            status = 409
        elif value.code.startswith("recovery_") or value.code in {
            "acquisition_uncertain",
            "cleanup_unconfirmed",
        }:
            status = 503
        elif value.code == "request_forbidden" and request.url.path in {
            "/workspace/operations",
            "/workspace/diagnostics",
            "/workspace/recovery/check",
        }:
            status = 403
        return JSONResponse({"error": value.model_dump()}, status_code=status)

    @app.exception_handler(RequestValidationError)
    async def bad_request(request, error):
        """Hide validation details behind a generic invalid-request response."""
        return JSONResponse(
            {"error": WorkflowError.of("invalid_request").model_dump()}, status_code=400
        )

    def cookie(request):
        """Read the workspace’s opaque cookie, rejecting duplicate Cookie headers."""
        raw = request.headers.getlist("cookie")
        if len(raw) > 1:
            raise SecurityError("request_forbidden")
        return cookie_value(raw[0] if raw else "", cookie_name)

    def context(request, *, signed=False):
        """Resolve the cookie to a server-held browser/session context and optionally
        require sign-in.
        """
        key = cookie(request)
        session = store.session(key)
        if signed and (not session or session.state != "active"):
            raise SecurityError("sign_in_required")
        return (session or store.browsers.get(digest(key))) if key else None

    def mutation(request, *, signed=False):
        """Require a valid context and matching CSRF token before a state-changing request."""
        value = context(request, signed=signed)
        if not value:
            raise SecurityError("sign_in_required" if signed else "request_forbidden")
        check_csrf(request.headers.get("x-csrf-token"), value.csrf)
        return value

    async def body(request, model):
        """Parse the strict request model without exposing submitted values in validation
        errors.
        """
        try:
            return model.model_validate_json(await request.body())
        except (ValidationError, ValueError):
            raise SecurityError("invalid_request") from None

    app.state.context = context
    app.state.mutation = mutation
    app.state.body = body

    @app.get("/")
    async def index():
        """Serve the packaged workspace HTML, with security headers added by Boundary."""
        return Response(
            files("agent.workspace").joinpath("static/index.html").read_bytes(),
            media_type="text/html",
        )

    @app.get("/assets/{name}")
    async def asset(name):
        """Serve only the two named packaged assets, rejecting arbitrary file paths."""
        if name not in {"app.js", "style.css"}:
            return Response(status_code=404)
        return Response(
            files("agent.workspace").joinpath("static/" + name).read_bytes(),
            media_type="text/javascript" if name == "app.js" else "text/css",
        )

    @app.get("/workspace/session")
    async def session_view(request: Request):
        """Bootstrap a bounded browser context or project the current session without
        credentials.

        Issue an HttpOnly cookie and expose only configuration names and a CSRF token;
        consume a pending login error once.
        """
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
        try:
            recovery_store.claim_workspace()
        except SecurityError:
            pass
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

    def operations(request):
        """Read aggregate state without refresh or idle touch; disclose only owned incidents."""
        current = context(request)
        if current is None:
            raise SecurityError("request_forbidden")
        try:
            recovery_store.claim_workspace()
        except SecurityError:
            pass
        signed = getattr(current, "state", None) == "active"
        manager = app.state.manager
        owned = set().union(*(job.incidents for job in current.jobs.values())) if signed else set()
        view = recovery_store.status(
            authentication=signed, owned=owned, active_work=manager.owner is not None
        )
        latest = diagnostics.latest
        connection = "unchecked"
        if latest is not None:
            network = [c for c in latest.checks if c.check_id in {"identity", "vault", "database"}]
            connection = (
                "inconclusive"
                if latest.stale or any(c.state in {"unavailable", "inconclusive"} for c in network)
                else "observed"
                if all(c.state == "observed" for c in network)
                else "blocked"
            )
        restriction = manager.containment_view(current if signed else None)
        return view.model_copy(update={"connection": connection, "containment": restriction})

    @app.get("/api/governance")
    async def governance_view(request: Request):
        """Read only the verified session owner's generated governance case projections."""
        current = context(request, signed=True)
        if request.query_params:
            raise SecurityError("invalid_request")
        from agent.governance.models import GovernanceError
        from agent.governance.report import summary

        principal = current.credentials.principal
        if current.credentials.expires <= time.time():
            return {"schema_version": 1, "candidates": [], "reason_code": "sign_in_required"}
        try:
            return summary(governance_store.read(), owner=(principal.issuer, principal.subject))
        except GovernanceError as error:
            return {"schema_version": 1, "candidates": [], "reason_code": str(error)}

    @app.get("/workspace/operations")
    async def operational_view(request: Request):
        """Return separate authentication, connection observations, and durable recovery status."""
        return operations(request).model_dump(mode="json")

    @app.post("/workspace/diagnostics")
    async def check_connection(request: Request):
        """Run one CSRF-protected read-only check, including for a signed-out bootstrap context."""
        mutation(request)
        await body(request, EmptyRequest)
        view = operations(request)
        return (
            await diagnostics.check(
                authentication=view.authentication, last_failure=app.state.manager.last_failure
            )
        ).model_dump(mode="json")

    @app.post("/workspace/recovery/check")
    async def check_recovery(request: Request):
        """Observe durable closure without restoring authority or changing old jobs."""
        mutation(request)
        await body(request, EmptyRequest)
        # Missing/unsafe state remains a safe projection. Contention is an explicit
        # 409; housekeeping never supplies cleanup proof or changes user authority.
        try:
            recovery_store.prune()
        except SecurityError as error:
            if str(error) == "recovery_busy":
                raise
        app.state.manager.check_recovery()
        return operations(request).model_dump(mode="json")

    @app.post("/auth/login")
    async def login(request: Request):
        """Start one CSRF-protected login attempt when the workspace can admit
        authentication.

        Close a prior signed-in context before creating a new bootstrap context;
        provider
        setup failures return a safe identity error.
        """
        current = mutation(request)
        await body(request, EmptyRequest)
        manager = app.state.manager
        if manager and manager.owner is not None:
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
        """Consume a bound one-time login callback and rotate the authenticated session
        cookie.

        Reject duplicate or ambiguous parameters. Provider cancellation and verification
        errors return safe state to the workspace rather than raw provider text.
        """
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
        """Close the session, contain active work, and delete its browser cookie."""
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
        """Admit a CSRF-protected task under its idempotent submission UUID."""
        session = mutation(request, signed=True)
        value = await body(request, TaskSubmission)
        existing = value.submission_id in session.submissions
        job = await app.state.manager.submit(session, value)
        return JSONResponse(
            app.state.manager.project_job(job).model_dump(mode="json"),
            status_code=200 if existing else 202,
        )

    @app.get("/workspace/runs")
    async def list_runs(request: Request):
        """Return reverse-chronological public job views owned by this signed-in session."""
        session = context(request, signed=True)
        return {
            "schema_version": 1,
            "jobs": [
                app.state.manager.project_job(job).model_dump(mode="json")
                for job in reversed(list(session.jobs.values()))
            ],
        }

    @app.get("/workspace/runs/{job_id}")
    async def status(request: Request, job_id: str):
        """Return one owned job view, treating invalid or foreign IDs as not found."""
        session = context(request, signed=True)
        try:
            identifier = UUID(job_id)
        except ValueError:
            raise SecurityError("run_not_found") from None
        return app.state.manager.project_job(app.state.manager.get(session, identifier)).model_dump(
            mode="json"
        )

    @app.post("/workspace/runs/{job_id}/retry")
    async def retry(request: Request, job_id: str):
        """Request a separately admitted exact-action approval retry, never a replay of the
        task.
        """
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
        return JSONResponse(
            app.state.manager.project_job(job).model_dump(mode="json"),
            status_code=200 if existing else 202,
        )

    return app
