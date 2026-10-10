"""Separate loopback relay service with one bounded responder and no browser authority."""

import asyncio
from contextlib import asynccontextmanager
from uuid import UUID

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import SecretStr

from agent.recovery.workers import descriptor_scope

from .auth import SourceAuthenticator
from .coordinator import Coordinator, parse_signal
from .models import REASONS, ResponseError
from .store import ResponseStore

STATUS = {
    "signal_invalid": 400,
    "mapping_missing": 422,
    "provider_capacity": 429,
    "source_invalid": 403,
    "target_unknown": 404,
    "event_conflict": 409,
    "signal_stale": 422,
    "response_capacity": 429,
    "revision_conflict": 409,
    "release_unsafe": 409,
}


def create_response_app(settings, *, store=None, transport=None):
    """Construct a separately authenticated API; no credential or raw exception logging."""
    store = store or ResponseStore(settings)
    coordinator = Coordinator(store, transport=transport)

    @asynccontextmanager
    async def lifespan(app):
        """Claim one worker lifetime and drain dispatched cleanup before releasing it."""
        try:
            with store._lock("worker.lock") as worker_fd, descriptor_scope(worker_fd):
                from agent.telemetry import configure_telemetry

                policy = store.policy()
                if store.read().schema_version != 2:
                    raise ResponseError("response_schema_migration_required")
                telemetry = configure_telemetry(settings)
                coordinator.telemetry = telemetry
                coordinator.normalize()
                from .providers.worker import Worker

                Worker(store).normalize()
                try:
                    store.prune()
                except Exception as error:
                    # Retention must not compete with ordinary owners or mask unsafe storage.
                    if str(error) not in {"response_busy", "recovery_busy"}:
                        raise
                async with httpx.AsyncClient(
                    timeout=1, follow_redirects=False, trust_env=False, transport=transport
                ) as http:
                    app.state.auth = SourceAuthenticator(settings, policy, http)

                    async def work():
                        """Service accepted incidents once; restart only never-submitted work."""
                        initial = {
                            i.incident_id for i in store.read().incidents if i.phase != "settled"
                        }
                        attempted = set()
                        while True:
                            try:
                                state = store.read()
                            except ResponseError as error:
                                if str(error) != "response_busy":
                                    raise
                                await asyncio.sleep(0.25)
                                continue
                            retained = {i.incident_id for i in state.incidents}
                            attempted.intersection_update(retained)
                            initial.intersection_update(retained)
                            for item in state.incidents:
                                if item.incident_id in attempted:
                                    continue
                                if item.phase == "contained" or item.incident_id in initial:
                                    initial.add(item.incident_id)
                                    attempted.add(item.incident_id)
                                    try:
                                        await coordinator.process(item.incident_id)
                                    except ResponseError as error:
                                        if str(error) != "response_busy":
                                            raise
                                        # Durable submitted history still prevents effect replay.
                                        attempted.discard(item.incident_id)
                            await asyncio.sleep(0.25)

                    worker = asyncio.create_task(work())
                    app.state.worker = worker
                    try:
                        yield
                    finally:
                        worker.cancel()
                        await asyncio.gather(worker, return_exceptions=True)
                        telemetry.shutdown()
        except ResponseError:
            raise
        except Exception:
            raise ResponseError("response_busy") from None

    app = FastAPI(
        title="Incident response",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.coordinator = coordinator
    app.state.store = store

    @app.exception_handler(ResponseError)
    async def error(request, error):
        """Emit only a closed reason; validation/provider payloads are never reflected."""
        reason = str(error)
        return JSONResponse(
            {"schema_version": 1, "reason_code": reason, "next_action": REASONS[reason]},
            status_code=STATUS.get(reason, 503),
            headers={"Cache-Control": "no-store"},
        )

    async def source(request):
        """Reject cookies and ordinary credentials; only the captured source policy authorizes."""
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise ResponseError("source_invalid")
        return await app.state.auth.verify(SecretStr(header[7:]))

    @app.post("/response/incidents")
    async def submit(request: Request):
        """Bound body and key-verification time, then durably contain before 202."""
        try:
            async with asyncio.timeout(2):
                sender = await source(request)
                if getattr(app.state, "worker", None) is not None and app.state.worker.done():
                    raise ResponseError("response_storage_error")
                if (
                    request.headers.get("content-type", "").split(";")[0].strip()
                    != "application/json"
                ):
                    return JSONResponse(
                        {
                            "schema_version": 1,
                            "reason_code": "signal_invalid",
                            "next_action": "correct_request",
                        },
                        status_code=415,
                        headers={"Cache-Control": "no-store"},
                    )
                raw = b""
                async for chunk in request.stream():
                    raw += chunk
                    if len(raw) > 16384:
                        return JSONResponse(
                            {
                                "schema_version": 1,
                                "reason_code": "signal_invalid",
                                "next_action": "correct_request",
                            },
                            status_code=413,
                            headers={"Cache-Control": "no-store"},
                        )
                item, new = coordinator.submit(parse_signal(raw), sender)
                return JSONResponse(
                    store.summary(item).model_dump(mode="json"),
                    status_code=202 if new else 200,
                    headers={"Cache-Control": "no-store"},
                )
        except TimeoutError:
            raise ResponseError("response_busy") from None

    @app.post("/response/native/{profile_alias}")
    async def native_submit(request: Request, profile_alias: str):
        """Authenticate an enrolled native relay and persist containment within two seconds."""
        from .auth import NativeAuthenticator
        from .native import project

        try:
            async with asyncio.timeout(2):
                state = store.read()
                profile = (
                    next((p for p in state.enrollment.sources if p.alias == profile_alias), None)
                    if state.schema_version == 2 and state.enrollment
                    else None
                )
                if profile is None:
                    raise ResponseError("source_invalid")
                header = request.headers.get("authorization", "")
                if not header.startswith("Bearer "):
                    raise ResponseError("source_invalid")
                async with httpx.AsyncClient(
                    timeout=1, transport=transport, follow_redirects=False, trust_env=False
                ) as http:
                    await NativeAuthenticator(settings, profile, http).verify(SecretStr(header[7:]))
                if (
                    request.headers.get("content-type", "").split(";")[0].strip()
                    != "application/json"
                ):
                    raise ResponseError("signal_invalid")
                if getattr(app.state, "worker", None) is not None and app.state.worker.done():
                    raise ResponseError("response_storage_error")
                if request.headers.get("content-encoding", "identity") not in {"", "identity"}:
                    raise ResponseError("signal_invalid")
                raw = b""
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > 65536:
                        return JSONResponse(
                            {
                                "schema_version": 1,
                                "reason_code": "signal_invalid",
                                "next_action": "correct_request",
                            },
                            status_code=413,
                            headers={"Cache-Control": "no-store"},
                        )
                    raw += chunk
                projection = project(raw, profile, state)
                signal, rule = projection
                item, new = coordinator.submit(
                    signal,
                    native=profile,
                    rule_alias=rule.alias,
                    native_digest=projection.selected_digest,
                    native_enrollment_digest=projection.enrollment_digest,
                )
                return JSONResponse(
                    {
                        "schema_version": 1,
                        "incident_id": str(item.incident_id),
                        "disposition": "accepted" if new else "duplicate",
                    },
                    status_code=202 if new else 200,
                    headers={"Cache-Control": "no-store"},
                )
        except TimeoutError:
            raise ResponseError("response_busy") from None

    @app.get("/response/incidents/{incident_id}")
    async def status(request: Request, incident_id: str):
        """Return only a source-owned summary; UUID knowledge confers no authority."""
        try:
            async with asyncio.timeout(2):
                sender = await source(request)
                try:
                    key = UUID(incident_id)
                except ValueError:
                    raise ResponseError("target_unknown") from None
                item = coordinator.get(key)
                if item.source != sender.alias:
                    raise ResponseError("target_unknown")
                return JSONResponse(
                    store.summary(item).model_dump(mode="json"),
                    headers={"Cache-Control": "no-store"},
                )
        except TimeoutError:
            raise ResponseError("response_busy") from None

    return app


def serve(settings, port=8002):
    """Reserve a loopback socket before service construction; never permit a public host."""
    import socket

    import uvicorn

    if type(port) is not int or not 1024 <= port <= 65535:
        raise ResponseError("signal_invalid")
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            raise ResponseError("response_busy") from None
        listener.listen(32)
        app = create_response_app(settings)
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                access_log=False,
                proxy_headers=False,
                log_level="critical",
                limit_concurrency=32,
                timeout_keep_alive=5,
            )
        )
        print(f"Response service: http://127.0.0.1:{port}", flush=True)
        server.run(sockets=[listener])
