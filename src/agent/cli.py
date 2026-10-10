import argparse
import asyncio
import json
import sys
from pathlib import Path

import httpx

from .demo import model as demo_model
from .oauth import JWTVerifier, OAuthClient
from .probe import oauth_config, probe
from .runtime import Runtime
from .schemas import Principal, RequestEnvelope
from .security import SecurityError
from .settings import Settings
from .telemetry import configure_telemetry


def selected_model(settings: Settings):
    if settings.model.startswith("google-gla:") and settings.google_api_key:
        from pydantic_ai.models.google import GoogleModel
        from pydantic_ai.providers.google import GoogleProvider

        return GoogleModel(
            settings.model.split(":", 1)[1],
            provider=GoogleProvider(api_key=settings.google_api_key.get_secret_value()),
        )
    return settings.model


async def authenticated_principal(settings: Settings) -> Principal:
    if not settings.bearer_token or not settings.oauth_audience:
        raise SecurityError("verified_bearer_and_audience_required")
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as http:
        verifier = JWTVerifier(
            OAuthClient(oauth_config(settings), http),
            settings.oauth_audience,
            token_typ=settings.oauth_access_token_typ,
        )
        return await verifier.verify(settings.bearer_token)


async def execute(args) -> int:
    if args.command == "validate":
        from .validation.commands import execute_validation

        return await execute_validation(args)
    settings = Settings()
    if args.command == "push-demo":
        from .push_demo import push_demo

        result = await push_demo(settings)
        print(json.dumps(result))
        return 0 if result["result"]["status"] == "simulated" else 1
    if args.command == "probe":
        print(json.dumps(await probe(settings), indent=2))
        return 0
    if args.command == "demo":
        # Explicitly synthetic mode: no local credentials/Logfire and no external model call.
        runtime = Runtime(Settings(_env_file=None), model=demo_model())
        child_model = demo_model()
        with runtime.agents["ticket-reader"].override(model=child_model):
            result = await runtime.run(
                RequestEnvelope(task="Summarize POC-1"),
                Principal(
                    issuer="offline-demo",
                    subject="synthetic-user",
                    scopes=frozenset({"tickets:read"}),
                ),
            )
        print(result.model_dump_json())
        print(json.dumps({"mode": "synthetic", "audit": runtime.audit.events}))
        return 0 if result.status == "completed" else 1
    principal = await authenticated_principal(settings)
    telemetry = configure_telemetry(settings)
    from .broker import DatabaseBroker
    from .services import VerifyApprovalBackend

    runtime = Runtime(
        settings,
        telemetry=telemetry,
        model=selected_model(settings),
        database_reader=DatabaseBroker(settings, settings.bearer_token, principal.subject)
        if settings.database_host
        else None,
        approval_backend=VerifyApprovalBackend(settings) if settings.verify_push_enabled else None,
    )
    if args.command == "run":
        result = await runtime.run(RequestEnvelope(task=args.task, profile=args.profile), principal)
        print(result.model_dump_json())
        return 0 if result.status == "completed" else 1
    if args.command == "batch":
        failed = False
        with Path(args.input).open() as file:
            for index, line in enumerate(file, 1):
                if not line.strip():
                    continue
                try:
                    request = RequestEnvelope.model_validate_json(line)
                    result = await runtime.run(request, principal)
                    print(result.model_dump_json())
                    failed |= result.status != "completed"
                except ValueError:
                    print(
                        json.dumps(
                            {"status": "failed", "error_code": "invalid_request", "line": index}
                        )
                    )
                    failed = True
        return 1 if failed else 0
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Reusable secure agent PoC runtime")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="Offline synthetic delegation; no network calls")
    sub.add_parser("probe", help="Read-only configuration/connectivity summary")
    sub.add_parser("push-demo", help="Verify phone approval for a simulated restart")
    sub.add_parser("serve", help="Run optional authenticated HTTP service")
    workspace = sub.add_parser("workspace", help="Open a signed-in local browser workspace")
    workspace.add_argument("--port", type=int, default=8000)
    run = sub.add_parser("run")
    run.add_argument("--task", required=True)
    run.add_argument("--profile", default="parent")
    batch = sub.add_parser("batch")
    batch.add_argument("--input", required=True)
    from .validation.commands import add_validation_parser

    add_validation_parser(sub)
    args = parser.parse_args()
    try:
        if args.command == "workspace":
            import socket

            try:
                import uvicorn

                from .workspace.app import create_workspace_app, prerequisites
            except ImportError:
                print("Install the server extra: uv sync --extra server", file=sys.stderr)
                sys.exit(1)
            if not 1024 <= args.port <= 65535:
                print("--port must be between 1024 and 65535.", file=sys.stderr)
                sys.exit(1)
            settings = Settings()
            missing = prerequisites(settings)
            if missing:
                print("Set these workspace settings: " + ", ".join(missing), file=sys.stderr)
                sys.exit(1)
            with socket.socket() as listener:
                try:
                    listener.bind(("127.0.0.1", args.port))
                except OSError:
                    print(
                        "Port unavailable; choose another --port and register its callback.",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                try:
                    app = create_workspace_app(settings, port=args.port)
                except ImportError:
                    extra = (
                        "google"
                        if settings.model.startswith("google")
                        else settings.model.split(":", 1)[0]
                    )
                    print(
                        "Install the selected model extra: uv sync --extra server --extra " + extra,
                        file=sys.stderr,
                    )
                    sys.exit(1)
                print(f"Workspace: http://127.0.0.1:{args.port}", flush=True)
                print(f"Register callback: http://127.0.0.1:{args.port}/auth/callback", flush=True)
                listener.listen(128)
                server = uvicorn.Server(
                    uvicorn.Config(app, access_log=False, proxy_headers=False, log_level="warning")
                )
                server.run(sockets=[listener])
            return
        if args.command == "serve":
            import uvicorn

            from .api import create_app

            uvicorn.run(create_app(), host="127.0.0.1", port=8000)
            return
        sys.exit(asyncio.run(execute(args)))
    except SecurityError as error:
        print(json.dumps({"status": "denied", "error_code": str(error)}), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print(
            json.dumps({"status": "failed", "error_code": "configuration_or_runtime_error"}),
            file=sys.stderr,
        )
        sys.exit(1)
