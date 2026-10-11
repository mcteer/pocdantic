"""Explicit operator command boundary and fixed private configuration workflow.

No secret appears in command arguments or public JSON. Privileged provider operations
are separated from read-only status and observation ingress; errors use a closed code.
"""

import asyncio
import json
from uuid import UUID

from agent.recovery.store import environment_digest
from agent.settings import Settings
from agent.validation.store import project_root

from .config import Draft, create_private, read_private
from .models import GovernanceError, require
from .report import ACTIONS, closeout, summary
from .store import GovernanceStore


def add_governance_parser(sub):
    """Register operator commands additively without changing existing CLI behavior."""
    parser = sub.add_parser("govern", help="Review and govern an observed workload")
    commands = parser.add_subparsers(dest="govern_command", required=True)
    commands.add_parser("prepare")
    configure = commands.add_parser("configure")
    configure.add_argument("--revision", type=int, required=True)
    configure.add_argument("--operator", required=True)
    case = commands.add_parser("case")
    cases = case.add_subparsers(dest="case_command", required=True)
    cases.add_parser("prepare").add_argument("--source", required=True)
    commands.add_parser("serve").add_argument("--port", type=int, default=8002)
    relying = commands.add_parser("relying").add_subparsers(dest="relying_command", required=True)
    relying.add_parser("serve")
    commands.add_parser("readiness").add_argument("--candidate", type=UUID, required=True)
    for name in ("observe", "review", "reconcile", "prove", "close", "import"):
        item = commands.add_parser(name)
        item.add_argument("--candidate", type=UUID, required=True)
        item.add_argument("--revision", type=int, required=True)
        if name in {"review", "close", "import"}:
            item.add_argument("--operator", required=True)
        if name == "prove":
            item.add_argument(
                "--scenario", choices=("identity", "permissions", "negatives"), required=True
            )
        if name == "import":
            item.add_argument("--input", required=True)
    enroll = commands.add_parser("enroll")
    enroll.add_argument("--review", type=UUID, required=True)
    enroll.add_argument("--revision", type=int, required=True)
    resolve = commands.add_parser("resolve")
    resolve.add_argument("--attempt", type=UUID, required=True)
    resolve.add_argument("--revision", type=int, required=True)
    resolve.add_argument("--operator", required=True)
    commands.add_parser("status").add_argument("--candidate", type=UUID)
    commands.add_parser("closeout").add_argument("--candidate", type=UUID, required=True)


async def execute_governance(args, *, store=None):
    """Execute local state commands and emit safe JSON; adapters never echo provider text."""
    try:
        settings = Settings() if store is None else None
        if store is None:
            store = GovernanceStore(
                project=project_root(), environment=environment_digest(settings)
            )
        command = args.govern_command
        if command == "prepare":
            store.prepare()
            create_private(store, "config.draft.json", {"schema_version": 1, "sources": []})
            create_private(
                store,
                "secrets.json",
                {"schema_version": 1, "operator": None, "candidate": None, "healthy": None},
            )
            result = summary(store.read())
        elif command == "configure":
            from pydantic import TypeAdapter

            from .models import Alias

            TypeAdapter(Alias).validate_python(args.operator)
            draft = Draft.model_validate(read_private(store, "config.draft.json"))
            result = summary(store.configure(draft.sources, args.revision))
        elif command == "case":
            candidate = store.case(args.source)
            create_private(
                store,
                f"candidate-{candidate.candidate_id}.draft.json",
                {"schema_version": 1, "binding": None},
            )
            result = {
                "schema_version": 1,
                "candidate_id": str(candidate.candidate_id),
                "case_id": str(candidate.case_id),
                "alias": candidate.alias,
                "state": "prepared",
            }
        elif command == "import":
            from .evidence import import_file

            with store.lock("effect.lock"):
                item = import_file(
                    store, args.input, args.candidate, args.operator, revision=args.revision
                )
            result = {
                "schema_version": 1,
                "evidence_id": str(item.evidence_id),
                "revision": store.read().revision,
            }
        elif command in {"close", "resolve"}:
            from .evidence import close, resolve

            if command == "close":
                result = summary(
                    close(store, args.candidate, args.operator, revision=args.revision)
                )
            else:
                result = summary(
                    resolve(store, args.attempt, args.operator, revision=args.revision)
                )
        elif command == "serve":
            from .api import serve

            require(settings is not None, "missing_authority")
            await serve(store, settings, args.port)
            return 0
        elif command == "relying":
            from agent.recovery.store import RecoveryStore
            from agent.response.store import ResponseStore

            from .relying import serve

            require(settings is not None, "missing_authority")
            settings = Settings.model_construct(**public_selectors(settings))
            recovery = RecoveryStore(settings, project=store.project)
            response = ResponseStore(settings, project=store.project, recovery=recovery)
            await serve(store, response, recovery)
            return 0
        elif command in {"readiness", "observe", "review", "enroll", "reconcile", "prove"}:
            require(settings is not None, "missing_authority")
            result = await effect(args, store, settings)
        elif command == "status":
            result = summary(store.read())
            if args.candidate:
                result["candidates"] = [
                    c for c in result["candidates"] if c["candidate_id"] == str(args.candidate)
                ]
                result["attempts"] = [
                    a
                    for a in result.get("attempts", [])
                    if a["candidate_id"] == str(args.candidate)
                ]
                require(result["candidates"])
        elif command == "closeout":
            result = closeout(store.read(), args.candidate)
        else:
            raise GovernanceError("unsupported")
        if command not in {"status", "closeout"}:
            result.setdefault("revision", store.read().revision)
        print(json.dumps(result))
        if result.get("ready") is False:
            return 3
        if result.get("result") in {"fail", "inconclusive", "blocked"} or any(
            value != "pass" for value in result.get("results", {}).values()
        ):
            return 4
        return 0
    except GovernanceError as error:
        code = str(error)
        print(
            json.dumps(
                {"schema_version": 1, "reason_code": code, "next_action": ACTIONS.get(code, "")}
            )
        )
        if error.effect:
            return 4
        return (
            2
            if code == "invalid_input"
            else 4
            if code
            in {"creation_uncertain", "effect_uncertain", "identity_rejected", "bootstrap_mismatch"}
            else 3
        )
    except Exception:
        print('{"schema_version":1,"reason_code":"invalid_input"}')
        return 2


async def effect(args, store, settings):
    """Own existing anchors before starting a compiled child; private input never becomes argv."""
    from agent.recovery.store import RecoveryStore
    from agent.recovery.workers import OWNERSHIP_FDS
    from agent.response.store import ResponseStore

    from .coordinator import Coordinator, guarded
    from .enrollment import review
    from .workers import run

    recovery = RecoveryStore(settings, project=store.project)
    response = ResponseStore(settings, project=store.project, recovery=recovery)
    coordinator = Coordinator(store, response, recovery)
    with coordinator.ownership(allow_unresolved=args.govern_command in {"readiness", "reconcile"}):
        store.recover_submissions()
        if args.govern_command == "review":
            from .config import create_private

            decision = review(store, args.candidate, args.revision, args.operator)
            item = next(c for c in store.read().candidates if c.candidate_id == args.candidate)
            create_private(
                store,
                f"review-{decision.review_id}.json",
                {
                    "schema_version": 1,
                    "review": decision.model_dump(mode="json"),
                    "binding": item.binding.model_dump(mode="json"),
                },
            )
            return {
                "schema_version": 1,
                "review_id": str(decision.review_id),
                "candidate_id": str(args.candidate),
                "revision": store.read().revision,
            }
        # Carry only the nonsecret selectors used to verify existing anchors, plus
        # fixed OAuth adapter configuration. The child cannot load .env.local.
        names = (
            "vault_addr",
            "vault_namespace",
            "vault_read_path",
            "database_host",
            "database_port",
            "database_name",
            "database_username_suffix",
            "oauth_issuer",
            "oauth_discovery_url",
            "oauth_audience",
            "vault_audience",
            "actor_audience",
            "oauth_client_id",
            "workload_definition",
            "profiles_file",
            "login_client_id",
            "oauth_access_token_typ",
        )
        payload = {
            "project": str(store.project),
            "environment": store.environment,
            "ownership": list(OWNERSHIP_FDS.get()),
            "settings": {name: getattr(settings, name) for name in names},
            "revision": getattr(args, "revision", store.read().revision),
        }
        if hasattr(args, "candidate"):
            payload["candidate"] = str(args.candidate)
        if hasattr(args, "review"):
            payload["review"] = str(args.review)
        operation = (
            "reconcile-case"
            if args.govern_command == "reconcile"
            else args.scenario
            if args.govern_command == "prove"
            else args.govern_command
        )
        if operation == "permissions":
            payload["human"] = await human_input()
        return await guarded(lambda: run(operation, payload), coordinator.check)


async def human_input():
    """Read a closed non-TTY JSON object with a ten-second deadline and 64-KiB bound."""
    import os
    import sys

    from agent.validation.store import decode_json

    require(not sys.stdin.isatty(), "missing_authority")
    loop = asyncio.get_running_loop()
    raw = bytearray()
    fd = sys.stdin.fileno()
    future = loop.create_future()

    def readable():
        """Accumulate only bounded private bytes; EOF is required for one complete object."""
        try:
            chunk = os.read(fd, 8192)
            raw.extend(chunk)
            require(len(raw) <= 65536, "capacity_exhausted")
            if not chunk and not future.done():
                future.set_result(bytes(raw))
        except Exception:
            if not future.done():
                future.set_exception(GovernanceError("invalid_input"))

    import stat

    regular = stat.S_ISREG(os.fstat(fd).st_mode)
    if regular:
        # epoll cannot watch a regular redirected file. Its bounded read does not
        # await a producer, so handle that supported non-TTY input synchronously.
        data = os.read(fd, 65537)
        require(len(data) <= 65536, "capacity_exhausted")
        value = decode_json(data)
    else:
        loop.add_reader(fd, readable)
        try:
            async with asyncio.timeout(10):
                value = decode_json(await future)
        finally:
            loop.remove_reader(fd)
    require(
        isinstance(value, dict)
        and set(value) == {"schema_version", "human_token"}
        and value["schema_version"] == 1
        and type(value["human_token"]) is str
        and 0 < len(value["human_token"]) <= 16384
    )
    return value["human_token"]


def public_selectors(settings):
    """Copy only noncredential settings needed by read-only service anchor validation."""
    names = (
        "vault_addr",
        "vault_namespace",
        "vault_read_path",
        "database_host",
        "database_port",
        "database_name",
        "database_username_suffix",
        "oauth_issuer",
        "oauth_discovery_url",
        "oauth_audience",
        "vault_audience",
        "actor_audience",
        "oauth_client_id",
        "workload_definition",
        "profiles_file",
        "login_client_id",
        "oauth_access_token_typ",
    )
    return {name: getattr(settings, name) for name in names}
