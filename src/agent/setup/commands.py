"""Non-overwriting local setup and bounded, explicit readiness dispatch."""

import os
from pathlib import Path

from agent.security import SecurityError


def add_setup_parser(subparsers):
    """Expose setup without credential flags, remote provisioning or alternate storage roots."""
    parser = subparsers.add_parser("setup", help="Configure a reusable local PoC")
    commands = parser.add_subparsers(dest="setup_command", required=True)
    init = commands.add_parser("init", help="Create private configuration without overwriting")
    init.add_argument("--mode", choices=["user-jwt", "delegated-exchange"], required=True)
    check = commands.add_parser("check", help="Check required settings without issuing credentials")
    check.add_argument(
        "--network", action="store_true", help="Observe public endpoints; no credential issuance"
    )


def initialize(mode, *, project=None):
    """Create a 0600 template atomically; existing files and symlinks are never overwritten."""
    if mode not in {"user-jwt", "delegated-exchange"}:
        raise SecurityError("configuration_missing")
    root = Path(project or Path.cwd()).absolute()
    if root.resolve() != root:
        raise SecurityError("configuration_missing")
    path = root / ".env.local"
    if path.exists() or path.is_symlink():
        return {
            "status": "unchanged",
            "next_action": "Edit existing .env.local privately, then run agent setup check.",
        }
    content = f"""# Private local PoC configuration. Never commit this file.
DATABASE_AUTH_MODE={mode}
OAUTH_PROVIDER=generic
OAUTH_DISCOVERY_URL=
OAUTH_ISSUER=
OAUTH_AUDIENCE=
OAUTH_ACCESS_TOKEN_TYP=at+jwt
LOGIN_CLIENT_ID=
LOGIN_CLIENT_SECRET=
LOGIN_SCOPES="openid database:read"
VAULT_ADDR=
VAULT_JWT_AUTH_MOUNT=jwt
VAULT_JWT_AUTH_ROLE=
VAULT_DATABASE_MOUNT=database
VAULT_DATABASE_ROLE=poc-readonly
DATABASE_HOST=
DATABASE_NAME=
DATABASE_PORT=5432
DATABASE_SSLROOTCERT=
GOOGLE_API_KEY=
# Conditional trust: JSON array of exact DNS hosts; no wildcards.
OAUTH_TRUSTED_HOSTS=[]
# OAUTH_CA_FILE=/private/path/identity-ca.pem
# VAULT_CA_FILE=/private/path/vault-ca.pem
# VAULT_NAMESPACE=team
"""
    if mode == "delegated-exchange":
        content += (
            "\n# Required for delegated exchange only.\n"
            "OAUTH_CLIENT_ID=\nOAUTH_CLIENT_SECRET=\nVAULT_AUDIENCE=\nACTOR_AUDIENCE=\n"
        )
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError:
        return {
            "status": "unchanged",
            "next_action": "Edit existing .env.local privately, then run agent setup check.",
        }
    except OSError:
        raise SecurityError("configuration_missing") from None
    return {
        "status": "created",
        "next_action": "Supply your administrator's settings in .env.local; run agent setup check.",
    }


async def execute_setup(args):
    """Emit only closed setup outcomes and sanitized readiness, hiding validation inputs."""
    import json

    from pydantic import ValidationError

    from agent.settings import Settings

    from .readiness import check

    try:
        if args.setup_command == "init":
            print(json.dumps(initialize(args.mode)))
            return 0
        report = await check(Settings(), network=args.network)
        print(report.model_dump_json())
        return report.exit_code
    except (SecurityError, ValidationError, OSError):
        print(
            json.dumps(
                {
                    "reason_code": "configuration_invalid",
                    "next_action": (
                        "Check .env.local against docs/setup.md; "
                        "no provider operation was attempted."
                    ),
                }
            )
        )
        return 2
