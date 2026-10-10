"""Private configuration grouping; never source authentication or credential capture."""

import hashlib
from importlib.resources import files
from pathlib import Path

from .models import DeploymentContext, digest
from .store import MAX_ARTIFACT, StoreError, read_private

SELECTORS = (
    "oauth_provider",
    "oauth_issuer",
    "oauth_discovery_url",
    "oauth_token_endpoint",
    "oauth_audience",
    "oauth_auth_method",
    "oauth_access_token_typ",
    "oauth_client_id",
    "verify_tenant_url",
    "verify_api_client_id",
    "verify_user_id",
    "verify_authenticator_id",
    "verify_push_enabled",
    "vault_addr",
    "vault_namespace",
    "vault_read_path",
    "vault_audience",
    "actor_audience",
    "database_host",
    "database_name",
    "database_port",
    "database_username_suffix",
    "workload_definition",
    "workload_auth_mount",
    "workload_auth_role",
    "logfire_project",
)


def profile_bytes(path):
    p = Path(path)
    if path == "config/agents.json" and not p.is_file():
        resource = files("agent").joinpath("default_agents.json")
        raw = (
            resource.read_bytes()
            if resource.is_file()
            else read_private(Path(__file__).parents[3] / path)
        )
    else:
        raw = read_private(p.absolute())
    if len(raw) > MAX_ARTIFACT:
        raise StoreError("limits_exceeded")
    return raw


def capture_context(settings):
    selectors = {k: getattr(settings, k) for k in SELECTORS}
    selectors["logfire_base_url"] = settings.logfire_base_url or "token-routed"
    for key, read in (
        ("profiles_digest", lambda: profile_bytes(settings.profiles_file)),
        ("tls_ca_digest", lambda: read_private(Path(settings.database_sslrootcert).absolute())),
    ):
        try:
            selectors[key] = (
                hashlib.sha256(read()).hexdigest()
                if key == "profiles_digest" or settings.database_sslrootcert
                else None
            )
        except (ValueError, OSError):
            selectors[key] = "unreadable"
    return DeploymentContext(selectors=selectors, digest=digest(selectors))
