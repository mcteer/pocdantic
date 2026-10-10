"""Bounded local assessment; configuration sufficiency is never remote verification."""

import importlib.util
import ssl
import time
from urllib.parse import urlsplit

from pydantic import ValidationError

from ..probe import oauth_config
from ..settings import Settings
from .catalog import load_catalog, select_suite
from .context import profile_bytes
from .models import ReadinessCheck, ReadinessReport, Reason
from .store import StoreError, decode_json, read_private


def ready(suite_label, names=None, *, settings=None):
    suite, selection = select_suite(load_catalog(), suite_label, names, "live", True)
    start = time.monotonic()
    invalid_settings = False
    try:
        s = settings if settings is not None else Settings()
    except ValidationError:
        s = Settings.model_construct()
        invalid_settings = True
    checks = []
    for scenario in selection:

        def add(
            key,
            present=True,
            *,
            section="execution",
            invalid=False,
            external=False,
            label=scenario.label,
        ):
            if time.monotonic() - start > 2:
                raise StoreError("scenario_timeout")
            state = (
                "unverified"
                if external
                else "invalid"
                if invalid
                else "configured"
                if present
                else "missing"
            )
            checks.append(
                ReadinessCheck(
                    check_id=key,
                    scenario=label,
                    section=section,
                    state=state,
                    owner="integration_owner" if external else "operator",
                    reason=Reason.external_unverified
                    if external
                    else Reason.schema_invalid
                    if invalid
                    else None
                    if present
                    else Reason.prerequisite_missing,
                )
            )

        add("human-token", bool(s.bearer_token))
        add("oauth-client", bool(s.oauth_client_id and s.oauth_client_secret))
        add("oauth-audience", bool(s.oauth_audience))
        try:
            config = oauth_config(s)
            configured = bool(config.discovery_url or (config.issuer and config.token_endpoint))
            for endpoint in (config.discovery_url, config.issuer, config.token_endpoint):
                if endpoint:
                    p = urlsplit(endpoint)
                    if (
                        p.scheme != "https"
                        or not p.hostname
                        or p.username
                        or p.password
                        or p.query
                        or p.fragment
                    ):
                        raise ValueError()
            add("oauth-config", configured, invalid=invalid_settings)
        except Exception:
            # No exception text, field inputs or provider calls cross this projection.
            add("oauth-config", False, invalid=True)
        try:
            raw = profile_bytes(s.profiles_file)
            decode_json(raw)
            from ..runtime import load_definitions

            definitions = load_definitions(s.profiles_file)
            profile = "database-reader" if suite.label == "live-database" else "parent"
            needed = (
                "database-read" if suite.label == "live-database" else "simulated-infrastructure"
            )
            add("profiles", profile in definitions and needed in definitions[profile].capabilities)
        except Exception:
            add("profiles", False, invalid=True)
        if suite.label == "live-database":
            add("postgres-extra", importlib.util.find_spec("psycopg") is not None)
            path = s.vault_read_path
            valid_path = (
                path.startswith("database/creds/")
                and ".." not in path.split("/")
                and not any(c in path for c in "?#")
            )
            p = urlsplit(s.vault_addr or "https://absent.invalid")
            valid_url = (
                p.scheme == "https"
                and bool(p.hostname)
                and not (p.username or p.password or p.query or p.fragment)
            )
            add("vault-target", bool(s.vault_addr), invalid=not (valid_path and valid_url))
            add("delegated-audiences", bool(s.vault_audience))
            add(
                "database-target",
                bool(s.database_host and s.database_name),
                invalid=not 1 <= s.database_port <= 65535,
            )
            try:
                if s.database_sslrootcert:
                    from pathlib import Path

                    ca = read_private(Path(s.database_sslrootcert).absolute()).decode("utf-8")
                    ssl.create_default_context(cadata=ca)
                add("database-tls", True)
            except Exception:
                add("database-tls", False, invalid=True)
        else:
            add("phone-enabled", s.verify_push_enabled)
            add(
                "phone-client",
                bool(s.verify_api_client_id and s.verify_api_client_secret and s.verify_tenant_url),
            )
            add("phone-mapping", bool(s.verify_user_id and s.verify_authenticator_id))
        sdk = importlib.util.find_spec("logfire") is not None
        exporter_ok = not s.logfire_token or sdk
        try:
            if s.logfire_base_url:
                from ..telemetry import validate_base_url

                validate_base_url(s.logfire_base_url)
        except Exception:
            exporter_ok = False
        add("configured-exporter", exporter_ok)
        add(
            "telemetry-config",
            bool(s.logfire_token and sdk and s.logfire_project),
            section="evidence",
        )
        for label in (
            "vault-export" if suite.label == "live-database" else "verify-events-export",
            "logfire-export",
        ):
            add(label, section="evidence", external=True)
        for label in ("remote-identity", "remote-permissions", "remote-reachability"):
            add(label, external=True)
    return ReadinessReport(
        suite=suite.label,
        selected=tuple(x.label for x in selection),
        checks=tuple(checks),
        execution_ready=not any(
            c.section == "execution" and c.state in {"missing", "invalid"} for c in checks
        ),
        evidence_ready=not any(
            c.section == "evidence" and c.state in {"missing", "invalid"} for c in checks
        ),
    )
