"""No-effect local prerequisites and explicit public network observations.

Configuration is never proof of provider authorization. Missing administrative features do
not disable the standard baseline. Raw configuration and upstream errors never leave here.
"""

from agent.recovery.store import RecoveryStore

from .models import CapabilityObservation, SetupReport


def required(settings, *, cli=False, denial=False):
    """List only the short configuration names needed by the selected route and entry point."""
    names = [
        "OAUTH_DISCOVERY_URL",
        "OAUTH_ISSUER",
        "OAUTH_AUDIENCE",
        "VAULT_ADDR",
        "DATABASE_HOST",
        "DATABASE_NAME",
    ]
    if settings.oauth_provider == "verify" and settings.verify_tenant_url:
        names.remove("OAUTH_DISCOVERY_URL")
    if cli:
        names.append("PORTABILITY_DENIED_TOKEN" if denial else "BEARER_TOKEN")
    else:
        names.extend(["LOGIN_CLIENT_ID", "LOGIN_CLIENT_SECRET"])
        if settings.model.startswith("google-gla:"):
            names.append("GOOGLE_API_KEY")
    if settings.database_auth_mode == "user-jwt":
        names.append("VAULT_JWT_AUTH_ROLE")
    else:
        names.extend(["OAUTH_CLIENT_ID", "OAUTH_CLIENT_SECRET", "VAULT_AUDIENCE"])

    def supplied(name):
        """Treat empty secret placeholders as missing rather than truthy wrapper objects."""
        value = getattr(settings, name.lower())
        return bool(value.get_secret_value() if hasattr(value, "get_secret_value") else value)

    return tuple(name for name in names if not supplied(name))


def local_check(settings, *, project=None, cli=False, denial=False):
    """Check configuration and durable admission without issuing tokens or changing state."""
    import importlib.util
    import time

    from agent.probe import oauth_config

    from .http import tls_context

    started = time.monotonic()
    missing = list(required(settings, cli=cli, denial=denial))
    if (
        not cli
        and settings.database_auth_mode == "user-jwt"
        and "database:read" not in settings.login_scopes.split()
    ):
        missing.append("LOGIN_SCOPES")
    if importlib.util.find_spec("psycopg") is None:
        missing.append("POSTGRES_EXTRA")
    oauth_invalid = vault_invalid = False
    try:
        oauth_config(settings, verification=True)
        tls_context(settings, "oauth")
    except Exception:
        oauth_invalid = True
        if settings.oauth_ca_file:
            missing.append("OAUTH_CA_FILE")
    try:
        tls_context(settings, "vault")
    except Exception:
        vault_invalid = True
        if settings.vault_ca_file:
            missing.append("VAULT_CA_FILE")
    profile_invalid = False
    try:
        from agent.runtime import load_definitions

        profiles = load_definitions(settings.profiles_file)
        if (
            "database-reader" not in profiles
            or "database-read" not in profiles["database-reader"].capabilities
        ):
            raise ValueError()
    except Exception:
        profile_invalid = True
        missing.append("PROFILES_FILE")
    invalid = oauth_invalid or vault_invalid or profile_invalid
    recovery_store = RecoveryStore(settings, project=project)
    recovery = recovery_store.status()
    response_needed = False
    if settings.database_host:
        from agent.response.store import ResponseStore

        try:
            ResponseStore(settings, project=project, recovery=recovery_store).read()
        except Exception:
            response_needed = True
    blocked = recovery.recovery not in {"clear", "not_configured"}
    observations = []
    for feature in ("baseline-sign-in", "baseline-database"):
        feature_missing = (
            missing
            if feature == "baseline-database"
            else [
                name
                for name in missing
                if name
                in {
                    "OAUTH_DISCOVERY_URL",
                    "OAUTH_ISSUER",
                    "OAUTH_AUDIENCE",
                    "OAUTH_CA_FILE",
                    "LOGIN_CLIENT_ID",
                    "LOGIN_CLIENT_SECRET",
                }
            ]
        )
        database_blocked = feature == "baseline-database" and (blocked or response_needed)
        feature_invalid = oauth_invalid or (
            feature == "baseline-database" and (vault_invalid or profile_invalid)
        )
        failed = bool(feature_missing) or feature_invalid or database_blocked
        reason = (
            "configuration_invalid"
            if feature_invalid
            else "configuration_missing"
            if feature_missing
            else "recovery_blocked"
            if database_blocked
            else "external_unverified"
        )
        observations.append(
            CapabilityObservation(
                feature=feature,
                state="blocked" if failed else "configured",
                reason_code=reason,
                repair_key="configure"
                if feature_missing or feature_invalid
                else "recover"
                if database_blocked
                else "check_network",
            )
        )
    for feature in (
        "delegated-exchange",
        "phone-approval",
        "remediation",
        "governance",
        "audit-export",
    ):
        observations.append(
            CapabilityObservation(
                feature=feature,
                state="unverified",
                reason_code="external_unverified",
                repair_key="provider_review",
                owner="provider-administrator",
            )
        )
    instructions = []
    if missing or invalid:
        instructions.append(
            "Supply listed settings privately using docs/setup.md; "
            "install the postgres extra if listed."
        )
    if blocked:
        instructions.append(
            "Run agent recover init once if uninitialized; otherwise agent recover status "
            "and follow its incident instructions. Do not reset existing state."
        )
    if response_needed:
        instructions.append(
            "Run agent respond status. If uninitialized, run agent respond init --prepare "
            "only when .local/response/policy.json is absent; inspect that private policy, "
            "then run agent respond init. Preserve existing incident state."
        )
    instructions.append(
        "Configuration and reachability do not establish provider permission. "
        "Sign in and run the selected validation workflow to demonstrate it."
    )
    observations = demonstrated(settings, project, observations, started + 2)
    if time.monotonic() > started + 2:
        invalid = True
        observations = [
            o.model_copy(update={"state": "blocked", "reason_code": "dependency_unreachable"})
            for o in observations
        ]
    return SetupReport(
        observations=tuple(observations),
        missing_settings=tuple(missing),
        instructions=tuple(instructions),
        exit_code=2 if missing or invalid else 3 if blocked or response_needed else 0,
    )


async def check(settings, *, network=False, project=None, transport=None):
    """Observe configured public targets within diagnostics' bounded worker ownership."""
    import asyncio
    import time

    deadline = time.monotonic() + 30
    report = local_check(settings, project=project)
    if not network or report.missing_settings or report.exit_code == 2:
        return report
    from agent.oauth import OAuthClient
    from agent.probe import oauth_config
    from agent.workspace.diagnostics import Diagnostics

    from .http import client

    identity_invalid = False
    advertised_exchange = False
    try:
        async with client(settings, "oauth", transport=transport) as http:
            oauth = OAuthClient(oauth_config(settings, verification=True), http)
            metadata = await asyncio.wait_for(oauth.metadata(), 10)
            status, keys = await asyncio.wait_for(
                oauth.bounded_json("GET", metadata["jwks_uri"]), 10
            )
            if status != 200 or not isinstance(keys.get("keys"), list) or not keys["keys"]:
                identity_invalid = True
            advertised_exchange = "urn:ietf:params:oauth:grant-type:token-exchange" in metadata.get(
                "grant_types_supported", []
            )
    except Exception:
        identity_invalid = True
    diagnostic = Diagnostics(
        settings,
        RecoveryStore(settings, project=project),
        transport=transport,
        total_timeout=max(0.001, deadline - time.monotonic()),
    )
    try:
        result = await diagnostic.check(authentication=False)
    finally:
        await diagnostic.shutdown()
    checks = {row.check_id: row for row in result.checks}
    observations = list(report.observations)
    if identity_invalid:
        observations[0] = CapabilityObservation(
            feature="baseline-sign-in",
            state="blocked",
            reason_code="configuration_invalid",
            repair_key="provider_review",
            owner="provider-administrator",
        )
    if advertised_exchange:
        observations[2] = observations[2].model_copy(update={"evidence_level": "advertised"})
    for index, key in enumerate(("identity", "vault")):
        row = checks[key]
        if row.state != "observed":
            observations[index] = CapabilityObservation(
                feature=observations[index].feature,
                state="blocked",
                reason_code="provider_access_denied"
                if row.reason_code == "provider_access_denied"
                else "dependency_unreachable",
                repair_key="provider_review",
                owner="provider-administrator",
            )
    if checks["database"].state != "observed":
        observations[1] = CapabilityObservation(
            feature="baseline-database",
            state="blocked",
            reason_code="dependency_unreachable",
            repair_key="provider_review",
            owner="provider-administrator",
        )
    return report.model_copy(
        update={
            "observations": tuple(observations),
            "exit_code": report.exit_code
            or (2 if any(o.state == "blocked" for o in observations[:2]) else 0),
        }
    )


def demonstrated(settings, project, observations, deadline):
    """Project only recent sealed native captures in the identical private context.

    Read at most 16 existing runs; missing, foreign, synthetic or corrupt evidence never
    promotes configuration. This does not add evidence or change vendor acceptance.
    """
    import time
    from datetime import UTC, datetime, timedelta
    from pathlib import Path
    from uuid import UUID

    from agent.validation.context import capture_context
    from agent.validation.models import DeploymentContext, ValidationRun
    from agent.validation.report import read_bindings, rebuild_report
    from agent.validation.store import PrivateStore

    root = Path(project or Path.cwd()) / ".local/validation"
    if not root.is_dir() or root.is_symlink() or settings.database_auth_mode != "user-jwt":
        return observations
    try:
        context = capture_context(settings)
        store = PrivateStore(project=project, read_only=True)
        for path in sorted(root.iterdir(), reverse=True)[:16]:
            if time.monotonic() >= deadline:
                break
            try:
                run_id = UUID(path.name)
                with store.open(run_id) as writer:
                    run = ValidationRun.model_validate(writer.read_json("run.json"))
                    if (
                        run.mode != "live"
                        or run.suite != "live-portability"
                        or run.authentication_mode != "user-jwt"
                        or run.execution_origin != "provider"
                        or run.completed_at is None
                        or not timedelta(0)
                        <= datetime.now(UTC) - run.completed_at
                        < timedelta(hours=24)
                        or DeploymentContext.model_validate(writer.read_json("context.json")).digest
                        != context.digest
                    ):
                        continue
                    report = rebuild_report(writer, persist=False)
                    bindings = read_bindings(writer)
                    matched = {
                        c.operation_ref for c in report.correlations if c.status == "matched"
                    }
                    for row in report.scenarios:
                        own = [
                            b
                            for b in bindings
                            if b.observation_id == row.observation_id and b.source_kind == "vault"
                        ]
                        if (
                            row.scenario == "user-jwt-read"
                            and row.outcome == "pass"
                            and row.cleanup == "revoked"
                            and not report.blockers
                            and len(own) >= 5
                            and sum(b.phase == "cleanup" for b in own) == 2
                            and all(b.operation_ref in matched for b in own)
                        ):
                            observations = [
                                o.model_copy(
                                    update={
                                        "state": "supported",
                                        "evidence_level": "demonstrated",
                                        "reason_code": "observed",
                                        "repair_key": "none",
                                        "observed_at": run.completed_at,
                                    }
                                )
                                if o.feature == "baseline-database" and o.state == "configured"
                                else o
                                for o in observations
                            ]
            except Exception:
                continue
    except Exception:
        pass  # Evidence remains unverified; raw source errors never become instructions.
    return observations


def sandbox_support():
    """Optional analysis availability never changes the baseline readiness result."""
    from agent.sandbox import INSTALL, available

    return {"available": available(), "next_action": INSTALL}
