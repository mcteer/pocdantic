"""Shared names-only launch admission; no models, clients, sockets or telemetry are created."""

import importlib.util

from agent.model_config import descriptor
from agent.settings import Settings

from .recipes import RECIPES


def package_present(name: str) -> bool:
    """Inspect optional package availability without constructing an integration."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def supplied(settings: Settings, name: str) -> bool:
    """Treat empty SecretStr placeholders as absent and never return their values."""
    value = getattr(settings, name.lower())
    return bool(value.get_secret_value() if hasattr(value, "get_secret_value") else value)


def common(
    settings: Settings, *, supplied_model: bool = False, guided: bool = False
) -> tuple[str, ...]:
    """Check shared browser/model limits while preserving direct custom-provider support."""
    missing = [
        name
        for name in ("LOGIN_CLIENT_ID", "LOGIN_CLIENT_SECRET", "OAUTH_AUDIENCE")
        if not supplied(settings, name)
    ]
    if not (
        settings.oauth_discovery_url
        or (settings.oauth_provider == "verify" and settings.verify_tenant_url)
    ):
        missing.append("OAUTH_DISCOVERY_URL")
    if not 1 <= settings.timeout_seconds <= 180:
        missing.append("TIMEOUT_SECONDS")
    info = descriptor(settings.model)
    if not supplied_model:
        if settings.model_mode is None:
            missing.append("MODEL_MODE")
        if settings.model_mode == "gateway":
            from agent.gateway.config import route_policy
            from agent.gateway.models import GatewayError

            for name in ("GATEWAY_REGION", "GATEWAY_ROUTE", "GATEWAY_MODELS", "GATEWAY_API_KEY"):
                if not supplied(settings, name):
                    missing.append(name)
            extras = {
                "google-cloud": "google",
                "openai-chat": "openai",
                "openai-responses": "openai",
                "anthropic": "anthropic",
            }
            prefix, sep, name = settings.model.partition(":")
            extra = extras.get(prefix)
            if not extra or not sep or not name:
                missing.append("MODEL")
            else:
                probe = {"google": "google.genai", "openai": "openai", "anthropic": "anthropic"}[
                    extra
                ]
                if not package_present(probe):
                    missing.append(extra.upper() + "_EXTRA")
            if not any(name.startswith("GATEWAY_") for name in missing):
                try:
                    route_policy(settings)
                except GatewayError:
                    missing.append("MODEL")
            return tuple(dict.fromkeys(missing))
        if info:
            if not supplied(settings, info.credential_setting):
                missing.append(info.credential_setting)
            if not all(package_present(name) for name in info.package_probes):
                missing.append(info.extra.upper() + "_EXTRA")
        elif guided:
            missing.append("MODEL")
    return tuple(missing)


def recipe_missing(settings: Settings, recipe: str) -> tuple[str, ...]:
    """Check fixed package/profile requirements for the selected live recipe only."""
    selected = RECIPES[recipe]
    if recipe == "offline":
        return ()
    missing = list(common(settings, guided=True))
    for extra, packages in (
        ("server", ("fastapi", "uvicorn")),
        ("postgres", ("psycopg",)),
        ("sandbox", ("pydantic_monty", "sqlglot")),
    ):
        if extra == "sandbox" and extra in selected.extras:
            from agent.sandbox import available

            if not available():
                missing.append("SANDBOX_EXTRA")
        if extra in selected.extras and not all(package_present(name) for name in packages):
            missing.append(extra.upper() + "_EXTRA")
    try:
        from agent.runtime import load_definitions

        profiles = load_definitions(settings.profiles_file)
        if selected.profile not in profiles or any(
            capability not in profiles[selected.profile].capabilities
            for capability in selected.required_capabilities
        ):
            missing.append("PROFILES_FILE")
    except Exception:
        missing.append("PROFILES_FILE")
    return tuple(dict.fromkeys(missing))


def setting_source(settings: Settings, name: str) -> str:
    """Return a closed source label using names only, without rereading private files.

    Explicit Settings construction and dotenv share a local-input label because the
    validated model does not retain their individual provenance. Multiple environment
    aliases are reported as a potential conflict without comparing or returning values.
    """
    import os

    from .models import SETTING_NAMES

    if name not in SETTING_NAMES:
        raise ValueError("invalid_setting_name")
    field = Settings.model_fields.get(name.lower())
    if field is None:
        return "compiled-requirement"
    alias = field.validation_alias
    candidates = getattr(alias, "choices", (alias,))
    present = [value for value in candidates if isinstance(value, str) and value in os.environ]
    if len(present) > 1:
        return "multiple-environment-aliases"
    if present:
        return "environment"
    return "local-input" if name.lower() in settings.model_fields_set else "default"
