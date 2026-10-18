"""Typed local configuration with short environment names and legacy aliases.

Defaults support synthetic execution. Live credentials use SecretStr and remain
out of representations; URL normalization does not replace adapter trust checks.
"""

from typing import Literal

from pydantic import (
    AliasChoices,
    AliasGenerator,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env.local",
        hide_input_in_errors=True,
        extra="ignore",
        populate_by_name=True,
        alias_generator=AliasGenerator(
            validation_alias=lambda name: AliasChoices(name.upper(), "POCDANTIC_" + name.upper())
        ),
    )
    model: str = "google-gla:gemini-3.8-flash"
    model_mode: Literal["gateway", "direct"] | None = None
    gateway_region: Literal["us", "eu"] | None = None
    gateway_route: str | None = Field(default=None, repr=False)
    gateway_models: tuple[str, ...] = ()
    gateway_api_key: SecretStr | None = Field(
        default=None,
        repr=False,
        validation_alias=AliasChoices("GATEWAY_API_KEY", "LOGFIRE_GATEWAY_API_KEY"),
    )

    @field_validator("gateway_region", mode="before")
    @classmethod
    def optional_gateway_region(cls, value):
        """Treat an empty fresh template region as missing, never an implicit region."""
        return None if value == "" else value

    @model_validator(mode="before")
    @classmethod
    def gateway_aliases(cls, values):
        """Refuse conflicting process aliases without echoing their private values."""
        import os

        left, right = os.environ.get("GATEWAY_API_KEY"), os.environ.get("LOGFIRE_GATEWAY_API_KEY")
        if left and right and left != right:
            from .security import SecurityError

            raise SecurityError("gateway_configuration_invalid")
        return values

    timeout_seconds: float = Field(default=45, gt=0, le=300)
    request_limit: int = Field(default=8, gt=0, le=50)
    tool_calls_limit: int = Field(default=12, gt=0, le=100)
    output_tokens_limit: int = Field(default=6000, gt=0)
    profiles_file: str = "config/agents.json"
    workload_definition: str = "pocdantic-runtime"
    google_api_key: SecretStr | None = Field(
        default=None, validation_alias="GOOGLE_API_KEY", repr=False
    )
    openai_api_key: SecretStr | None = Field(
        default=None, validation_alias="OPENAI_API_KEY", repr=False
    )
    anthropic_api_key: SecretStr | None = Field(
        default=None, validation_alias="ANTHROPIC_API_KEY", repr=False
    )
    database_auth_mode: Literal["delegated-exchange", "user-jwt"] = "delegated-exchange"
    oauth_trusted_hosts: tuple[str, ...] = ()
    oauth_ca_file: str | None = Field(default=None, repr=False)
    vault_ca_file: str | None = Field(default=None, repr=False)
    portability_denied_token: SecretStr | None = Field(default=None, repr=False)
    vault_jwt_auth_mount: str = "jwt"
    vault_jwt_auth_role: str | None = Field(default=None, repr=False)
    vault_database_mount: str | None = Field(default=None, repr=False)
    vault_database_role: str | None = Field(default=None, repr=False)

    oauth_provider: Literal["verify", "generic"] = "verify"
    oauth_issuer: str | None = None
    oauth_discovery_url: str | None = None
    oauth_token_endpoint: str | None = None
    oauth_audience: str | None = None
    oauth_access_token_typ: str = "at+jwt"
    oauth_client_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "OAUTH_CLIENT_ID",
            "POCDANTIC_OAUTH_CLIENT_ID",
            "VERIFY_AGENT_CLIENT_ID",
            "VERIFY_CLIENT_ID",
        ),
        repr=False,
    )
    oauth_client_secret: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "OAUTH_CLIENT_SECRET",
            "POCDANTIC_OAUTH_CLIENT_SECRET",
            "VERIFY_AGENT_CLIENT_SECRET",
            "VERIFY_CLIENT_SECRET",
        ),
        repr=False,
    )
    login_client_id: str | None = Field(default=None, repr=False)
    login_client_secret: SecretStr | None = Field(default=None, repr=False)
    login_scopes: str = "openid"

    @field_validator("login_scopes")
    @classmethod
    def scopes(cls, value):
        """Require a bounded, unique login-scope list containing openid, then normalize
        spaces.
        """
        parts = value.split()
        if (
            any(ord(c) < 32 and c != " " for c in value)
            or "openid" not in parts
            or not 1 <= len(parts) <= 32
            or len(set(parts)) != len(parts)
            or any(not 1 <= len(p) <= 128 for p in parts)
        ):
            raise ValueError("Invalid login scopes")
        return " ".join(parts)

    oauth_auth_method: Literal["client_secret_basic", "client_secret_post"] = "client_secret_post"
    verify_tenant_url: str | None = Field(
        default=None, validation_alias="VERIFY_TENANT_URL", repr=False
    )
    verify_api_client_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "VERIFY_API_CLIENT_ID", "POCDANTIC_VERIFY_API_CLIENT_ID", "VERIFY_CLIENT_ID"
        ),
        repr=False,
    )
    verify_api_client_secret: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "VERIFY_API_CLIENT_SECRET", "POCDANTIC_VERIFY_API_CLIENT_SECRET", "VERIFY_CLIENT_SECRET"
        ),
        repr=False,
    )
    verify_push_enabled: bool = False
    verify_authenticator_id: str | None = None
    verify_user_id: str | None = None
    bearer_token: SecretStr | None = Field(default=None, repr=False)
    logfire_token: SecretStr | None = Field(
        default=None, validation_alias="LOGFIRE_TOKEN", repr=False
    )
    logfire_base_url: str | None = Field(default=None, repr=False)
    logfire_project: str | None = Field(default=None, min_length=1, max_length=128, repr=False)
    logfire_environment: str = "unclassified"

    @field_validator("logfire_environment", mode="before")
    @classmethod
    def telemetry_environment(cls, value):
        """Export only fixed environment labels; never export arbitrary operator text."""
        return (
            value
            if value in ("prd", "synth", "synthetic", "dev", "playtest", "test")
            else "unclassified"
        )

    @field_validator("logfire_base_url")
    @classmethod
    def logfire_endpoint(cls, value):
        """Validate an optional telemetry URL before it can become an export destination."""
        if value:
            from .telemetry import validate_base_url

            return validate_base_url(value)
        return None

    vault_addr: str | None = Field(default=None, validation_alias="VAULT_ADDR", repr=False)
    vault_namespace: str = Field(default="", validation_alias="VAULT_NAMESPACE", repr=False)
    vault_token: SecretStr | None = Field(default=None, validation_alias="VAULT_TOKEN", repr=False)
    vault_read_path: str = "database/creds/poc-readonly"
    vault_audience: str | None = None
    actor_audience: str | None = None
    workload_jwt: SecretStr | None = Field(default=None, repr=False)
    workload_auth_mount: str = "jwt"
    workload_auth_role: str | None = None
    database_host: str | None = None
    database_name: str | None = None
    database_port: int = 5432
    database_sslrootcert: str | None = None
    database_username_suffix: str = Field(default="", repr=False)

    @field_validator("verify_tenant_url", "vault_addr", mode="before")
    @classmethod
    def normalize_url(cls, value):
        """Normalize provider base URLs to HTTPS and remove trailing slashes."""
        if value and not str(value).startswith("https://"):
            value = "https://" + str(value)
        return value.rstrip("/") if value else None

    @field_validator("vault_jwt_auth_role", mode="before")
    @classmethod
    def optional_jwt_role(cls, value):
        """Treat a fresh template's empty role as missing, without inventing a role."""
        return None if value == "" else value

    @field_validator("oauth_trusted_hosts")
    @classmethod
    def trust_hosts(cls, value):
        """Reject implicit or unbounded endpoint trust before constructing clients."""
        from .setup.models import hosts

        return hosts(value)

    @model_validator(mode="after")
    def database_target(self):
        """Resolve custom targets while preserving explicit legacy configuration precedence."""
        from .setup.models import DatabaseTarget

        legacy = DatabaseTarget.from_path(self.vault_read_path)
        if self.vault_database_mount is not None or self.vault_database_role is not None:
            target = DatabaseTarget(
                mount=self.vault_database_mount or legacy.mount,
                role=self.vault_database_role or legacy.role,
            )
            if "vault_read_path" in self.model_fields_set and legacy != target:
                raise ValueError("conflicting_database_target")
            self.vault_read_path = target.credential_path
        DatabaseTarget.path(self.vault_jwt_auth_mount)
        if self.vault_jwt_auth_role is not None:
            DatabaseTarget.path(self.vault_jwt_auth_role)
        return self


def synthetic_settings() -> Settings:
    """Validate fixed offline defaults without consulting dotenv or process environment.

    The bundled profile path is absolute so an unrelated cwd profile cannot redirect
    the rehearsal. This factory changes no process-global settings or private files.
    """
    from importlib.resources import files
    from pathlib import Path

    class SyntheticSettings(Settings):
        """Offline settings whose only source is explicitly supplied trusted defaults."""

        @model_validator(mode="before")
        @classmethod
        def gateway_aliases(cls, values):
            """Offline construction does not inspect ambient Gateway credential aliases."""
            return values

        @classmethod
        def settings_customise_sources(
            cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings
        ):
            """Exclude live sources before validation, rather than suppressing errors."""
            return (init_settings,)

    resource = files("agent").joinpath("default_agents.json")
    profiles = (
        str(Path(str(resource)).resolve())
        if resource.is_file()
        else str(Path(__file__).resolve().parents[2] / "config/agents.json")
    )
    return SyntheticSettings(profiles_file=profiles)
