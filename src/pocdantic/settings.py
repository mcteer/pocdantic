from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env.local", extra="ignore", env_prefix="POCDANTIC_", populate_by_name=True
    )
    model: str = "google-gla:gemini-3.8-flash"
    timeout_seconds: float = Field(default=45, gt=0, le=300)
    request_limit: int = Field(default=8, gt=0, le=50)
    tool_calls_limit: int = Field(default=12, gt=0, le=100)
    output_tokens_limit: int = Field(default=6000, gt=0)
    profiles_file: str = "config/agents.json"
    workload_definition: str = "pocdantic-runtime"
    google_api_key: SecretStr | None = Field(
        default=None, validation_alias="GOOGLE_API_KEY", repr=False
    )
    oauth_provider: Literal["verify", "generic"] = "verify"
    oauth_issuer: str | None = None
    oauth_discovery_url: str | None = None
    oauth_token_endpoint: str | None = None
    oauth_audience: str | None = None
    oauth_access_token_typ: str = "at+jwt"
    oauth_client_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "POCDANTIC_OAUTH_CLIENT_ID", "VERIFY_AGENT_CLIENT_ID", "VERIFY_CLIENT_ID"
        ),
        repr=False,
    )
    oauth_client_secret: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "POCDANTIC_OAUTH_CLIENT_SECRET", "VERIFY_AGENT_CLIENT_SECRET", "VERIFY_CLIENT_SECRET"
        ),
        repr=False,
    )
    oauth_auth_method: Literal["client_secret_basic", "client_secret_post"] = "client_secret_post"
    verify_tenant_url: str | None = Field(
        default=None, validation_alias="VERIFY_TENANT_URL", repr=False
    )
    verify_api_client_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("POCDANTIC_VERIFY_API_CLIENT_ID", "VERIFY_CLIENT_ID"),
        repr=False,
    )
    verify_api_client_secret: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("POCDANTIC_VERIFY_API_CLIENT_SECRET", "VERIFY_CLIENT_SECRET"),
        repr=False,
    )
    verify_push_enabled: bool = False
    verify_authenticator_id: str | None = None
    verify_user_id: str | None = None
    bearer_token: SecretStr | None = Field(default=None, repr=False)
    logfire_token: SecretStr | None = Field(
        default=None, validation_alias="LOGFIRE_TOKEN", repr=False
    )
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
        if value and not str(value).startswith("https://"):
            value = "https://" + str(value)
        return value.rstrip("/") if value else None
