"""Reviewed model descriptors and trusted private-key injection without eager provider imports."""

from dataclasses import dataclass
from typing import Literal

from pydantic_ai.models import Model

from .settings import Settings


@dataclass(frozen=True)
class ModelDescriptor:
    """Immutable package/key mapping; lookup itself performs no provider construction."""

    provider: Literal["google", "openai", "anthropic"]
    model_kind: Literal["google", "chat", "responses", "anthropic"]
    extra: Literal["google", "openai", "anthropic"]
    package_probes: tuple[str, ...]
    credential_setting: Literal["GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]

    @property
    def prefixes(self) -> tuple[str, ...]:
        """Expose the immutable reviewed prefixes associated with this descriptor."""
        return next(prefixes for prefixes, info in DESCRIPTORS if info == self)


DESCRIPTORS = (
    (
        ("google-gla",),
        ModelDescriptor("google", "google", "google", ("google.genai",), "GOOGLE_API_KEY"),
    ),
    (
        ("openai", "openai-chat"),
        ModelDescriptor("openai", "chat", "openai", ("openai",), "OPENAI_API_KEY"),
    ),
    (
        ("openai-responses",),
        ModelDescriptor("openai", "responses", "openai", ("openai",), "OPENAI_API_KEY"),
    ),
    (
        ("anthropic",),
        ModelDescriptor("anthropic", "anthropic", "anthropic", ("anthropic",), "ANTHROPIC_API_KEY"),
    ),
)


def descriptor(model: str) -> ModelDescriptor | None:
    """Recognize only reviewed prefixes with a nonempty model name; unknowns stay direct."""
    prefix, separator, name = model.partition(":")
    if separator and name:
        for prefixes, info in DESCRIPTORS:
            if prefix in prefixes:
                return info
    return None


def selected_model(settings: Settings) -> str | Model:
    """Pass the selected SecretStr only to its trusted provider, retaining model kind.

    Unknown integrations retain Pydantic AI's existing direct resolution. Constructors
    may raise on unavailable packages; callers expose only closed sanitized errors.
    """
    from .gateway.config import route_policy

    policy = route_policy(settings)
    if policy is not None:
        return gateway_model(settings, policy)
    info = descriptor(settings.model)
    if info is None:
        return settings.model
    key = getattr(settings, info.credential_setting.lower())
    if not key or not key.get_secret_value():
        return settings.model
    name = settings.model.split(":", 1)[1]
    if info.provider == "google":
        from pydantic_ai.models.google import GoogleModel
        from pydantic_ai.providers.google import GoogleProvider

        return GoogleModel(name, provider=GoogleProvider(api_key=key.get_secret_value()))
    if info.provider == "openai":
        from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModel
        from pydantic_ai.providers.openai import OpenAIProvider

        model_type = OpenAIResponsesModel if info.model_kind == "responses" else OpenAIChatModel
        return model_type(name, provider=OpenAIProvider(api_key=key.get_secret_value()))
    from pydantic_ai.models.anthropic import AnthropicModel
    from pydantic_ai.providers.anthropic import AnthropicProvider

    return AnthropicModel(name, provider=AnthropicProvider(api_key=key.get_secret_value()))


def gateway_model(settings, policy, *, inner=None, store=None):
    """Construct native models with an owned final transport; injected seams are trusted tests.

    No control-plane call or model request happens during construction. Runtime admission
    and the every-turn capability require private reviewed evidence before ordinary use.
    """
    import httpx2
    from pydantic_ai.providers.gateway import gateway_provider

    from .gateway.capability import ModelBoundary
    from .gateway.config import bindings
    from .gateway.models import GatewayError
    from .gateway.review import ReviewStore
    from .gateway.transport import GatewayTransport

    client = httpx2.AsyncClient(
        transport=GatewayTransport(policy, settings.gateway_api_key, inner=inner),
        trust_env=False,
        follow_redirects=False,
        timeout=settings.timeout_seconds,
    )
    try:
        provider = gateway_provider(
            policy.protocol,
            api_key=settings.gateway_api_key.get_secret_value(),
            base_url=policy.base_url + "/proxy",
            route=policy.route,
            http_client=client,
        )
        if policy.protocol in {"openai-chat", "openai-responses"}:
            from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModel

            provider.client.max_retries = 0
            cls = OpenAIResponsesModel if policy.protocol == "openai-responses" else OpenAIChatModel
        elif policy.protocol == "anthropic":
            from pydantic_ai.models.anthropic import AnthropicModel

            provider.client.max_retries = 0
            cls = AnthropicModel
        else:
            from pydantic_ai.models.google import GoogleModel

            cls = GoogleModel
        # SDK debug loggers can include message bodies even when AI instrumentation excludes
        # content. Disable only model/HTTP SDK loggers; application metadata has its own sink.
        import logging

        for name, logger in tuple(logging.Logger.manager.loggerDict.items()):
            if isinstance(logger, logging.Logger) and name.startswith(
                ("openai", "anthropic", "google_genai", "httpx2", "httpcore")
            ):
                logger.disabled = True
        model = cls(policy.model, provider=provider)
        model._agent_gateway = ModelBoundary(
            client,
            policy,
            bindings(settings, policy),
            store if store is not None else ReviewStore(),
        )
        return model
    except Exception:
        # Construction has opened no connections; the caller must not display SDK errors.
        raise GatewayError("gateway_configuration_invalid") from None
