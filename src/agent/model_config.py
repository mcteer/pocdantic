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
