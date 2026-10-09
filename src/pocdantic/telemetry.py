from pydantic_ai.agent import InstrumentationSettings
from pydantic_ai.capabilities import Instrumentation

from .settings import Settings


def configure_telemetry(settings: Settings) -> None:
    if settings.logfire_token:
        import logfire

        logfire.configure(
            token=settings.logfire_token.get_secret_value(),
            service_name="pocdantic",
            console=False,
            send_to_logfire=True,
            inspect_arguments=False,
        )
        # Do not instrument HTTP bodies/headers or globally wrap private adapter calls.


def safe_instrumentation() -> Instrumentation:
    return Instrumentation(
        settings=InstrumentationSettings(
            include_content=False,
            include_binary_content=False,
            include_model_request_parameters=False,
        )
    )
