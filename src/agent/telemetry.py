"""Metadata-only tracing with a restrictive export boundary.

Wrappers discard arbitrary text, exception details, and unapproved attributes before
the SDK receives them. The private OTLP transport uses a fixed validated destination.
An exporter acknowledgement is tracked separately from server-side receipt evidence.
"""

import http.client
import math
import re
import ssl
from contextlib import contextmanager
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from opentelemetry.metrics import NoOpMeterProvider
from opentelemetry.trace import (
    Link,
    NonRecordingSpan,
    NoOpTracerProvider,
    Span,
    SpanContext,
    SpanKind,
    Status,
    StatusCode,
    Tracer,
    TracerProvider,
    TraceState,
    get_current_span,
    set_span_in_context,
    use_span,
)
from pydantic_ai.agent import InstrumentationSettings
from pydantic_ai.capabilities import Instrumentation

from .settings import Settings
from .validation.models import Reason

SAFE_NAMES = frozenset(
    (
        "run",
        "delegation",
        "policy",
        "approval",
        "identity",
        "credential",
        "database",
        "cleanup",
        "telemetry",
        "report",
        "response",
        "governance",
        "agent",
        "model",
        "tool",
    )
)
UUID_ATTRIBUTES = frozenset(
    (
        "gov_candidate_id",
        "gov_case_id",
        "gov_attempt_id",
        "gov_proof_id",
        "validation_id",
        "observation_id",
        "request_id",
        "run_id",
        "parent_run_id",
        "agent_ref",
        "workload_ref",
        "operation_ref",
        "lease_ref",
        "approval_ref",
    )
)
COUNTS = frozenset(
    (
        "gov_observations",
        "gov_evidence",
        "gov_generation",
        "duration",
        "effect_attempts",
        "forbidden_effects",
        "gen_ai.usage.input_tokens",
        "gen_ai.usage.output_tokens",
    )
)
ENUMS = {
    "gov_operation": frozenset(
        (
            "readiness",
            "observe",
            "enroll",
            "identity",
            "permissions",
            "negatives",
            "reconcile",
            "resolve",
            "import",
            "close",
            "source_intake",
        )
    ),
    "gov_state": frozenset(
        (
            "prepared",
            "observed",
            "reviewed",
            "enrolling",
            "registered",
            "blocked",
            "closed",
            "submitted",
            "confirmed",
            "denied",
            "uncertain",
            "conflict",
        )
    ),
    "gov_outcome": frozenset(("pass", "fail", "blocked", "inconclusive")),
    "gov_provenance": frozenset(("synthetic", "operator", "native")),
    "response_action": frozenset(("cancel_local", "revoke_exact")),
    "response_status": frozenset(
        ("planned", "submitted", "confirmed", "denied", "failed", "uncertain")
    ),
    "provider_action": frozenset(
        (
            "block_registration",
            "revoke_native_token",
            "suspend_user",
            "revoke_user_sessions",
            "rotate_static",
            "terminate_static_sessions",
            "notify_teams",
        )
    ),
    "provider_state": frozenset(
        ("planned", "submitted", "acknowledged", "denied", "failed", "uncertain", "reconciled")
    ),
    "provider_proof": frozenset(
        ("not_run", "proven", "disproven", "inconclusive", "unsupported", "not_applicable")
    ),
    "phase": SAFE_NAMES,
    "outcome": frozenset(("pass", "fail", "blocked", "interrupted")),
    "detail": frozenset(
        (
            "started",
            "completed",
            "failed",
            "denied",
            "allowed",
            "pending",
            "contained",
            "interrupted",
            "acquired",
            "revoked",
            "verified",
            "attempted",
            "acknowledged",
            "received",
            "blocked",
        )
    ),
    "reason": frozenset(r.value for r in Reason),
}


def safe_attributes(attributes):
    """Keep only closed labels, generated identifiers, and finite nonnegative counters."""
    result = {}
    for key, value in (attributes or {}).items():
        if key in UUID_ATTRIBUTES and isinstance(value, str):
            try:
                if str(UUID(value)) == value:
                    result[key] = value
            except ValueError:
                pass
        elif key in COUNTS and type(value) in (int, float) and math.isfinite(value) and value >= 0:
            result[key] = value
        elif key in ENUMS and isinstance(value, str) and value in ENUMS[key]:
            result[key] = value
        elif key == "scenario" and value in SCENARIOS:
            result[key] = value
    return result


SCENARIOS = frozenset(
    (
        "delegated-read",
        "policy-denial",
        "injection-denial",
        "approval-denied",
        "approval-expired",
        "approval-replay",
        "approval-mutated",
        "cleanup-failure",
        "cleanup-cancelled",
        "delegated-database-read",
        "actor-only-denial",
        "phone-approved",
        "phone-denied",
    )
)


def safe_name(name):
    """Map known runtime and instrumentation names to bounded span names."""
    if name in SAFE_NAMES:
        return name
    # Native operation classes are preserved, never dynamic tool/agent/model names.
    if isinstance(name, str):
        if name.startswith("agent run"):
            return "agent"
        if name.startswith("chat "):
            return "model"
        if name.startswith("running tool"):
            return "tool"
    return "agent"


def clean_context(context):
    """Retain trace linkage while removing trace-state data from the supplied context."""
    if not context.is_valid:
        return context
    return SpanContext(
        context.trace_id, context.span_id, context.is_remote, context.trace_flags, TraceState()
    )


class AllowlistSpan(Span):
    def __init__(self, native):
        """Wrap an SDK span so all later mutations pass the metadata allowlist."""
        self.native = native
        self.safe_metadata = {}

    def end(self, end_time=None):
        """End the underlying span at the optional caller-supplied timestamp."""
        self.native.end(end_time)

    def get_span_context(self):
        """Return trace linkage needed for correlation without exposing span payloads."""
        return self.native.get_span_context()

    def set_attributes(self, attributes):
        """Filter a batch of attributes before passing them to the SDK span."""
        filtered = safe_attributes(attributes)
        self.safe_metadata.update(filtered)
        self.native.set_attributes(filtered)

    def set_attribute(self, key, value):
        """Apply the same metadata filter to a single attribute mutation."""
        self.set_attributes({key: value})

    def add_event(self, name, attributes=None, timestamp=None):
        """Record only a bounded event name and allowed metadata."""
        if name in SAFE_NAMES:
            self.native.add_event(name, safe_attributes(attributes), timestamp)

    def add_link(self, context, attributes=None):
        """Add trace linkage with sanitized context and link attributes."""
        self.native.add_link(clean_context(context), safe_attributes(attributes))

    def update_name(self, name):
        """Normalize a replacement span name through the closed naming policy."""
        self.native.update_name(safe_name(name))

    def is_recording(self):
        """Expose whether the underlying span is recording metadata."""
        return self.native.is_recording()

    def set_status(self, status, description=None):
        """Set the status code while discarding free-text status descriptions."""
        code = status.status_code if isinstance(status, Status) else status
        self.native.set_status(Status(code))

    def record_exception(self, exception, attributes=None, timestamp=None, escaped=False):
        """Record a fixed failure code instead of exception messages or stack traces."""
        self.native.add_event("run", {"reason": Reason.agent_run_failed.value}, timestamp)
        self.native.set_status(Status(StatusCode.ERROR))


class AllowlistTracer(Tracer):
    def __init__(self, native):
        """Wrap an SDK tracer with the metadata boundary shared by every new span."""
        self.native = native

    def start_span(
        self,
        name,
        context=None,
        kind=SpanKind.INTERNAL,
        attributes=None,
        links=None,
        start_time=None,
        record_exception=True,
        set_status_on_exception=True,
    ):
        """Start an internal span with filtered attributes, context, and links.

        Only allowed correlation metadata is inherited; automatic exception recording
        is disabled to prevent raw provider or task text entering traces.
        """
        parent = get_current_span(context)
        inherited = parent.safe_metadata if isinstance(parent, AllowlistSpan) else {}
        filtered = safe_attributes(attributes)
        filtered = {
            k: v for k, v in inherited.items() if k in UUID_ATTRIBUTES or k == "scenario"
        } | filtered
        if parent.get_span_context().is_valid:
            context = set_span_in_context(
                NonRecordingSpan(clean_context(parent.get_span_context())), context
            )
        filtered_links = [
            Link(clean_context(link.context), safe_attributes(link.attributes))
            for link in links or ()
        ]
        span = AllowlistSpan(
            self.native.start_span(
                safe_name(name),
                context=context,
                kind=SpanKind.INTERNAL,
                attributes=filtered,
                links=filtered_links,
                start_time=start_time,
                record_exception=False,
                set_status_on_exception=False,
            )
        )
        span.safe_metadata.update(filtered)
        return span

    @contextmanager
    def start_as_current_span(
        self,
        name,
        context=None,
        kind=SpanKind.INTERNAL,
        attributes=None,
        links=None,
        start_time=None,
        record_exception=True,
        set_status_on_exception=True,
        end_on_exit=True,
    ):
        """Activate a filtered span and safely mark errors before propagating them.

        The original exception remains local; its text is not recorded by the SDK.
        """
        span = self.start_span(name, context, kind, attributes, links, start_time)
        with use_span(
            span, end_on_exit=end_on_exit, record_exception=False, set_status_on_exception=False
        ):
            try:
                yield span
            except BaseException:
                span.set_status(StatusCode.ERROR)
                span.set_attribute("reason", Reason.agent_run_failed.value)
                raise


class AllowlistProvider(TracerProvider):
    def __init__(self, native):
        """Wrap the injected tracer provider without configuring a global provider."""
        self.native = native

    def get_tracer(
        self,
        instrumenting_module_name,
        instrumenting_library_version=None,
        schema_url=None,
        attributes=None,
    ):
        """Return a filtered tracer under the fixed service instrumentation identity."""
        return AllowlistTracer(self.native.get_tracer("agent", "1"))


def validate_base_url(value):
    """Require a clean HTTPS telemetry base URL without credentials, query, or fragment."""
    url = urlsplit(value)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or "?" in value
        or "#" in value
        or any(ord(c) < 33 for c in value)
    ):
        raise ValueError("schema_invalid")
    return value.rstrip("/")


@dataclass(frozen=True)
class SafeReply:
    ok: bool
    status_code: int
    reason: str = "telemetry_export_failed"
    text: str = ""
    headers: dict = field(default_factory=dict)


class SafeOTLPSession:
    """Exporter session contract with fixed destination and sanitized responses.

    Ignore SDK/environment TLS/client-certificate inputs. The explicit transport owns
    verified TLS, has no ambient credentials/proxies or redirects, and logs no URLs.
    """

    def __init__(self, endpoint, token, *, transport=None):
        """Bind a fixed OTLP endpoint, private authorization header, and bounded timeout."""
        self.endpoint = validate_base_url(endpoint)
        self.headers = {"Authorization": token}
        self.transport = transport
        self.acknowledged = False

    def post(self, url, data, timeout=5, **ignored):
        """Send span bytes to the fixed endpoint using verified TLS and a bounded response.

        Do not inherit proxy/client-certificate settings or follow redirects. Only a
        valid successful OTLP response with no rejected spans counts as acknowledgement.
        """
        self.acknowledged = False
        if url != self.endpoint:
            return SafeReply(False, 400)
        try:
            headers = {
                "Authorization": self.headers["Authorization"],
                "Content-Type": "application/x-protobuf",
            }
            budget = max(0.01, min(timeout, 5))
            if self.transport is not None:
                response = self.transport.handle_request(
                    httpx.Request("POST", self.endpoint, content=data, headers=headers)
                )
                content = response.read()
                status = response.status_code
                response.close()
            else:
                import certifi

                parsed_url = urlsplit(self.endpoint)
                connection = http.client.HTTPSConnection(
                    parsed_url.hostname,
                    parsed_url.port or 443,
                    timeout=budget,
                    context=ssl.create_default_context(cafile=certifi.where()),
                )
                try:
                    connection.request("POST", parsed_url.path or "/", body=data, headers=headers)
                    reply = connection.getresponse()
                    status = reply.status
                    content = reply.read(1024 * 1024 + 1)
                finally:
                    connection.close()
            if not 200 <= status < 300 or len(content) > 1024 * 1024:
                return SafeReply(False, 400)
            from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
                ExportTraceServiceResponse,
            )

            parsed = ExportTraceServiceResponse()
            if content:
                parsed.ParseFromString(content)
            if parsed.partial_success.rejected_spans or parsed.partial_success.error_message:
                return SafeReply(False, 400)
            self.acknowledged = True
            return SafeReply(True, 200, "")
        except Exception:
            return SafeReply(False, 400)

    def close(self):
        """Close an injected transport if one was supplied for this private session."""
        if self.transport is not None:
            self.transport.close()


@dataclass
class Delivery:
    state: str = "disabled"
    attempted: set[tuple[str, str]] = field(default_factory=set)
    acknowledged: set[tuple[str, str]] = field(default_factory=set)
    received: set[tuple[str, str]] = field(default_factory=set)
    records: dict = field(default_factory=dict)


def tracked_exporter(delegate, delivery, session=None, private_sink=None, source_instance=None):
    """Wrap an exporter to track attempted and acknowledged span IDs plus private bindings."""
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

    class TrackedExporter(SpanExporter):
        def export(self, spans):
            """Record export intent before delivery and acknowledge only verified transport
            success.

            Storage or exporter failures return an SDK failure; acknowledgement alone
            does
            not prove spans are queryable in the destination project.
            """
            ids = {(f"{s.context.trace_id:032x}", f"{s.context.span_id:016x}") for s in spans}
            for span in spans:
                key = (f"{span.context.trace_id:032x}", f"{span.context.span_id:016x}")
                attributes = span.attributes or {}
                delivery.records[key] = {
                    "trace_id": key[0],
                    "span_id": key[1],
                    "parent_span_id": f"{span.parent.span_id:016x}" if span.parent else None,
                    "run_id": attributes.get("run_id"),
                    "validation_id": attributes.get("validation_id"),
                }
                if (
                    private_sink
                    and source_instance
                    and all(
                        attributes.get(k) for k in ("run_id", "validation_id", "observation_id")
                    )
                ):
                    from .validation.models import PrivateOperationBinding

                    try:
                        private_sink.bind(
                            PrivateOperationBinding(
                                validation_id=attributes["validation_id"],
                                observation_id=attributes["observation_id"],
                                run_id=attributes["run_id"],
                                phase="telemetry",
                                source_kind="logfire",
                                source_instance=source_instance,
                                trace_id=key[0],
                                span_id=key[1],
                                parent_span_id=delivery.records[key]["parent_span_id"],
                                parent_run_id=attributes.get("parent_run_id"),
                            )
                        )
                    except Exception:
                        delivery.state = "failed"
                        return SpanExportResult.FAILURE
            delivery.attempted.update(ids)
            delivery.state = "attempted"
            try:
                result = delegate.export(spans)
            except Exception:
                result = SpanExportResult.FAILURE
            if result == SpanExportResult.SUCCESS and (session is None or session.acknowledged):
                delivery.acknowledged.update(ids)
                delivery.state = "acknowledged"
            else:
                delivery.state = "failed"
            return result

        def shutdown(self):
            """Forward shutdown to the underlying exporter."""
            delegate.shutdown()

        def force_flush(self, timeout_millis=5000):
            """Forward the bounded flush request to the underlying exporter."""
            return delegate.force_flush(timeout_millis)

    return TrackedExporter()


@dataclass
class Telemetry:
    provider: TracerProvider = field(default_factory=NoOpTracerProvider)
    meter_provider: object = field(default_factory=NoOpMeterProvider)
    sdk: object = None
    delivery: Delivery = field(default_factory=Delivery)

    def flush(self):
        """Flush pending metadata within the bounded deadline and return delivery success."""
        if self.sdk is None:
            return True
        try:
            ok = self.sdk.force_flush(timeout_millis=5000)
            if not ok:
                self.delivery.state = "failed"
            return ok
        except Exception:
            self.delivery.state = "failed"
            return False

    def shutdown(self):
        """Shut down the owned SDK provider when telemetry is configured."""
        if self.sdk is not None:
            self.sdk.shutdown()


def configure_telemetry(settings: Settings, *, exporter=None, private_sink=None) -> Telemetry:
    """Create an isolated metadata-only provider, or a no-op when no exporter is
    configured.

    Tests can inject a synchronous exporter. Live export uses the validated endpoint
    and bounded queue; this function does not install global instrumentation.
    """
    if not settings.logfire_token and exporter is None:
        return Telemetry()
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider as SDKProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON

    delivery = Delivery(state="disabled" if exporter is not None else "attempted")

    sdk = SDKProvider(
        resource=Resource({"service.name": "agent"}), sampler=ALWAYS_ON, shutdown_on_exit=False
    )
    if exporter is not None:
        sdk.add_span_processor(SimpleSpanProcessor(tracked_exporter(exporter, delivery)))
    else:
        from logfire import AdvancedOptions
        from opentelemetry.exporter.otlp.proto.http import Compression
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        token = settings.logfire_token.get_secret_value()
        # Suppress warnings that can embed arbitrary token region text; reject unknown regions.
        if not settings.logfire_base_url and not re.match(r"^pylf_v1_(?:us|eu)_", token):
            raise ValueError("prerequisite_missing")
        base = validate_base_url(
            AdvancedOptions(base_url=settings.logfire_base_url).generate_base_url(
                token, warn_unknown_region=False
            )
        )
        session = SafeOTLPSession(base + "/v1/traces", token)
        delegate = OTLPSpanExporter(
            endpoint=session.endpoint,
            session=session,
            headers={"Authorization": token},
            timeout=5,
            compression=Compression.NoCompression,
            meter_provider=NoOpMeterProvider(),
        )
        sdk.add_span_processor(
            BatchSpanProcessor(
                tracked_exporter(
                    delegate, delivery, session, private_sink, settings.logfire_project
                ),
                max_queue_size=2048,
                max_export_batch_size=128,
                schedule_delay_millis=1000,
                export_timeout_millis=5000,
            )
        )
    return Telemetry(provider=AllowlistProvider(sdk), sdk=sdk, delivery=delivery)


def safe_instrumentation(telemetry=None) -> Instrumentation:
    """Configure Pydantic AI instrumentation to exclude model content and binary payloads."""
    telemetry = telemetry or Telemetry()
    return Instrumentation(
        settings=InstrumentationSettings(
            tracer_provider=telemetry.provider,
            meter_provider=telemetry.meter_provider,
            include_content=False,
            include_binary_content=False,
            include_model_request_parameters=False,
        )
    )
