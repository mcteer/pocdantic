from datetime import timedelta
from uuid import uuid4

from agent.validation.correlation import correlate
from agent.validation.models import (
    ImportManifest,
    NormalizedSourceEvent,
    PrivateOperationBinding,
    SourceArtifact,
    now,
)


def fixture(source="vault", **updates):
    time = now()
    run = uuid4()
    binding = PrivateOperationBinding(
        validation_id=uuid4(),
        observation_id=uuid4(),
        run_id=run,
        phase="credential" if source == "vault" else "telemetry",
        source_kind=source,
        source_instance="synthetic-instance",
        native_request_id="synthetic-request" if source == "vault" else None,
        trace_id="a" * 32 if source == "logfire" else None,
        span_id="b" * 16 if source == "logfire" else None,
        started_at=time,
        finished_at=time + timedelta(seconds=2),
    )
    manifest = ImportManifest(
        source_kind=source,
        format_label={"vault": "vault-jsonl", "verify": "verify-events", "logfire": "logfire-rows"}[
            source
        ],
        source_instance="synthetic-instance",
        window_start=time,
        window_end=time + timedelta(seconds=2),
        completeness="complete",
    )
    base = dict(
        source_event_id="synthetic-request",
        source_kind=source,
        source_instance="synthetic-instance",
        observed_at=time,
        kind="response",
        native_request_id="synthetic-request",
        phase="credential",
        outcome="success",
    )
    if source == "logfire":
        base.update(
            source_event_id="b" * 16,
            kind="span",
            trace_id="a" * 32,
            span_id="b" * 16,
            validation_id=binding.validation_id,
            run_id=binding.run_id,
        )
    base.update(updates)
    response = NormalizedSourceEvent(**base)
    events = (
        (response.model_copy(update={"kind": "request", "outcome": "unknown"}), response)
        if source == "vault"
        else (response,)
    )
    artifact = SourceArtifact(
        manifest=manifest,
        raw_digest="a" * 64,
        normalized_digest="b" * 64,
        bytes_count=1,
        event_count=len(events),
        events=events,
    )
    return binding, artifact


def test_exact_vault_pair_and_source_namespace():
    binding, artifact = fixture()
    assert correlate(binding, [artifact]).status == "matched"
    assert (
        correlate(binding.model_copy(update={"source_instance": "different"}), [artifact]).status
        == "missing"
    )
    assert (
        correlate(binding.model_copy(update={"native_request_id": "wrong"}), [artifact]).status
        == "missing"
    )


def test_clock_skew_incomplete_and_contradiction():
    binding, artifact = fixture()
    binding = binding.model_copy(
        update={
            "started_at": binding.started_at - timedelta(seconds=1000),
            "finished_at": binding.finished_at - timedelta(seconds=1000),
        }
    )
    assert correlate(binding, [artifact]).status == "outside_window"
    binding, artifact = fixture(outcome="denied")
    assert correlate(binding, [artifact]).status == "contradicted"
    binding, artifact = fixture()
    incomplete = artifact.model_copy(
        update={
            "manifest": artifact.manifest.model_copy(update={"completeness": "partial"}),
            "events": artifact.events[:1],
        }
    )
    assert correlate(binding, [incomplete]).status == "incomplete_export"


def test_unknown_verify_linkage_and_logfire_wrong_run():
    binding, artifact = fixture("verify")
    assert correlate(binding, [artifact]).status == "unsupported"
    binding, artifact = fixture("logfire")
    assert correlate(binding, [artifact]).status == "matched"
    assert correlate(binding.model_copy(update={"run_id": uuid4()}), [artifact]).status == "missing"


def test_hmac_is_not_plain_sha_or_raw_lease():
    binding, artifact = fixture(native_lease_id="hmac-sha256:opaque")
    binding = binding.model_copy(update={"native_lease_id": "private-raw-lease"})
    assert correlate(binding, [artifact]).status == "unsupported"
