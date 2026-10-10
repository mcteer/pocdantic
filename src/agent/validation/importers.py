"""Versioned native parsers. Imports never fetch URLs or extract archives."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError

from .models import ImportManifest, NormalizedSourceEvent, SourceArtifact, digest
from .store import MAX_ARTIFACT, MAX_EVENTS, StoreError, decode_json, read_private


def timestamp(value, *, milliseconds=False):
    try:
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError()
            return parsed.astimezone(UTC)
        if milliseconds and type(value) in (int, float):
            return datetime.fromtimestamp(value / 1000, UTC)
    except (ValueError, OverflowError, TypeError):
        pass
    raise StoreError("schema_invalid")


def vault_record(row, manifest):
    if row.get("type") not in {"request", "response"}:
        raise StoreError("source_unsupported")
    request = row.get("request")
    if not isinstance(request, dict) or not request.get("id"):
        raise StoreError("schema_invalid")
    response = row.get("response") or {}
    path = request.get("path", "")
    phase = (
        "cleanup"
        if path == "sys/leases/revoke"
        else "credential"
        if path.startswith("database/creds/")
        else None
    )
    headers = request.get("headers") or {}
    correlation = next((v for k, v in headers.items() if k.lower() == "x-correlation-id"), None)
    if isinstance(correlation, list):
        if len(correlation) != 1:
            raise StoreError("schema_invalid")
        correlation = correlation[0]
    operation_ref = None
    if correlation is not None:
        try:
            operation_ref = UUID(correlation)
        except (ValueError, TypeError):
            # Native header HMAC or unrelated IDs cannot manufacture a generated binding.
            pass
    lease = (
        (request.get("data") or {}).get("lease_id")
        if phase == "cleanup"
        else response.get("lease_id")
    )
    return NormalizedSourceEvent(
        source_event_id=request["id"],
        source_kind="vault",
        source_instance=manifest.source_instance,
        observed_at=timestamp(row.get("time")),
        kind=row["type"],
        native_request_id=request["id"],
        native_lease_id=lease,
        operation_ref=operation_ref,
        phase=phase,
        outcome="denied"
        if row.get("error")
        else "success"
        if row["type"] == "response"
        else "unknown",
    )


def verify_record(row, manifest):
    return NormalizedSourceEvent(
        source_event_id=row["id"],
        source_kind="verify",
        source_instance=manifest.source_instance,
        observed_at=timestamp(row["time"], milliseconds=True),
        kind="audit",
        native_correlation_id=row.get("correlationid"),
        outcome="unknown",
    )


def logfire_record(row, manifest):
    project = row.get("project_id") or row.get("project_name") or row.get("project")
    if project is not None and project != manifest.source_instance:
        raise StoreError("evidence_contradicted")
    attributes = row.get("attributes") or {}
    if not isinstance(attributes, dict):
        raise StoreError("schema_invalid")
    return NormalizedSourceEvent(
        source_event_id=row["span_id"],
        source_kind="logfire",
        source_instance=manifest.source_instance,
        observed_at=timestamp(row["start_timestamp"]),
        kind="span",
        trace_id=row["trace_id"],
        span_id=row["span_id"],
        parent_span_id=row.get("parent_span_id") or None,
        validation_id=attributes.get("validation_id"),
        run_id=attributes.get("run_id"),
        parent_run_id=attributes.get("parent_run_id"),
        phase="telemetry",
        outcome="success",
    )


def normalize(raw, manifest):
    if len(raw) > MAX_ARTIFACT:
        raise StoreError("limits_exceeded")
    try:
        if manifest.source_kind == "vault":
            rows = [decode_json(line) for line in raw.splitlines() if line.strip()]
            adapter = vault_record
        elif manifest.source_kind == "verify":
            rows = decode_json(raw)["response"]["events"]["events"]
            adapter = verify_record
        else:
            value = decode_json(raw)
            rows = value["rows"] if isinstance(value, dict) else value
            adapter = logfire_record
        if not isinstance(rows, list) or not rows:
            raise StoreError("source_unsupported")
        if len(rows) > MAX_EVENTS:
            raise StoreError("limits_exceeded")
        unique = {}
        for row in rows:
            if not isinstance(row, dict):
                raise StoreError("schema_invalid")
            event = adapter(row, manifest)
            key = (event.source_instance, event.source_event_id, event.kind)
            if key in unique and unique[key] != event:
                raise StoreError("evidence_contradicted")
            unique[key] = event
        return tuple(unique.values())
    except (KeyError, TypeError, AttributeError, ValidationError):
        raise StoreError("schema_invalid") from None


def load_artifacts(writer):
    artifacts = []
    for path in sorted(writer.path.glob("artifact-*.json")):
        artifact = SourceArtifact.model_validate(writer.read_json(path.name))
        raw = writer.read_bytes(f"source-{artifact.artifact_id}.raw")
        if (
            hashlib.sha256(raw).hexdigest() != artifact.raw_digest
            or digest([e.model_dump(mode="json") for e in artifact.events])
            != artifact.normalized_digest
        ):
            raise StoreError("digest_mismatch")
        if normalize(raw, artifact.manifest) != artifact.events:
            raise StoreError("digest_mismatch")
        artifacts.append(artifact)
    return artifacts


def import_source(writer, source, input_path, manifest):
    if not isinstance(manifest, ImportManifest):
        manifest = ImportManifest.model_validate(manifest)
    if source != manifest.source_kind:
        raise StoreError("source_unsupported")
    raw = read_private(Path(input_path))
    events = normalize(raw, manifest)
    previous = load_artifacts(writer)
    if sum(a.event_count for a in previous) + len(events) > MAX_EVENTS:
        raise StoreError("limits_exceeded")
    existing = {
        (e.source_instance, e.source_kind, e.source_event_id, e.kind): e
        for artifact in previous
        for e in artifact.events
    }
    for event in events:
        key = (event.source_instance, event.source_kind, event.source_event_id, event.kind)
        if key in existing and event != existing[key]:
            raise StoreError("evidence_contradicted")
    artifact = SourceArtifact(
        manifest=manifest,
        events=events,
        event_count=len(events),
        raw_digest=hashlib.sha256(raw).hexdigest(),
        bytes_count=len(raw),
        normalized_digest=digest([e.model_dump(mode="json") for e in events]),
    )
    writer.write_bytes(f"source-{artifact.artifact_id}.raw", raw)
    writer.write_json(f"artifact-{artifact.artifact_id}.json", artifact)
    return artifact


def load_transactions(writer):
    from .models import TransactionEvidence

    values = []
    for path in sorted(writer.path.glob("transaction-*.json")):
        value = TransactionEvidence.model_validate(writer.read_json(path.name))
        raw = writer.read_bytes(f"source-{value.artifact_id}.raw")
        if hashlib.sha256(raw).hexdigest() != value.raw_digest:
            raise StoreError("digest_mismatch")
        data = decode_json(raw)
        transaction_data = data.get("transactionData")
        if isinstance(transaction_data, str):
            transaction_data = decode_json(transaction_data.encode())
        if not isinstance(transaction_data, dict):
            raise StoreError("schema_invalid")
        native = {
            item.get("name"): item.get("value")
            for item in transaction_data.get("additionalData", ())
        }
        state = data.get("state")
        approved = state in {"SUCCESS", "VERIFY_SUCCESS"}
        denied = state in {
            "DENIED",
            "FAILED",
            "CANCELED",
            "TIMEOUT",
            "VERIFY_FAILED",
            "VERIFY_DENIED",
            "EXPIRED",
        }
        if (
            data.get("id") != value.native_transaction_id
            or native.get("approval_id") != str(value.approval_ref)
            or native.get("action_digest") != value.action_digest
            or not (approved if value.decision == "approved" else denied)
        ):
            raise StoreError("digest_mismatch")
        values.append(value)
    return values
