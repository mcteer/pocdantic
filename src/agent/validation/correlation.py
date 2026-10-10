"""Correlate imported source events with private operation bindings.

Native identifiers or recorded operation references supply linkage; timestamps are
secondary checks. Unsupported source formats and ambiguous records stay blocked.
This evidence projection does not itself authorize new effects or recovery retries.
"""

from datetime import timedelta
from uuid import uuid5

from .models import CorrelationResult, Reason

REASONS = {
    "missing": Reason.evidence_missing,
    "unsupported": Reason.source_unsupported,
    "ambiguous": Reason.evidence_ambiguous,
    "outside_window": Reason.evidence_outside_window,
    "incomplete_export": Reason.export_incomplete,
    "contradicted": Reason.evidence_contradicted,
}


def correlate(binding, artifacts, *, expected_outcome=None):
    """Match one operation against source records and check expected outcome and native
    linkage.

    Contradictions fail, missing or unsupported evidence blocks, and matching records
    produce a correlation result referring to immutable artifact IDs.
    """
    expected_outcome = expected_outcome or binding.expected_outcome
    method = {
        "vault": "vault-request-v1",
        "verify": "verify-unsupported-v1",
        "logfire": "logfire-trace-v1",
    }[binding.source_kind]

    def result(status, refs=()):
        """Build a bounded result for this binding without exposing its native private
        fields.
        """
        return CorrelationResult(
            correlation_id=uuid5(
                binding.operation_ref,
                method + ":" + status + ":" + ":".join(sorted(str(r) for r in refs)),
            ),
            operation_ref=binding.operation_ref,
            method=method,
            artifact_refs=tuple(dict.fromkeys(refs)),
            status=status,
            reason=REASONS.get(status),
        )

    if binding.source_kind == "verify":
        return result("unsupported")
    sources = [
        a
        for a in artifacts
        if a.manifest.source_kind == binding.source_kind
        and a.manifest.source_instance == binding.source_instance
    ]
    candidates = []
    for artifact in sources:
        for event in artifact.events:
            if binding.source_kind == "vault":
                exact = (
                    binding.native_request_id
                    and event.native_request_id == binding.native_request_id
                ) or event.operation_ref == binding.operation_ref
            else:
                exact = (
                    binding.trace_id is not None
                    and binding.span_id is not None
                    and event.trace_id == binding.trace_id
                    and event.span_id == binding.span_id
                    and event.validation_id == binding.validation_id
                    and event.run_id == binding.run_id
                )
            if exact:
                candidates.append((artifact, event))
    if not candidates:
        return result("missing")
    refs = [a.artifact_id for a, _ in candidates]
    unique = {}
    for artifact, event in candidates:
        key = (event.source_event_id, event.kind)
        if key in unique and unique[key][1] != event:
            return result("contradicted", refs)
        unique[key] = (artifact, event)
    candidates = list(unique.values())
    bound_end = binding.finished_at or binding.started_at
    for artifact, event in candidates:
        if (
            not binding.started_at - timedelta(seconds=300)
            <= event.observed_at
            <= bound_end + timedelta(seconds=300)
            or not artifact.manifest.window_start
            <= event.observed_at
            <= artifact.manifest.window_end
        ):
            return result("outside_window", refs)
    if binding.source_kind == "vault":
        if expected_outcome == "denied" and any(
            a.manifest.completeness != "complete" for a, _ in candidates
        ):
            return result("incomplete_export", refs)
        ids = {e.native_request_id for _, e in candidates}
        if len(ids) != 1:
            return result("ambiguous", refs)
        if {e.kind for _, e in candidates} != {"request", "response"}:
            return result(
                "incomplete_export"
                if any(a.manifest.completeness != "complete" for a, _ in candidates)
                else "missing",
                refs,
            )
        for _, event in candidates:
            if event.phase is not None and event.phase != binding.phase:
                return result("contradicted", refs)
            if event.kind == "response" and event.outcome != expected_outcome:
                return result("contradicted", refs)
            if binding.native_lease_id and event.native_lease_id:
                if event.native_lease_id.startswith("hmac-"):
                    # No supported compatible audit-device HMAC binding has been captured.
                    return result("unsupported", refs)
                if event.native_lease_id != binding.native_lease_id:
                    return result("contradicted", refs)
        if (
            binding.phase == "cleanup"
            and binding.native_lease_id
            and not any(e.native_lease_id for _, e in candidates)
        ):
            return result("unsupported", refs)
    else:
        if len(candidates) != 1:
            return result("ambiguous", refs)
        artifact, span = candidates[0]
        if span.parent_span_id != binding.parent_span_id:
            return result("contradicted", refs)
        if span.parent_span_id:
            parent = [
                e
                for a in sources
                for e in a.events
                if e.kind == "span"
                and e.trace_id == span.trace_id
                and e.span_id == span.parent_span_id
            ]
            if not parent:
                return result("missing", refs)
            if any(
                e.validation_id != binding.validation_id
                or e.run_id not in {binding.run_id, binding.parent_run_id}
                for e in parent
            ):
                return result("contradicted", refs)
    return result("matched", refs)
