"""Local release cannot revive roots or bypass unresolved actions or revisions."""

import pytest
from response_support import enrolled, signal

from agent.response.coordinator import Coordinator
from agent.response.models import ResponseError


async def test_release_requires_current_complete_holds(tmp_path, workspace_settings):
    response = enrolled(workspace_settings, tmp_path)
    worker = Coordinator(response)
    one, _ = worker.submit(signal(workspace_settings))
    two, _ = worker.submit(signal(workspace_settings, event="second"))
    await worker.process(one.incident_id)
    await worker.process(two.incident_id)
    with pytest.raises(ResponseError, match="release_unsafe"):
        worker.release(
            workspace_settings.workload_definition,
            [one.incident_id],
            response.read().revision,
            "fixture",
        )
    with pytest.raises(ResponseError, match="revision_conflict"):
        worker.release(
            workspace_settings.workload_definition, [one.incident_id, two.incident_id], 1, "fixture"
        )
    worker.release(
        workspace_settings.workload_definition,
        [one.incident_id, two.incident_id],
        response.read().revision,
        "fixture",
    )
    assert not response.read().holds and response.read().generation == 4


def test_invalid_monotonic_clock_is_unavailable():
    """Clock discontinuity cannot become a negative or invented latency measurement."""
    from agent.response.coordinator import elapsed_ms

    assert elapsed_ms(10, 9) is None
    assert elapsed_ms(10, float("nan")) is None
    assert elapsed_ms(10, float("inf")) is None
    assert elapsed_ms(10, 10.25) == 250
