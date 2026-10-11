"""Result capacity is bounded before dispatch and normalized reporting stays fast."""

import time

import pytest
from test_security_regression_report import seed

from scripts.security_regression.models import Frame, RegressionError, decode
from scripts.security_regression.report import reconstruct
from scripts.security_regression.store import Store


def test_ten_thousand_report_budget(tmp_path):
    """Reconstruct 10,000 actual normalized results within five seconds excluding I/O setup."""
    run = seed(tmp_path, count=10000)
    with Store(tmp_path).open(run) as writer:
        started = time.monotonic()
        report, code = reconstruct(tmp_path, writer)
        assert time.monotonic() - started < 5
    assert code == 0 and report["count"] == 10000
    assert report["cases"][0]["count"] == 10000


def test_frame_limit_and_count_coercion():
    """Oversize frames and result count overflow are rejected instead of truncated to pass."""
    with pytest.raises(RegressionError, match="limits_exceeded"):
        decode(b"x" * (16384 + 1), 16384)
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Frame(
            run_id="00000000-0000-0000-0000-000000000000",
            content_digest="0" * 64,
            selection_digest="1" * 64,
            profile="baseline",
            kind="terminal",
            seq=1,
            count=10001,
        )


@pytest.mark.parametrize(
    "name,size",
    [
        ("manifest.json", 8 * 1024 * 1024),
        ("report.json", 8 * 1024 * 1024),
        ("artifact.json", 10 * 1024 * 1024),
    ],
)
def test_artifact_capacity(tmp_path, name, size):
    """Oversize records never become visible as partial immutable artifacts."""
    from uuid import uuid4

    with Store(tmp_path).create(str(uuid4())) as writer:
        with pytest.raises(RegressionError, match="limits_exceeded"):
            writer.write(name, {"synthetic": "x" * size})
        assert not (writer.path / name).exists()


def test_run_file_quota(tmp_path):
    """The one-hundred-artifact ceiling applies even to tiny valid records."""
    from uuid import uuid4

    with Store(tmp_path).create(str(uuid4())) as writer:
        for i in range(100):
            writer.write(f"artifact-{i}.json", {"synthetic": i})
        with pytest.raises(RegressionError, match="limits_exceeded"):
            writer.write("overflow.json", {})


def test_run_byte_quota(tmp_path):
    """Aggregate storage is bounded independently of per-artifact size."""
    from uuid import uuid4

    with Store(tmp_path).create(str(uuid4())) as writer:
        value = {"synthetic": "x" * (10 * 1024 * 1024 - 100)}
        for i in range(10):
            writer.write(f"artifact-{i}.json", value)
        with pytest.raises(RegressionError, match="limits_exceeded"):
            writer.write("overflow.json", value)
