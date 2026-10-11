"""Execution accounting rejects partial, skipped and incorrectly ordered phases."""

import pytest

from scripts.security_regression.runner import phase_outcome


@pytest.mark.parametrize(
    "phases,reason",
    [
        (["pass", "pass", "pass"], None),
        (["pass", "pass", "fail"], "test_failed"),
        (["pass", "skip", "pass"], "test_skipped"),
        (["pass", "xfail", "pass"], "expected_failure"),
        (["pass", "xpass", "pass"], "unexpected_pass"),
        (["pass", "missing", "pass"], "phase_missing"),
        (["pass"], "phase_missing"),
    ],
)
def test_phase_completeness(phases, reason):
    """A passed call cannot conceal failed cleanup or absent execution."""
    assert phase_outcome(phases)[1] == reason


@pytest.fixture
def isolated_probe(tmp_path):
    """Supply a disposable maintained snapshot for child protocol and collection tests."""
    from pathlib import Path

    from scripts.security_regression.isolation import snapshot

    with snapshot(Path(__file__).resolve().parents[1]) as (root, _):
        (root / "tests/conftest.py").write_text("")
        yield root


def probe(root, source, timeout=10):
    """Execute a fixed synthetic test function using the production guarded child path."""
    import time
    from uuid import uuid4

    from scripts.security_regression.isolation import content_digest
    from scripts.security_regression.models import Manifest, digest, now
    from scripts.security_regression.runner import execute

    (root / "tests/test_probe.py").write_text(source)
    manifest = Manifest(
        run_id=str(uuid4()),
        content_digest=content_digest(root),
        selection_digest="1" * 64,
        started_at=now(),
        deadline_at=now(),
        cases=["probe"],
        profiles=["baseline"],
        complete_catalog=False,
        catalog_digest="2" * 64,
        profile_digests={"baseline": digest({})},
        versions={"python": "3.12"},
        base_digest="3" * 64,
        platform="macOS",
    )
    return execute(
        root, manifest, "baseline", ["tests/test_probe.py::test_probe"], time.monotonic() + timeout
    )


@pytest.mark.parametrize(
    "body,reason",
    [
        ("def test_probe(): assert True", None),
        ("import pytest\n@pytest.mark.skip\ndef test_probe(): pass", "test_skipped"),
        ("import pytest\n@pytest.mark.xfail\ndef test_probe(): assert False", "expected_failure"),
        ("import pytest\n@pytest.mark.xfail\ndef test_probe(): assert True", "unexpected_pass"),
        (
            (
                "import pytest\n@pytest.fixture(autouse=True)\ndef cleanup():\n yield"
                "\n assert False\ndef test_probe(): assert True"
            ),
            "test_failed",
        ),
        (
            (
                "import pytest\n@pytest.fixture(autouse=True)\ndef setup():\n assert "
                "False\ndef test_probe(): assert True"
            ),
            "test_failed",
        ),
    ],
)
def test_real_phase_stream(isolated_probe, body, reason):
    "The actual plugin classifies each pytest phase, including teardown after a successful call."
    result = probe(isolated_probe, body)
    items = [f for f in result["frames"] if f["kind"] == "item"]
    assert len(items) == 1
    assert phase_outcome(items[0]["phases"])[1] == reason
    assert result["cleanup"] == "drained"


def test_caught_precollection_connection_is_still_failed(isolated_probe):
    """A collection-time attempt cannot be hidden by catching the guard's exception."""
    result = probe(
        isolated_probe,
        (
            "import socket\ntry: socket.getaddrinfo('private.example',443)\nexce"
            "pt Exception: pass\ndef test_probe(): assert True"
        ),
    )
    assert result["reason"] == "isolation_failed"


def test_parameter_inventory(isolated_probe):
    """Every parametrized item expands and executes; parameter strings never leave the child."""
    result = probe(
        isolated_probe,
        (
            "import pytest\n@pytest.mark.parametrize('value',[1,2,3],ids=['PRIV"
            "ATE_A','PRIVATE_B','PRIVATE_C'])\ndef test_probe(value): assert va"
            "lue > 0"
        ),
    )
    assert sum(f["kind"] == "item" for f in result["frames"]) == 3
    assert "PRIVATE_" not in str(result)


def test_deadline_and_partial_raw_stream(isolated_probe):
    """An unbounded child is drained and its raw output cannot reach normalized records."""
    result = probe(
        isolated_probe,
        "import time\ndef test_probe():\n print('PRIVATE_RAW',flush=True)\n time.sleep(30)",
        timeout=0.8,
    )
    assert result["reason"] == "timeout"
    assert result["cleanup"] == "drained"
    assert "PRIVATE_RAW" not in str(result)


@pytest.mark.parametrize(
    "source,reason",
    [
        (
            (
                "import os\ndef test_probe():\n os.write(int(os.environ['SECURI"
                "TY_REGRESSION_FD']),b'x'*17000)"
            ),
            "limits_exceeded",
        ),
        (
            (
                "import os\ndef test_probe():\n os.write(int(os.environ['SECURI"
                "TY_REGRESSION_FD']),b'{}\\n')"
            ),
            "protocol_invalid",
        ),
        ("import os\ndef test_probe():\n os._exit(0)", "phase_missing"),
        (
            (
                "import subprocess\ntry: subprocess.run(['sh','-c','true'])\nex"
                "cept Exception: pass\ndef test_probe(): assert True"
            ),
            "isolation_failed",
        ),
        (
            (
                "import psycopg\ntry: psycopg.connect('host=private.example')\n"
                "except Exception: pass\ndef test_probe(): assert True"
            ),
            "isolation_failed",
        ),
    ],
)
def test_protocol_and_native_effect_failures(isolated_probe, source, reason):
    """Malformed/lost metadata and caught native/subprocess attempts remain nonpassing."""
    result = probe(isolated_probe, source)
    assert result["reason"] == reason
    assert result["cleanup"] == "drained"


def test_parent_death_watchdog(isolated_probe):
    """Killing an owner cannot leave its guarded test process running past the watchdog."""
    import os
    import subprocess
    import sys
    import time

    source = (
        "import os,time\nfrom pathlib import Path\ndef test_probe():\n P"
        "ath('scratch/child.pid').write_text(str(os.getpid()))\n time."
        "sleep(30)"
    )
    script = (
        "import sys;from pathlib import Path;sys.path[:0]=['.','tests'];"
        "from test_security_regression_execution import probe;"
        f"probe(Path({str(isolated_probe)!r}),{source!r},timeout=10)"
    )
    owner = subprocess.Popen(
        [sys.executable, "-c", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    pidfile = isolated_probe / "scratch/child.pid"
    try:
        deadline = time.monotonic() + 5
        while not pidfile.exists() and owner.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert pidfile.exists()
        child_pid = int(pidfile.read_text())
        owner.kill()
        owner.wait(timeout=2)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            pytest.fail("owned child survived owner loss")
    finally:
        if owner.poll() is None:
            owner.kill()
            owner.wait(timeout=2)


def test_deselection_and_empty_collection(isolated_probe):
    """Collection hooks cannot quietly remove a selected item."""
    (isolated_probe / "tests/conftest.py").write_text(
        "def pytest_collection_modifyitems(items): items.clear()"
    )
    result = probe(isolated_probe, "def test_probe(): assert True")
    assert result["reason"] in {"selection_incomplete", "empty_selection", "phase_missing"}
    assert not any(f["kind"] == "item" for f in result["frames"])


@pytest.mark.parametrize("mutation", ["extra", "duplicate", "foreign"])
def test_extra_duplicate_foreign_frames(isolated_probe, mutation):
    """Metadata claims for foreign or repeated items cannot manufacture execution completeness."""
    source = (
        "def test_probe(request):\n"
        " r=next(p for p in request.config.pluginmanager.get_plugins() if hasattr(p,'identity'))\n"
        " selector,node,ordinal=next(iter(r.items.values()))\n"
    )
    if mutation == "extra":
        source += " selector='tests/test_unknown.py::test_unknown'\n"
    if mutation == "foreign":
        source += " r.identity['run_id']='00000000-0000-0000-0000-000000000000'\n"
    source += (
        " r.emit('item',selector=selector,node_digest=node,ordinal=ordinal,phases=['pass']*3)\n"
    )
    result = probe(isolated_probe, source)
    assert result["reason"] == "protocol_invalid"
    assert result["cleanup"] == "drained"


def test_capacity_overflow_stops_before_dispatch(isolated_probe):
    """The child refuses expanded collection beyond the remaining run allowance before any call."""
    import time
    from uuid import uuid4

    from scripts.security_regression.isolation import content_digest
    from scripts.security_regression.models import Manifest, now
    from scripts.security_regression.runner import execute

    (isolated_probe / "tests/test_probe.py").write_text(
        "import pytest\nfrom pathlib import Path\n"
        "@pytest.mark.parametrize('i',[1,2])\ndef test_probe(i):\n"
        " Path('scratch/dispatched').write_text('yes')"
    )
    manifest = Manifest(
        run_id=str(uuid4()),
        content_digest=content_digest(isolated_probe),
        selection_digest="1" * 64,
        started_at=now(),
        deadline_at=now(),
        cases=["probe"],
        profiles=["baseline"],
        complete_catalog=False,
        catalog_digest="2" * 64,
        profile_digests={"baseline": "3" * 64},
        versions={"python": "3.12"},
        base_digest="4" * 64,
        platform="macOS",
    )
    result = execute(
        isolated_probe,
        manifest,
        "baseline",
        ["tests/test_probe.py::test_probe"],
        time.monotonic() + 10,
        item_limit=1,
    )
    assert result["reason"] == "limits_exceeded"
    assert not (isolated_probe / "scratch/dispatched").exists()
