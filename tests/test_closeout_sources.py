"""Original-byte extraction, provenance review and member read-only capture tests."""

import json
from uuid import uuid4

import pytest
from closeout_support import instant, inventory

from agent.closeout.models import CloseoutError, Inventory, byte_digest, digest, now, validate
from agent.closeout.sources import capture, import_source
from agent.closeout.store import Store


def source_fixture(project):
    """Create a reviewed-format fixture whose actual operation fields are source-derived."""
    inv = inventory()
    profile = inv["sources"][0]
    profile.update(
        fact_kind="operation_result",
        proof_labels=["sql-read"],
        selectors=[
            {"field": name, "pointer": "/" + name}
            for name in [
                "source_event_id",
                "occurred_at",
                "operation_ref",
                "values_operation",
                "values_target_ref",
                "values_request_digest",
                "values_policy_digest",
                "values_scope_digest",
                "values_result",
                "values_mechanism",
                "values_issued",
            ]
        ],
    )
    store = Store(project)
    head = store.prepare(validate(Inventory, inv))
    raw = json.dumps(
        {
            "source_event_id": "native-event-fixture",
            "occurred_at": instant(-1),
            "operation_ref": "op-fixture",
            "values_operation": "read",
            "values_target_ref": "fixture",
            "values_request_digest": "a" * 64,
            "values_policy_digest": "d" * 64,
            "values_scope_digest": "e" * 64,
            "values_result": "success",
            "values_mechanism": "unknown",
            "values_issued": 0,
        }
    ).encode()
    manifest = {
        "profile_id": profile["profile_id"],
        "format": "native-facts-v1",
        "provenance": "native",
        "input_digest": byte_digest(raw),
        "observed_at": instant(),
        "environment_digest": digest(validate(Inventory, inv)),
        "scope": str(uuid4()),
        "complete": True,
    }
    return store, head, raw, manifest


def test_native_import_derives_actual_values(closeout_project):
    """A native label does not substitute a free-form asserted outcome for source fields."""
    store, head, raw, manifest = source_fixture(closeout_project)
    ref = import_source(store, head, manifest, raw)
    value = store.read(head.dossier_id, ref)
    assert value["facts"][0]["values"]["operation"] == "read"
    assert value["facts"][0]["source_event_id"] == "native-event-fixture"
    assert value["raw_digest"] == byte_digest(raw)


def test_digest_and_secret_mismatch_reject_before_commit(closeout_project):
    """Known secret fields and wrong original digests never enter evidence storage."""
    store, head, raw, manifest = source_fixture(closeout_project)
    with pytest.raises(CloseoutError, match="integrity_failed"):
        import_source(store, head, manifest, raw + b" ")
    bad = json.loads(raw) | {"password": "private-secret-canary"}
    data = json.dumps(bad).encode()
    with pytest.raises(CloseoutError):
        import_source(store, head, manifest | {"input_digest": byte_digest(data)}, data)
    assert store.head(head.dossier_id).revision == 1


def test_missing_member_capture_does_not_create_source_root(closeout_project):
    """Inspection cannot initialize another feature's storage just to fill a report."""
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    with pytest.raises(CloseoutError, match="evidence_missing"):
        capture(store, head, "validation", uuid4())
    assert not (closeout_project / ".local/validation").exists()


@pytest.mark.parametrize("kind", ["validation", "response", "governance", "regression"])
def test_legacy_or_unsealed_member_never_initializes_or_passes(closeout_project, kind):
    """Malformed originals stay untouched and cannot become a captured proof record."""
    from closeout_support import private_file

    object_id = uuid4()
    local = closeout_project / ".local"
    local.mkdir(mode=0o700)
    root = (
        local / kind / str(object_id)
        if kind == "validation"
        else local / ("security-regression" if kind == "regression" else kind)
    )
    root.mkdir(parents=True, mode=0o700)
    names = {
        "validation": ["run.json"],
        "response": ["state.json", "anchor.json"],
        "governance": ["state.json", "anchor.json", "control.lock"],
        "regression": ["manifest.json", "seal.json"],
    }[kind]
    if kind == "regression":
        root = root / str(object_id)
        root.mkdir(mode=0o700)
    for name in names:
        private_file(root / name, {"legacy": "canary"})
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    with pytest.raises((CloseoutError, ValueError)):
        capture(store, head, kind, object_id)
    assert store.head(head.dossier_id).revision == 1
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}


def test_validation_reconstruction_is_readonly_software(closeout_project):
    """A captured offline run is rebuilt by maintained code and retains software provenance."""
    from closeout_support import private_file

    from agent.validation.models import ValidationRun

    run = ValidationRun(
        suite="offline-security",
        suite_revision="a" * 64,
        mode="offline",
        selected=("delegated-read",),
        configuration_fingerprint="b" * 64,
        state="running",
    )
    local = closeout_project / ".local"
    local.mkdir(mode=0o700)
    parent = local / "validation"
    parent.mkdir(mode=0o700)
    root = parent / str(run.validation_id)
    root.mkdir(mode=0o700)
    path = private_file(root / "run.json", run.model_dump(mode="json"))
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    ref = capture(store, head, "validation", run.validation_id)
    value = store.read(head.dossier_id, ref)
    assert value["provenance"] == "operator"
    assert value["source_assessment"]["scenarios"][0]["outcome"] == "interrupted"
    assert before == (path.read_bytes(), path.stat().st_mtime_ns)
    assert set(p.name for p in root.iterdir()) == {"run.json"}


def test_duplicate_ids_pointer_and_future_time_rejected(closeout_project):
    """Native-looking rows cannot hide duplicate events, bad pointers or future timestamps."""
    store, head, raw, manifest = source_fixture(closeout_project)
    row = json.loads(raw)
    for value in ([row, row], row | {"occurred_at": instant(6)}, row | {"values_issued": True}):
        data = json.dumps(value).encode()
        with pytest.raises(CloseoutError):
            import_source(store, head, manifest | {"input_digest": byte_digest(data)}, data)
    assert store.head(head.dossier_id).revision == 1


def test_source_snapshot_replacement_after_read_rejected(tmp_path, monkeypatch):
    """Source directory identity is stable across all bounded file reads."""
    from closeout_support import private_file

    import agent.closeout.sources as module

    root = tmp_path / "member"
    root.mkdir(mode=0o700)
    private_file(root / "state.json", {})
    read = module.read_owned
    changed = False

    def replacement(path, **kwargs):
        """Rename the original directory after its first file was read."""
        nonlocal changed
        value = read(path, **kwargs)
        if not changed:
            root.rename(tmp_path / "old")
            root.mkdir(mode=0o700)
            private_file(root / "state.json", {})
            changed = True
        return value

    monkeypatch.setattr(module, "read_owned", replacement)
    with pytest.raises(CloseoutError, match="input_changed"):
        module.snapshot_directory(root)


def test_installed_regression_capture_validates_original_sparse_frames(closeout_project):
    """Contributor default-elided frames are accepted read-only and remain software-only."""
    from datetime import timedelta

    from closeout_support import private_file

    from agent.closeout.models import now
    from agent.closeout.regression import REGRESSION_CASES
    from scripts.security_regression.catalog import CASES
    from scripts.security_regression.models import Frame, Manifest, Seal
    from scripts.security_regression.models import canonical as original_canonical

    assert set(REGRESSION_CASES) == {case.case_id for case in CASES}
    identifier = uuid4()
    stamp = now()
    from scripts.security_regression.catalog import policies, selection_digest
    from scripts.security_regression.models import digest as original_digest

    identity = {
        "run_id": str(identifier),
        "content_digest": "a" * 64,
        "selection_digest": selection_digest([CASES[0]], ["baseline"]),
    }
    manifest = Manifest(
        **identity,
        started_at=stamp.isoformat(),
        deadline_at=(stamp + timedelta(seconds=60)).isoformat(),
        cases=[CASES[0].case_id],
        profiles=["baseline"],
        complete_catalog=False,
        catalog_digest=original_digest([c.model_dump() for c in CASES]),
        profile_digests={"baseline": original_digest(policies()["baseline"])},
        versions={"python": "3.12"},
        base_digest="e" * 64,
        platform="macOS",
    )
    frames = []
    inventory_rows = [
        [selector, byte_digest(str(i).encode()), i + 1]
        for i, selector in enumerate(CASES[0].selectors)
    ]

    def emit(kind, **values):
        """Produce the real sparse protocol form without invoking a test process."""
        frame = Frame(**identity, seq=len(frames) + 1, kind=kind, profile="baseline", **values)
        frames.append(frame.model_dump(mode="json", exclude_none=True, exclude_defaults=True))

    for selector, node, ordinal in inventory_rows:
        emit("collection", selector=selector, node_digest=node, ordinal=ordinal)
    emit("collection", count=len(inventory_rows), inventory_digest=original_digest(inventory_rows))
    for selector, node, ordinal in inventory_rows:
        emit(
            "item",
            selector=selector,
            node_digest=node,
            ordinal=ordinal,
            phases=["pass", "pass", "pass"],
        )
    emit(
        "terminal",
        count=len(inventory_rows),
        inventory_digest=original_digest(inventory_rows),
        exit_code=0,
    )
    execution = {
        "profile": "baseline",
        "frames": frames,
        "reason": None,
        "cleanup": "drained",
        "exit_code": 0,
    }
    local = closeout_project / ".local"
    local.mkdir(mode=0o700)
    parent = local / "security-regression"
    parent.mkdir(mode=0o700)
    root = parent / str(identifier)
    root.mkdir(mode=0o700)
    originals = {
        "manifest.json": original_canonical(manifest),
        "baseline.json": original_canonical(execution),
    }
    seal = Seal(
        **identity,
        artifacts={name: byte_digest(raw) for name, raw in originals.items()},
        profile_digests=manifest.profile_digests,
        count=len(inventory_rows),
        state="completed",
        finished_at=stamp.isoformat(),
        exit_code=0,
        cleanup="drained",
    )
    originals["seal.json"] = original_canonical(seal)
    for name, raw in originals.items():
        private_file(root / name, raw)
    before = {name: (root / name).stat().st_mtime_ns for name in originals}
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inventory()))
    ref = capture(store, head, "regression", identifier)
    source = store.read(head.dossier_id, ref)
    assert source["provenance"] == "synthetic"
    assert source["source_assessment"]["software_outcome"] == "pass"
    assert source["source_assessment"]["complete_catalog"] is False
    assert before == {name: (root / name).stat().st_mtime_ns for name in originals}


def test_governance_capture_preserves_anchor_and_control_seal(closeout_project):
    """A real schema-valid local candidate snapshot is parsed with all anchored files intact."""
    from closeout_support import private_file
    from governance_support import source as governance_source

    from agent.governance.models import Candidate, Journal
    from agent.governance.store import Anchor, Seal
    from agent.validation.models import canonical as original_canonical

    install, identifier = uuid4(), uuid4()
    local = closeout_project / ".local"
    local.mkdir(mode=0o700)
    root = local / "governance"
    root.mkdir(mode=0o700)
    for name in ("anchor.json", "state.json", "control.lock", "effect.lock", "service.lock"):
        private_file(root / name, b"")
    state = Journal(
        installation_id=install,
        environment="a" * 64,
        sources=(governance_source(),),
        candidates=(
            Candidate(
                candidate_id=identifier, alias="fixture", source="fixture", source_generation=1
            ),
        ),
    )
    info = root.stat()
    anchor = Anchor(
        installation_id=install,
        environment=state.environment,
        root_identity=(info.st_dev, info.st_ino),
        file_identities={
            name: ((root / name).stat().st_dev, (root / name).stat().st_ino)
            for name in ("anchor.json", "control.lock", "effect.lock", "service.lock")
        },
    )
    private_file(root / "state.json", original_canonical(state))
    info = (root / "state.json").stat()
    seal = Seal(
        installation_id=install,
        revision=state.revision,
        state_identity=(info.st_dev, info.st_ino),
        state_digest=byte_digest(original_canonical(state)),
    )
    private_file(root / "anchor.json", original_canonical(anchor))
    private_file(root / "control.lock", original_canonical(seal))
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}
    inv = inventory()
    inv["sources"][0]["member_environment_digest"] = state.environment
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inv))
    captured = capture(store, head, "governance", identifier)
    value = store.read(head.dossier_id, captured)
    assert value["provenance"] == "operator"
    assert len(value["source_assessment"]["tests"]) == 7
    assert {t["outcome"] for t in value["source_assessment"]["tests"]} == {"blocked"}
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}


def test_response_capture_rechecks_policy_and_local_only_provenance(closeout_project):
    """A genuine v2 journal without provider observations is operator evidence, never native."""
    from closeout_support import private_file

    from agent.response.models import (
        Incident,
        ResponseAction,
        ResponseAnchor,
        RootTarget,
        SourcePolicy,
    )
    from agent.response.providers.journal import ResponseJournalV2
    from agent.validation.models import canonical as legacy_canonical

    install, identifier = uuid4(), uuid4()
    policy = SourcePolicy(
        workload_definition="fixture", environment_digest="a" * 64, issuer="offline"
    )
    state = ResponseJournalV2(
        installation_id=install,
        environment_digest=policy.environment_digest,
        policy_digest=byte_digest(legacy_canonical(policy)),
        incidents=(
            Incident(
                incident_id=identifier,
                source="local-operator",
                event_id="fixture",
                payload_digest="b" * 64,
                policy_digest=byte_digest(legacy_canonical(policy)),
                target=RootTarget(root_run_id=uuid4()),
                source_at=now(),
                actions=(
                    ResponseAction(kind="cancel_local", target_id=identifier, status="confirmed"),
                ),
            ),
        ),
    )
    (closeout_project / ".local").mkdir(mode=0o700)
    root = closeout_project / ".local" / "response"
    for name, value in {
        "state.json": state,
        "policy.json": policy,
        "anchor.json": ResponseAnchor(installation_id=install, recovery_mode="not_configured"),
    }.items():
        private_file(root / name, legacy_canonical(value))
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}
    inv = inventory()
    inv["sources"][0]["member_environment_digest"] = state.environment_digest
    store = Store(closeout_project)
    head = store.prepare(validate(Inventory, inv))
    ref = capture(store, head, "response", identifier)
    captured = store.read(head.dossier_id, ref)
    assert captured["provenance"] == "operator"
    assert len(captured["source_assessment"]["cases"]) == 9
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}
