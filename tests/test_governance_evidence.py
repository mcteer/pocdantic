"""Imports and local closure cannot erase uncertain provider authority."""

import hashlib
import json
from uuid import uuid4

import pytest
from governance_support import binding, installed, source

from agent.governance.config import binding_digest
from agent.governance.evidence import close, import_file
from agent.governance.models import Evidence, GovernanceError, now
from agent.validation.models import canonical, implementation_revision


def case(tmp_path):
    """Use only a temporary installation and a synthetic host-reviewed binding."""
    store = installed(tmp_path)
    store.configure((source(),), 1)
    candidate = store.case("fixture")
    candidate = candidate.model_copy(update={"binding": binding()})
    store.change(lambda j: j.model_copy(update={"candidates": (candidate,)}))
    return store, candidate


def test_import_digest_idempotency_and_changed_replay(tmp_path):
    store, candidate = case(tmp_path)
    artifact = {"decision": "fixture"}
    item = Evidence(
        candidate_id=candidate.candidate_id,
        case_id=candidate.case_id,
        generation=1,
        environment=store.environment,
        implementation=implementation_revision(),
        binding_digest=binding_digest(candidate.binding),
        source_digest="0" * 64,
        artifact_digest=hashlib.sha256(canonical(artifact)).hexdigest(),
        kind="audit",
        outcome="inconclusive",
        provenance="operator",
        observed_at=now(),
    )
    target = tmp_path / "receipt.json"
    target.touch(mode=0o600)
    envelope = {"schema_version": 1, "evidence": item.model_dump(mode="json"), "artifact": artifact}
    target.write_text(json.dumps(envelope))
    first = import_file(
        store, target, candidate.candidate_id, "reviewer", revision=store.read().revision
    )
    again = import_file(
        store, target, candidate.candidate_id, "reviewer", revision=store.read().revision
    )
    assert first == again
    assert len(store.read().evidence) == 1
    envelope["evidence"]["outcome"] = "pass"
    target.write_text(json.dumps(envelope))
    with pytest.raises(GovernanceError, match="replay_conflict"):
        import_file(
            store, target, candidate.candidate_id, "reviewer", revision=store.read().revision
        )


def test_native_discovery_cannot_be_invented_by_an_import(tmp_path):
    store, candidate = case(tmp_path)
    item = Evidence(
        candidate_id=candidate.candidate_id,
        case_id=candidate.case_id,
        generation=1,
        environment=store.environment,
        implementation=implementation_revision(),
        binding_digest=binding_digest(candidate.binding),
        source_digest="0" * 64,
        artifact_digest=hashlib.sha256(canonical({})).hexdigest(),
        kind="discovery",
        outcome="pass",
        provenance="native",
        observed_at=now(),
        observation_id=uuid4(),
    )
    target = tmp_path / "receipt.json"
    target.touch(mode=0o600)
    target.write_text(
        json.dumps({"schema_version": 1, "evidence": item.model_dump(mode="json"), "artifact": {}})
    )
    with pytest.raises(GovernanceError, match="native_evidence_missing"):
        import_file(
            store, target, candidate.candidate_id, "reviewer", revision=store.read().revision
        )
    assert not store.read().evidence


def test_close_refuses_unknown_issuance(tmp_path):
    store, candidate = case(tmp_path)
    store.intent(candidate.candidate_id, "svid")
    with pytest.raises(GovernanceError, match="issuance_unresolved"):
        close(store, candidate.candidate_id, "reviewer", revision=store.read().revision)
    assert store.read().candidates[0].closed_at is None


@pytest.mark.parametrize("no_issuance", [False, True])
def test_resolution_requires_explicit_current_provider_nonissuance_receipt(tmp_path, no_issuance):
    """Reviewed presence/absence alone cannot erase an unknown credential's pin."""
    from agent.governance.bootstrap import uncertain
    from agent.governance.evidence import attach, resolve
    from agent.governance.models import Facts

    store, candidate = case(tmp_path)
    intent = store.intent(candidate.candidate_id, "actor_oauth")
    submitted = now()
    uncertain(store, intent, candidate.binding, submitted_at=submitted)
    proof = Evidence(
        candidate_id=candidate.candidate_id,
        case_id=candidate.case_id,
        generation=1,
        environment=store.environment,
        implementation=implementation_revision(),
        binding_digest=binding_digest(candidate.binding),
        source_digest=binding_digest(candidate.binding),
        artifact_digest="0" * 64,
        kind="resolution",
        outcome="pass",
        provenance="native",
        observed_at=now(),
        independent=True,
        attributed=True,
        reviewed_by="fixture",
        reviewed_at=now(),
        attempt_id=intent.intent_id,
        facts=Facts(completed_at=now(), no_issuance=no_issuance),
    )
    attach(store, proof, revision=store.read().revision)
    if no_issuance:
        resolve(store, intent.intent_id, "reviewer", revision=store.read().revision)
        assert store.read().credentials[0].state == "denied"
    else:
        with pytest.raises(GovernanceError, match="native_evidence_missing"):
            resolve(store, intent.intent_id, "reviewer", revision=store.read().revision)
        assert store.read().credentials[0].state == "uncertain"
