import json

import pytest
from pydantic import ValidationError

from agent.evidence import CRITERIA, Evidence, load_evidence


def test_local_results_cannot_pass_live_acceptance():
    with pytest.raises(ValidationError):
        Evidence(
            criterion="UC1-02",
            status="pass",
            owner="owner",
            reason="mock passed",
            source="local",
            references=["test-run"],
            reviewer="reviewer",
        )


def test_all_fifteen_criteria_explicitly_recorded(tmp_path):
    file = tmp_path / "acceptance.json"
    file.write_text(
        json.dumps(
            [
                dict(criterion=c, status="blocked", owner="owner", reason="live proof pending")
                for c in CRITERIA
            ]
        )
    )
    evidence = load_evidence(file)
    assert len(evidence) == 15
    assert all(item.status == "blocked" for item in evidence)
