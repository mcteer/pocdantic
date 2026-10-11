"""Local verifier negatives stay synthetic and include each required rejection class."""

from governance_support import binding


def test_all_local_negative_classes_are_rejected():
    from agent.governance.negatives import local_checks

    result = local_checks(binding().trust)
    assert result["outcome"] == "pass"
    assert result["provenance"] == "synthetic"
    assert set(result["classes"]) == {"signature", "audience", "expiry", "trust", "entity"}
