"""Native closeout never promotes synthetic, stale or contradictory evidence."""

from governance_support import binding, installed, source


def test_no_evidence_and_synthetic_are_blocked(tmp_path):
    from agent.governance.report import closeout, summary

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture")
    result = closeout(s.read(), c.candidate_id)
    assert len(result["tests"]) == 7
    assert all(t["outcome"] == "blocked" for t in result["tests"])
    b = binding(owner="private-owner")
    s.change(lambda j: j.model_copy(update={"candidates": (c.model_copy(update={"binding": b}),)}))
    public = summary(s.read())
    assert "private-owner" not in str(public)
    assert summary(s.read(), owner=("https://id.example", "other"))["candidates"] == []
    assert len(summary(s.read(), owner=(b.owner_issuer, b.owner_subject))["candidates"]) == 1
