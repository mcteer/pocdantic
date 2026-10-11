"""Exact Function 13 coverage and closed guide selector checks."""

import pytest

from agent.closeout.catalog import catalog, guide


def test_catalog_has_complete_exact_design_coverage():
    """No build item, use case, criterion, test or phase gate is omitted."""
    data = catalog()
    for key, count in {
        "build": 13,
        "tests": 6,
        "gates": 5,
        "criteria": 15,
        "use_cases": 4,
        "experiments": 4,
        "roles": 5,
    }.items():
        assert len(data[key]) == len(set(data[key])) == count


def test_guide_has_concrete_actions_and_never_interpolates_input():
    """Guides give existing command steps and explicit native limitations."""
    assert "agent validate ready --suite live-database" in str(guide("UC1"))
    assert "audit" in str(guide("UC1"))
    with pytest.raises(ValueError):
        guide("UC1; curl hostile.example")
