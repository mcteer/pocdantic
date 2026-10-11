"""Compiled coverage and CLI selection cannot hide missing or renamed tests."""

import pytest

from scripts.security_regression.catalog import CASES, select, validate
from scripts.security_regression.models import BUILDS, GROUPS, RegressionError


def test_complete_catalog():
    """All fourteen build items and ten groups resolve to maintained exact functions."""
    from pathlib import Path

    selectors = validate(Path(__file__).resolve().parents[1])
    assert {g for c in CASES for g in c.groups} == set(GROUPS)
    assert {b for c in CASES for b in c.build_items} == set(BUILDS)
    assert len(selectors) == len(set(selectors))
    assert not any("test_security_regression_report" in s for s in selectors)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"groups": ["unknown"]},
        {"groups": ["F12-T1", "F12-T1"]},
        {"identifiers": ["approval-effects", "approval-effects"]},
        {"identifiers": ["/tmp/private"]},
        {"profile": "live"},
        {"groups": ["F12-T1"], "identifiers": ["approval-effects"]},
    ],
)
def test_invalid_selection(kwargs):
    """Unknown, duplicate and competing selections fail before state creation."""
    with pytest.raises(RegressionError):
        select(**kwargs)


def test_default_and_partial():
    """Default covers both profiles; reproduction selects one compiled case and profile."""
    assert select() == (CASES, ["baseline", "restricted"])
    cases, profiles = select(identifiers=["approval-effects"], profile="restricted")
    assert [c.case_id for c in cases] == ["approval-effects"]
    assert profiles == ["restricted"]


def test_renamed_selector_fails(tmp_path):
    """Static completeness cannot pass when a mapped function disappears."""
    with pytest.raises(RegressionError, match="catalog_invalid"):
        validate(tmp_path)


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["run", "--live"],
        ["run", "--timeout", "9999"],
        ["run", "--output-root", "/tmp/private"],
        ["run", "-k", "secret"],
        ["report", "--run", "../secret"],
    ],
)
def test_closed_cli(args, capsys):
    """No arbitrary options, credential inputs, paths or implicit run are accepted."""
    from scripts.security_regression.runner import main

    assert main(args) == 2
    assert "secret" not in capsys.readouterr().out


def test_shared_selector_is_deduplicated():
    """Two reviewed mappings can share a test without causing duplicate execution."""
    from pathlib import Path

    original = CASES[0]
    second = original.model_copy(update={"case_id": "shared-authority"})
    selectors = validate(Path(__file__).resolve().parents[1], [original, second], complete=False)
    assert selectors == sorted(original.selectors)
