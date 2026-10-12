"""Untrusted callback payloads cannot smuggle authority or unbounded values."""

import pytest
from pydantic import ValidationError

from agent.sandbox.models import QueryRequest, ReadPlan


@pytest.mark.parametrize("value", [True, None, 1.5, {}, [], 2**63, "x" * 1025])
def test_bad_parameter(value):
    with pytest.raises(ValidationError):
        QueryRequest(sql="SELECT id FROM poc_records", parameters=[value])


def test_limits_and_immutable_plan():
    with pytest.raises(ValidationError):
        QueryRequest(sql="x" * 8193)
    with pytest.raises(ValidationError):
        QueryRequest(sql="SELECT id FROM poc_records", token="untrusted")
    with pytest.raises(ValidationError):
        ReadPlan(kind="rows", columns=("password",))
    plan = ReadPlan(kind="rows", columns=("id",))
    with pytest.raises(ValidationError):
        plan.limit = 200
