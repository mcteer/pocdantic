"""Strict boundary and confidential projection contracts for the closeout workflow."""

import pytest
from closeout_support import inventory
from pydantic import ValidationError

from agent.closeout.models import Inventory, decode, validate


@pytest.mark.parametrize(
    "mutation",
    [
        lambda x: x.update(schema_version=True),
        lambda x: x.update(unexpected="ignored"),
        lambda x: x.update(owners=["untrusted"]),
        lambda x: x.update(definitions=[]),
        lambda x: x["sources"][0].update(clock_uncertainty=6),
        lambda x: x["sources"][0].update(reporting_delay=True),
        lambda x: x["sources"][0].update(profile_id="not-a-uuid"),
    ],
)
def test_inventory_rejects_ambiguous_input(mutation):
    """Reject coercion, unknown fields and data outside the reviewed contract."""
    value = inventory()
    mutation(value)
    with pytest.raises((ValueError, ValidationError)):
        validate(Inventory, value)


def test_inventory_accepts_explicit_unavailable_capability():
    """A structurally complete inventory does not invent provider availability."""
    assert validate(Inventory, inventory()).sources[0].capabilities["audit"] == "unavailable"


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b"[" * 9 + b"0" + b"]" * 9])
def test_decoder_rejects_ambiguous_json(raw):
    """Unknown JSON cannot undermine byte-bound deterministic evidence."""
    with pytest.raises(ValueError):
        decode(raw)
