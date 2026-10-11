"""Reject coercion, malformed JSON and unbounded regression metadata."""

import pytest
from pydantic import ValidationError

from scripts.security_regression.models import Frame, RegressionError, decode


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b"[" * 10 + b"0" + b"]" * 10])
def test_json_is_strict(raw):
    """Duplicate keys and excessive nesting cannot silently alter evidence."""
    with pytest.raises(RegressionError):
        decode(raw)


@pytest.mark.parametrize("seq", [True, "1", 0, -1])
def test_sequence_is_strict(seq):
    """Protocol sequence accepts only positive integers."""
    with pytest.raises(ValidationError):
        Frame(seq=seq, kind="terminal", run_id="invalid")


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": True},
        {"run_id": "../private"},
        {"content_digest": "A" * 64},
        {"profile": "native"},
        {"kind": "log"},
        {"phases": ["passed"]},
        {"counters": {"issued": True}},
        {"counters": {"secret": 0}},
        {"count": "1"},
        {"count": 10001},
        {"exit_code": -1},
        {"raw_log": "PRIVATE"},
    ],
)
def test_frame_boundary_mutations(changes):
    """All strict frame identifiers, counts, enums and unknown fields fail closed."""
    data = dict(
        run_id="00000000-0000-0000-0000-000000000000",
        content_digest="0" * 64,
        selection_digest="1" * 64,
        profile="baseline",
        seq=1,
        kind="terminal",
    )
    with pytest.raises(ValidationError):
        Frame.model_validate(data | changes)


def test_native_promotion_is_not_a_model_field():
    """A native row cannot be coerced into acceptance by changing its outcome."""
    from scripts.security_regression.models import NativeDisposition
    from scripts.security_regression.report import native

    with pytest.raises(ValidationError):
        NativeDisposition.model_validate(native()[0] | {"outcome": "pass"})
