"""Strict private contracts reject scope expansion before a provider effect."""

import pytest
from governance_support import binding, source
from pydantic import ValidationError


def test_scope_contracts():
    b = binding()
    assert b.trust.entity_id == b.entity_id
    assert b.optional_authorization_details is False
    assert "entity" not in repr(b)
    for update in (
        {"extra": True},
        {"exclusive": False},
        {"ceiling_policies": ["root"]},
        {"vault_origin": "http://vault.example"},
        {"paths": {"direct_allowed": "database/creds/role"}},
    ):
        with pytest.raises(ValidationError):
            type(b).model_validate(b.model_dump() | update)


def test_source_never_grants_authority():
    s = source()
    with pytest.raises(ValidationError):
        type(s).model_validate(s.model_dump() | {"actions": ["register"]})
    with pytest.raises(ValidationError):
        type(s).model_validate(s.model_dump() | {"pointers": {"owner": "/owner"}})


def test_private_string_representation_hides_native_fields():
    b = binding(owner="private-team")
    assert "private-team" not in str(b)


@pytest.mark.parametrize(
    "subject",
    [
        "spiffe://test.example/agent space",
        "spiffe://test.example/agent?",
        "spiffe://test.example/agent#",
        "spiffe://bad host/agent",
    ],
)
def test_spiffe_uri_is_canonical_even_with_empty_query(subject):
    b = binding()
    with pytest.raises(ValidationError):
        type(b.trust).model_validate(b.trust.model_dump() | {"subject": subject})


@pytest.mark.parametrize("value", ["..", "../database/creds/role", "encoded%2Fpath", "a/b", "a\\b"])
def test_native_route_identifiers_cannot_redirect_fixed_reads(value):
    """Opaque subject IDs may be broad, but Vault route IDs remain one safe component."""
    b = binding()
    with pytest.raises(ValidationError):
        type(b).model_validate(b.model_dump() | {"entity_id": value})
