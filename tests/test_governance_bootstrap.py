"""Candidate tokens must carry the exact requested resource grant and actor identity."""

import asyncio
from datetime import timedelta
from types import SimpleNamespace

import pytest
from governance_support import binding, installed, source
from pydantic import SecretStr

from agent.governance.models import GovernanceError, now


def test_signed_bootstrap_claims_are_exact():
    from agent.governance.bootstrap import validate_claims

    b = binding()
    details = [
        {"type": "vault:path_access", "path": "proof/data/allowed", "capabilities": ["read"]}
    ]
    t = int(now().timestamp())
    valid = {
        "iss": b.actor_issuer,
        "sub": b.actor_subject,
        "aud": "vault",
        "iat": t,
        "exp": t + 60,
        "authorization_details": details,
    }
    validate_claims(valid, b, "vault", details)
    missing = dict(valid)
    missing.pop("authorization_details")
    with pytest.raises(GovernanceError):
        validate_claims(missing, b, "vault", details)
    for changes in (
        {"sub": "operator"},
        {"aud": "wrong"},
        {"act": {"sub": "candidate"}},
        {"authorization_details": []},
        {"exp": t + 100000},
        {"iat": True},
        {
            "authorization_details": [
                {"type": "vault:path_access", "path": "proof/data/other", "capabilities": ["read"]}
            ]
        },
    ):
        with pytest.raises(GovernanceError):
            validate_claims(valid | changes, b, "vault", details)


def test_lost_issuance_without_server_bound_never_auto_expires(tmp_path):
    from agent.governance.bootstrap import uncertain

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture")
    i = s.intent(c.candidate_id, "actor_oauth")
    uncertain(s, i, binding(), submitted_at=now() - timedelta(days=10))
    assert s.read().credentials[-1].safe_after is None
    assert s.read().credentials[-1].state == "uncertain"


def test_bootstrap_rejection_never_returns_token(tmp_path):
    from agent.governance.bootstrap import acquire

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture")

    class OAuth:
        async def client_credentials_details(self, *_args):
            return SimpleNamespace(access_token=SecretStr("canary"))

    class Verifier:
        async def verify_claims(self, token):
            raise ValueError("canary")

    with pytest.raises(GovernanceError, match="bootstrap_mismatch"):
        asyncio.run(
            acquire(
                s,
                c,
                binding(),
                OAuth(),
                Verifier(),
                "vault",
                [
                    {
                        "type": "vault:path_access",
                        "path": "proof/data/allowed",
                        "capabilities": ["read"],
                    }
                ],
                lambda: None,
            )
        )
    assert "canary" not in (s.root / "state.json").read_text()


def test_scope_is_limited_to_fixed_probes_or_exact_mint(tmp_path):
    from agent.governance.bootstrap import acquire, mint_details

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture")
    b = binding()
    assert mint_details(b)[0]["capabilities"] == ["update"]
    with pytest.raises(GovernanceError, match="bootstrap_mismatch"):
        asyncio.run(
            acquire(
                s,
                c,
                b,
                None,
                None,
                "vault",
                [
                    {
                        "type": "vault:path_access",
                        "path": "database/creds/role",
                        "capabilities": ["read"],
                    }
                ],
                lambda: None,
            )
        )
    assert not s.read().credentials
