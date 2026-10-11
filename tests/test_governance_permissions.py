"""A 403 cannot identify a ceiling without exact signed delegation and native baselines."""

import pytest
from governance_support import binding


def test_ceiling_attribution_requires_all_controls():
    from agent.governance.permissions import ceiling_denial

    b = binding()
    details = [
        {
            "type": "vault:path_access",
            "path": b.paths["obo_beyond_ceiling"],
            "capabilities": ["read"],
        }
    ]
    claims = {
        "sub": "human",
        "act": {"iss": b.actor_issuer, "sub": b.actor_subject},
        "authorization_details": details,
    }
    assert ceiling_denial(
        403,
        claims,
        b,
        "human",
        details,
        baseline_status=200,
        healthy_status=200,
        metadata_current=True,
    )
    for changes in ({"baseline_status": 403}, {"healthy_status": 503}, {"metadata_current": False}):
        values = {"baseline_status": 200, "healthy_status": 200, "metadata_current": True} | changes
        assert not ceiling_denial(403, claims, b, "human", details, **values)
    assert not ceiling_denial(
        403,
        claims | {"authorization_details": []},
        b,
        "human",
        details,
        baseline_status=200,
        healthy_status=200,
        metadata_current=True,
    )
    assert not ceiling_denial(
        503,
        claims,
        b,
        "human",
        details,
        baseline_status=200,
        healthy_status=200,
        metadata_current=True,
    )


@pytest.mark.parametrize("human_baseline", [200, 403, 503])
def test_four_paths_require_actual_human_baseline_and_distinct_control(tmp_path, human_baseline):
    """Only a successful excessive human baseline supports ceiling-layer attribution."""
    import asyncio
    from types import SimpleNamespace

    import httpx
    from governance_support import FakeRegistry, binding, installed, source
    from pydantic import SecretStr

    from agent.governance.models import now
    from agent.governance.permissions import prove

    store = installed(tmp_path)
    store.configure((source(),), 1)
    item = store.case("fixture")
    b = binding()
    item = item.model_copy(
        update={
            "binding": b,
            "state": "registered",
            "registration_digest": "0" * 64,
            "registered_at": now(),
            "registration_id": "fixture",
        }
    )
    store.change(lambda j: j.model_copy(update={"candidates": (item,)}))
    from agent.governance.config import readiness

    item = item.model_copy(update={"readiness": asyncio.run(readiness(b, FakeRegistry()))})
    store.change(lambda j: j.model_copy(update={"candidates": (item,)}))
    claims = {}

    class OAuth:
        def __init__(self, subject):
            self.subject = subject

        async def client_credentials_details(self, details, audience):
            raw = f"fixture-{self.subject}-{len(claims)}"
            t = int(now().timestamp())
            claims[raw] = {
                "iss": b.actor_issuer,
                "sub": self.subject,
                "aud": audience,
                "iat": t,
                "exp": t + 60,
                "authorization_details": details,
            }
            return SimpleNamespace(access_token=SecretStr(raw))

        async def exchange_details(self, human, actor, details, audience):
            token = await self.client_credentials_details(details, audience)
            claims[token.access_token.get_secret_value()].update(
                sub=b.owner_subject, act={"iss": b.actor_issuer, "sub": b.actor_subject}
            )
            return token

    class Verifier:
        async def verify_claims(self, token):
            if token.get_secret_value() == "human":
                return {"iss": b.owner_issuer, "sub": b.owner_subject}
            return claims[token.get_secret_value()]

    def transport(request):
        raw = request.headers["X-Vault-Token"]
        if raw == "human":
            status = human_baseline
        elif claims[raw]["sub"] == "healthy":
            status = 200
        else:
            status = 403 if request.url.path.endswith(("excessive", "forbidden")) else 200
        return httpx.Response(status, json={"data": {"discarded-canary": "fixture-only"}})

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as http:
            return await prove(
                store,
                item,
                b,
                oauth=OAuth("candidate"),
                verifier=Verifier(),
                healthy_oauth=OAuth("healthy"),
                healthy_verifier=Verifier(),
                healthy_binding=b.model_copy(
                    update={
                        "actor_subject": "healthy",
                        "client": "healthy",
                        "healthy_client": "candidate",
                    }
                ),
                audience="vault",
                http=http,
                human=SecretStr("human"),
                human_verifier=Verifier(),
                registry=FakeRegistry(),
                check=lambda: None,
            )

    results = asyncio.run(exercise())
    assert set(results) == {"obo_allowed", "obo_beyond_ceiling", "direct_allowed", "direct_denied"}
    assert results["obo_beyond_ceiling"]["outcome"] == (
        "pass" if human_baseline == 200 else "inconclusive"
    )
    assert results["direct_allowed"]["outcome"] == "pass"
    assert results["direct_denied"]["outcome"] == "pass"
    assert "discarded-canary" not in (store.root / "state.json").read_text()
