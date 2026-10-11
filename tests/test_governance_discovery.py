"""The HTTP observation flow authenticates independently and acknowledges durable intake."""

import asyncio

import httpx
from governance_support import installed, source

from agent.governance.models import now


def test_http_observation_replay_and_compression(tmp_path):
    from agent.governance.api import create_app

    s = installed(tmp_path)
    s.configure((source(),), 1)

    class Verifier:
        async def verify_claims(self, token):
            t = int(now().timestamp())
            return {
                "iss": "https://id.example",
                "sub": "relay",
                "aud": "discovery",
                "scope": "governance:observe",
                "iat": t,
                "exp": t + 60,
            }

    app = create_app(s, lambda _: Verifier())

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
        ) as http:
            value = {
                "id": "event",
                "object": "object",
                "kind": "unknown",
                "time": now().isoformat(),
            }
            headers = {"Authorization": "Bearer fake"}
            first = await http.post("/governance/native/fixture", json=value, headers=headers)
            second = await http.post("/governance/native/fixture", json=value, headers=headers)
            assert first.status_code == second.status_code == 202
            assert first.json()["candidate_id"] == second.json()["candidate_id"]
            assert second.json()["disposition"] == "duplicate"
            denied = await http.post(
                "/governance/native/fixture",
                json=value,
                headers=headers | {"Content-Encoding": "gzip"},
            )
            assert denied.status_code == 400
            assert "object" not in first.text

    asyncio.run(run())
    assert len(s.read().observations) == 1
    assert not s.read().credentials and not s.read().registrations
