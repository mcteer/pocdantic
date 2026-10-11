"""A separately started relying process owns public keys, never the mint credential."""

import asyncio
import json
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from governance_support import binding, installed, source

from agent.governance.models import now
from agent.governance.relying import challenge

UDS_REQUEST = httpx.AsyncHTTPTransport.handle_async_request

SERVER = """
import asyncio, json, sys
from contextlib import asynccontextmanager
from pathlib import Path
import httpx, uvicorn
from agent.governance.store import GovernanceStore
from agent.governance.relying import create_app, private_socket
from agent.governance.verifier import Verifier
root = Path(sys.argv[1])
store = GovernanceStore(project=root, environment="0"*64)
public = json.loads((root / "public.json").read_text())
@asynccontextmanager
async def factory(trust):
    def transport(request):
        if str(request.url) == trust.discovery_url:
            return httpx.Response(200, json={"issuer": trust.issuer, "jwks_uri": trust.jwks_url})
        assert str(request.url) == trust.jwks_url
        return httpx.Response(200, json={"keys": [public]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(transport), trust_env=False) as http:
        yield Verifier(trust, http)
async def run():
    with store.lock("service.lock"):
        sock = private_socket(store)
        try:
            app = create_app(store, lambda: None, factory)
            server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False))
            await server.serve(sockets=[sock])
        finally:
            sock.close()
asyncio.run(run())
"""


@pytest.fixture
def private_project():
    """Use a short real path so macOS's Unix-socket length limit is respected."""
    base = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
    with tempfile.TemporaryDirectory(prefix="gov-", dir=base) as root:
        yield Path(root).resolve()


def test_separate_process_verifies_once_without_mint_credentials(private_project, monkeypatch):
    tmp_path = private_project
    """Real private IPC must record an independent proof and reject the reused nonce."""
    store = installed(tmp_path)
    store.configure((source(),), 1)
    candidate = store.case("fixture")
    b = binding()
    candidate = candidate.model_copy(
        update={
            "binding": b,
            "state": "registered",
            "registration_digest": "0" * 64,
            "registered_at": now(),
            "registration_id": "fixture-registration",
        }
    )
    store.change(lambda j: j.model_copy(update={"candidates": (candidate,)}))
    intent = store.intent(candidate.candidate_id, "svid")
    from agent.governance.bootstrap import update_intent

    update_intent(store, intent, state="submitted", submitted_at=now())
    envelope = challenge(store, candidate, intent)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public.update(kid="fixture", use="sig", alg="RS256")
    (tmp_path / "public.json").write_text(json.dumps(public))
    current = int(now().timestamp())
    raw = jwt.encode(
        {
            "iss": b.trust.issuer,
            "sub": b.trust.subject,
            "aud": b.trust.audience,
            "iat": current,
            "exp": current + 60,
            "vault": {"entity": {"id": b.entity_id}},
        },
        key,
        algorithm="RS256",
        headers={"kid": "fixture"},
    )
    process = subprocess.Popen(
        [sys.executable, "-c", SERVER, str(tmp_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
    )
    try:
        deadline = time.monotonic() + 5
        while not (store.root / "relying.sock").exists():
            assert process.poll() is None, process.stderr.read().decode()
            assert time.monotonic() < deadline
            time.sleep(0.02)
        assert (store.root / "relying.sock").stat().st_mode & 0o777 == 0o600
        transport = httpx.AsyncHTTPTransport(uds=str(store.root / "relying.sock"))

        async def only_private_socket(self, request):
            """Allow only this explicit test Unix socket; every other real HTTP stays denied."""
            assert self is transport and request.url.host == "relying"
            return await UDS_REQUEST(self, request)

        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", only_private_socket)

        async def exercise():
            async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
                value = {k: v for k, v in envelope.items()} | {"token": raw}
                first = await client.post("http://relying/verify", json=value)
                assert first.status_code == 200
                assert first.json()["result"] == "pass"
                assert raw not in first.text
                repeated = await client.post("http://relying/verify", json=value)
                assert repeated.status_code == 409

        asyncio.run(exercise())
        assert len(store.read().verifications) == 1
        assert store.read().verifications[0].expires_at == datetime.fromtimestamp(current + 60, UTC)
        assert raw not in (store.root / "state.json").read_text()
    finally:
        process.terminate()
        process.wait(timeout=5)
