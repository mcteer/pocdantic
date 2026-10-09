import httpx
import pytest
from pydantic import SecretStr

from pocdantic.oauth import OAuthClient, OAuthConfig
from pocdantic.security import SecurityError
from pocdantic.vault import VaultClient


async def test_oauth_exchange_is_actor_bound_and_exact_rar():
    requests = []

    def handle(req):
        requests.append(req)
        return httpx.Response(
            200, json={"access_token": "private", "token_type": "Bearer", "expires_in": 60}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        cfg = OAuthConfig(
            token_endpoint="https://id.example/token",
            client_id="client",
            client_secret=SecretStr("private-client-credential"),
        )
        token = await OAuthClient(cfg, http).exchange(
            SecretStr("human"), SecretStr("actor"), "database/creds/readonly", "vault"
        )
        assert token.access_token.get_secret_value() == "private"
    body = requests[0].content.decode()
    assert "actor_token=actor" in body and "subject_token=human" in body
    assert "vault%3Apath_access" in body
    assert "private-client-credential" not in repr(cfg)


async def test_lease_revoked_on_execution_failure():
    calls = []

    def handle(req):
        calls.append(req.url.path)
        if req.method == "GET":
            return httpx.Response(
                200,
                json={
                    "lease_id": "database/creds/read/lease",
                    "lease_duration": 60,
                    "data": {"username": "user", "password": "password"},
                },
            )
        return httpx.Response(204)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        vault = VaultClient("https://vault.example", "", http)
        with pytest.raises(RuntimeError):
            async with vault.credentials(SecretStr("token"), "database/creds/read") as lease:
                assert "password" not in repr(lease)
                raise RuntimeError("query failed")
    assert calls == ["/v1/database/creds/read", "/v1/sys/leases/revoke"]


async def test_vault_never_echoes_secret_error_body():
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(403, text="token=secret"))
    ) as http:
        with pytest.raises(SecurityError) as caught:
            await VaultClient("https://vault.example", "", http).read(
                SecretStr("token"), "database/creds/read"
            )
        assert "secret" not in str(caught.value)


async def test_cleanup_failure_prevents_false_success():
    def handler(req):
        if req.method == "GET":
            return httpx.Response(
                200,
                json={
                    "lease_id": "database/creds/read/lease",
                    "lease_duration": 60,
                    "data": {"username": "private-user", "password": "private-password"},
                },
            )
        return httpx.Response(403, text="private-password")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(SecurityError, match="vault_http_403"):
            async with VaultClient("https://vault.example", "", http).credentials(
                SecretStr("private-token"), "database/creds/read"
            ):
                pass


async def test_malformed_lease_still_revoked():
    revoked = []

    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json={"lease_id": "lease", "lease_duration": 60, "data": {}})
        revoked.append(True)
        return httpx.Response(204)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(SecurityError, match="vault_lease_invalid"):
            async with VaultClient("https://vault.example", "", http).credentials(
                SecretStr("private-token"), "database/creds/read"
            ):
                pass
    assert revoked == [True]


@pytest.mark.parametrize(
    "path",
    [
        "database/creds/*",
        "database/../sys",
        "/sys/mounts",
        "https://evil.example",
        "database%2fcreds",
    ],
)
async def test_path_injection_never_calls_vault(path):
    called = []
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: called.append(True))
    ) as http:
        with pytest.raises(SecurityError):
            await VaultClient("https://vault.example", "", http).read(SecretStr("private"), path)
    assert called == []


@pytest.mark.parametrize("suffix", ["", ".synthetic_project"])
async def test_database_connection_uses_leased_identity_and_verified_tls(monkeypatch, suffix):
    from unittest.mock import AsyncMock

    psycopg = pytest.importorskip("psycopg")
    from pocdantic.vault import Lease, read_postgres

    connect = AsyncMock(side_effect=psycopg.OperationalError("private server diagnostic"))
    monkeypatch.setattr(psycopg.AsyncConnection, "connect", connect)
    lease = Lease(
        lease_id="private-lease",
        lease_duration=60,
        username=SecretStr("leased_role"),
        password=SecretStr("leased_password"),
    )
    with pytest.raises(SecurityError, match="^database_request_failed$"):
        await read_postgres(
            lease,
            host="database.example",
            port=5432,
            database="postgres",
            record_id=1,
            sslrootcert="/trusted/ca.pem",
            username_suffix=suffix,
        )
    kwargs = connect.call_args.kwargs
    assert kwargs["user"] == "leased_role" + suffix
    assert kwargs["password"] == "leased_password"
    assert kwargs["sslmode"] == "verify-full"
    assert kwargs["sslrootcert"] == "/trusted/ca.pem"
