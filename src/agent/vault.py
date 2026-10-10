import asyncio
import re
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, SecretStr

from .security import SecurityError


def validate_path(path: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", path):
        raise SecurityError("vault_path_invalid")
    return path


class Lease(BaseModel):
    lease_id: str = Field(repr=False)
    lease_duration: int = Field(gt=0)
    username: SecretStr = Field(repr=False)
    password: SecretStr = Field(repr=False)


class VaultClient:
    def __init__(
        self, address: str, namespace: str, http: httpx.AsyncClient, *, operation_observer=None
    ):
        url = urlparse(address)
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise SecurityError("vault_https_required")
        self.address, self.namespace, self.http = address.rstrip("/"), namespace, http
        self.operation_observer = operation_observer

    async def request(
        self, method: str, path: str, token: SecretStr | None = None, body: dict | None = None
    ) -> dict:
        validate_path(path)
        headers = {"X-Vault-Namespace": self.namespace} if self.namespace else {}
        if token:
            headers["X-Vault-Token"] = token.get_secret_value()
        observer = self.operation_observer
        binding = None
        phase = "cleanup" if path == "sys/leases/revoke" else "credential"
        if observer and observer.validation_id and observer.observation_id:
            try:
                binding = observer.begin_operation(
                    validation_id=observer.validation_id,
                    observation_id=observer.observation_id,
                    phase=phase,
                    source_kind="vault",
                    source_instance=self.address,
                    expected_outcome=observer.expected_outcome
                    if phase == "credential"
                    else "success",
                    native_lease_id=body.get("lease_id") if phase == "cleanup" and body else None,
                )
                headers["X-Correlation-Id"] = str(binding.operation_ref)
            except Exception:
                if phase != "cleanup":
                    raise SecurityError("storage_error") from None
        try:
            response = await self.http.request(
                method, f"{self.address}/v1/{path}", headers=headers, json=body
            )
            if response.status_code >= 300:
                if observer and binding:
                    observer.record(
                        phase,
                        "denied" if response.status_code in {401, 403} else "failed",
                        operation_ref=binding.operation_ref,
                    )
                    observer.finish_operation(binding)
                raise SecurityError(f"vault_http_{response.status_code}")
            data = response.json() if response.content else {}
            if observer and binding:
                observer.finish_operation(
                    binding,
                    native_request_id=data.get("request_id"),
                    native_lease_id=data.get("lease_id"),
                )
                observer.record(
                    phase,
                    "revoked" if phase == "cleanup" else "completed",
                    operation_ref=binding.operation_ref,
                )
            return data
        except (httpx.HTTPError, ValueError, TypeError):
            raise SecurityError("vault_request_failed") from None

    async def read(self, token: SecretStr, path: str) -> dict:
        return await self.request("GET", path, token)

    async def workload_login(self, mount: str, role: str, jwt: SecretStr) -> dict:
        """Private result: caller must never forward auth client_token to model/telemetry."""
        return await self.request(
            "POST",
            f"auth/{validate_path(mount)}/login",
            body={"role": role, "jwt": jwt.get_secret_value()},
        )

    async def revoke(self, token: SecretStr, lease_id: str) -> None:
        await self.request("PUT", "sys/leases/revoke", token, {"lease_id": lease_id})

    @asynccontextmanager
    async def credentials(
        self,
        token: SecretStr,
        path: str,
        *,
        revoke: Callable[[str], Awaitable[None]] | None = None,
        cleanup_timeout: float = 30,
    ):
        if not path.startswith("database/creds/"):
            raise SecurityError("vault_credential_path")
        result = await self.read(token, path)
        # Obtain revocation handle first: malformed credentials must still be cleaned up.
        lease_id = result.get("lease_id")
        if not isinstance(lease_id, str) or not lease_id:
            raise SecurityError("vault_lease_missing")
        try:
            try:
                lease = Lease(
                    lease_id=lease_id,
                    lease_duration=result["lease_duration"],
                    username=result["data"]["username"],
                    password=result["data"]["password"],
                )
            except (ValueError, KeyError, TypeError):
                raise SecurityError("vault_lease_invalid") from None
            yield lease
        finally:
            # Cancellation cannot drop cleanup; HTTP client remains open until completion.
            cleanup = asyncio.create_task(
                revoke(lease_id) if revoke else self.revoke(token, lease_id)
            )
            deadline = asyncio.get_running_loop().time() + cleanup_timeout
            interrupted = False
            while not cleanup.done():
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    cleanup.cancel()
                    raise SecurityError("cleanup_failed")
                try:
                    await asyncio.wait_for(asyncio.shield(cleanup), remaining)
                except asyncio.CancelledError:
                    interrupted = True
                    # Repeated cancellation cannot cancel the separate cleanup task.
                except TimeoutError:
                    cleanup.cancel()
                    raise SecurityError("cleanup_failed") from None
            cleanup.result()
            if interrupted:
                raise asyncio.CancelledError


async def read_postgres(
    lease: Lease,
    *,
    host: str,
    port: int,
    database: str,
    record_id: int,
    sslrootcert: str | None = None,
    username_suffix: str = "",
) -> list[dict]:
    """Only a fixed parameterized query; database role must also enforce SELECT-only grants."""
    import psycopg
    from psycopg.rows import dict_row

    try:
        async with await psycopg.AsyncConnection.connect(
            host=host,
            port=port,
            dbname=database,
            user=lease.username.get_secret_value() + username_suffix,
            password=lease.password.get_secret_value(),
            sslmode="verify-full",
            connect_timeout=5,
            row_factory=dict_row,
            options="-c statement_timeout=5000",
            **({"sslrootcert": sslrootcert} if sslrootcert else {}),
        ) as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT id, status FROM poc_records WHERE id = %s LIMIT 1", (record_id,)
                )
                return await cur.fetchall()
    except psycopg.Error:
        raise SecurityError("database_request_failed") from None
