"""Trusted Vault HTTP adapter and short-lived PostgreSQL credential lifecycle.

Lease handles and passwords stay private. Cleanup is attempted even when credential
parsing or the database operation fails. Cleanup requests require synchronous completion;
durable recovery records, when configured, are committed before completion is reported.
"""

import asyncio
import re
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, SecretStr

from .security import SecurityError


def validate_path(path: str) -> str:
    """Reject traversal, query syntax, or unsupported characters in a relative Vault path."""
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
        self,
        address: str,
        namespace: str,
        http: httpx.AsyncClient,
        *,
        operation_observer=None,
        credential_lifecycle=None,
        credential_guard=None,
    ):
        """Bind the provider address, namespace, HTTP client, and optional private
        observer.
        """
        url = urlparse(address)
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise SecurityError("vault_https_required")
        self.address, self.namespace, self.http = address.rstrip("/"), namespace, http
        self.operation_observer = operation_observer
        self.credential_lifecycle = credential_lifecycle
        self.credential_guard = credential_guard

    async def request(
        self, method: str, path: str, token: SecretStr | None = None, body: dict | None = None
    ) -> dict:
        """Make a validated Vault request with private token and optional correlation
        metadata.

        Persist operation bindings before observed effects, limit response size, and
        map HTTP/parsing failures to safe codes without returning raw diagnostics.
        """
        validate_path(path)
        headers = {"X-Vault-Namespace": self.namespace} if self.namespace else {}
        if token:
            headers["X-Vault-Token"] = token.get_secret_value()
        observer = self.operation_observer
        binding = None
        phase = (
            "cleanup"
            if path in {"sys/leases/revoke", "auth/token/revoke-self", "auth/token/revoke-accessor"}
            else "credential"
        )
        lifecycle = self.credential_lifecycle
        operation_id = (
            lifecycle.item.operation_id
            if lifecycle
            and lifecycle.item
            and phase == "credential"
            and path == lifecycle.item.credential_path
            else None
        )
        if operation_id:
            headers["X-Correlation-Id"] = str(operation_id)
        if observer and observer.validation_id and observer.observation_id:
            try:
                binding = observer.begin_operation(
                    **({"operation_ref": operation_id} if operation_id else {}),
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
            # Last trusted admission check immediately before credential dispatch.
            # Cleanup remains permitted after containment so existing leases can drain.
            if phase == "credential" and self.credential_guard:
                self.credential_guard.check()
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
            if len(response.content) > 262144:
                raise ValueError("vault_response_size")
            data = response.json() if response.content else {}
            if not isinstance(data, dict):
                raise ValueError("invalid Vault response")
            if phase == "cleanup" and (
                response.status_code not in {200, 204}
                or data.get("warnings")
                or data.get("errors")
                or data.get("queued")
                or data.get("data")
                or "sync" in data
                and data["sync"] is not True
                or "lease_id" in data
                and data["lease_id"] != (body or {}).get("lease_id")
            ):
                raise SecurityError("cleanup_failed")
            if observer and binding:
                observer.finish_operation(
                    binding,
                    native_request_id=data.get("request_id"),
                    native_lease_id=data.get("lease_id"),
                )
                if phase != "cleanup" or lifecycle is None:
                    observer.record(
                        phase,
                        "revoked" if phase == "cleanup" else "completed",
                        operation_ref=binding.operation_ref,
                    )
            return data
        except (httpx.HTTPError, ValueError, TypeError):
            raise SecurityError("vault_request_failed") from None

    async def read(self, token: SecretStr, path: str) -> dict:
        """Fetch a relative Vault path using the caller’s explicitly supplied token."""
        return await self.request("GET", path, token)

    async def workload_login(self, mount: str, role: str, jwt: SecretStr) -> dict:
        """Acquire a prospectively owned service token; incomplete issuance remains uncertain.

        This optional native path requires a host guard, verified actor and explicitly
        enrolled exclusive login role. Ordinary delegated OBO remains unchanged.
        """
        from .recovery.workers import descriptor_scope
        from .response.providers.enrollment import native_begin, native_update

        guard = self.credential_guard
        if guard is None or not hasattr(guard.store, "transaction"):
            raise SecurityError("native_login_not_enrolled")
        store = guard.store
        mode = store.anchor().recovery_mode
        with store.recovery.effect() if mode == "configured" else store.effect() as owner:
            with descriptor_scope(owner.fd):
                item = native_begin(
                    store,
                    guard,
                    validate_path(mount),
                    validate_path(role),
                    self.address,
                    self.namespace,
                )
                native_update(store, item, "submitted")
                try:
                    from .response.providers.common import request

                    headers = {"X-Vault-Namespace": self.namespace} if self.namespace else {}
                    guard.check()
                    async with asyncio.timeout(10):
                        status, result, _ = await request(
                            self.http,
                            "POST",
                            f"{self.address}/v1/auth/{mount}/login",
                            headers=headers,
                            body={"role": role, "jwt": jwt.get_secret_value()},
                        )
                    if (
                        status in {401, 403}
                        and isinstance(result, dict)
                        and set(result) <= {"errors", "request_id"}
                    ):
                        native_update(store, item, "denied")
                        raise SecurityError("native_login_denied")
                    if not 200 <= status < 300 or not isinstance(result, dict):
                        raise SecurityError("native_login_uncertain")
                    native_update(
                        store,
                        item,
                        "bound",
                        auth=result.get("auth"),
                        origin=self.address,
                        namespace=self.namespace,
                    )
                    # Capture first: containment arriving during login must not hide a token.
                    guard.check()
                    return result
                except BaseException:
                    current = next(
                        a
                        for a in store.read().native_acquisitions
                        if a.acquisition_id == item.acquisition_id
                    )
                    if current.state not in {"bound", "denied"}:
                        native_update(store, item, "uncertain")
                    raise

    async def revoke(self, token: SecretStr, lease_id: str) -> None:
        """Wait for synchronous exact-lease revocation; never accept queued completion."""
        await self.request("PUT", "sys/leases/revoke", token, {"lease_id": lease_id, "sync": True})

    async def revoke_self(self, token):
        """Revoke only the captured native token, never another token or a role prefix."""
        await self.request("POST", "auth/token/revoke-self", token)

    @asynccontextmanager
    async def user_token(self, jwt, mount, role, *, operation_timeout, lifecycle):
        """Journal login intent, capture native custody, validate lifetime, and always clean up.

        A malformed login response may still contain an issued credential. Capture it before
        other parsing so rejection cannot abandon native authority. Cleanup survives containment.
        """
        import time

        lifecycle.start()
        token = None
        try:
            result = await self.request(
                "POST",
                f"auth/{validate_path(mount)}/login",
                body={"role": validate_path(role), "jwt": jwt.get_secret_value()},
            )
            auth = result.get("auth")
            if (
                not isinstance(auth, dict)
                or not isinstance(auth.get("client_token"), str)
                or not 0 < len(auth["client_token"]) <= 4096
            ):
                raise SecurityError("vault_token_invalid")
            token = SecretStr(auth["client_token"])
            issued_at = time.monotonic()
            # Persist usable cleanup authority before inspecting optional native metadata.
            lifecycle.acquired(token)
            if self.operation_observer:
                self.operation_observer.record("credential", "acquired")
            accessor, request_id = auth.get("accessor"), result.get("request_id")
            if any(
                value is not None and (not isinstance(value, str) or not 0 < len(value) <= 1024)
                for value in (accessor, request_id)
            ):
                raise SecurityError("vault_token_invalid")
            lifecycle.metadata(native_request_id=request_id, token_accessor=accessor)
            data = (await self.read(token, "auth/token/lookup-self")).get("data")
            if not isinstance(data, dict):
                raise SecurityError("vault_token_invalid")
            ttl, cap = data.get("ttl"), data.get("explicit_max_ttl")
            if (
                data.get("type") != "service"
                or data.get("period", 0) != 0
                or type(ttl) is not int
                or type(cap) is not int
                or not 0 < ttl <= cap <= 300
                or ttl - (time.monotonic() - issued_at) <= operation_timeout + 30
                or not isinstance(data.get("policies"), list)
                or not all(isinstance(policy, str) for policy in data["policies"])
                or "root" in data["policies"]
            ):
                raise SecurityError("vault_token_invalid")
            yield token
        except BaseException:
            if token is None:
                lifecycle.uncertain()
                if self.operation_observer:
                    self.operation_observer.fact("credential_uncertain")
            raise
        finally:
            if token is not None:
                pending_failed = False
                try:
                    lifecycle.pending()
                except Exception:
                    # A journal fault cannot abandon the already captured native token.
                    pending_failed = True
                worker = asyncio.create_task(self.revoke_self(token))
                deadline = asyncio.get_running_loop().time() + 10
                interrupted = False
                failed = False
                while not worker.done():
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        failed = True
                        worker.cancel()
                        remaining = 1
                    try:
                        await asyncio.wait_for(asyncio.shield(worker), remaining)
                    except asyncio.CancelledError:
                        if worker.done():
                            break
                        interrupted = True
                    except TimeoutError:
                        continue
                    except Exception:
                        break
                try:
                    if failed or worker.cancelled():
                        raise SecurityError("cleanup_failed")
                    worker.result()
                    if pending_failed:
                        raise SecurityError("cleanup_failed")
                    lifecycle.completed()
                except Exception:
                    lifecycle.uncertain("cleanup_unconfirmed")
                    if self.operation_observer:
                        self.operation_observer.fact("cleanup_failed")
                    raise SecurityError("cleanup_failed") from None
                if interrupted:
                    raise asyncio.CancelledError

    @asynccontextmanager
    async def credentials(
        self,
        token: SecretStr,
        path: str,
        *,
        revoke: Callable[[str], Awaitable[None]] | None = None,
        cleanup_timeout: float = 30,
        cleanup_drain_timeout: float = 5,
    ):
        """Yield parsed short-lived credentials and arrange bounded cleanup on every exit.

        Capture the lease handle before parsing fields so malformed credentials can
        still be revoked. Shield cleanup from caller cancellation; report uncertain
        issuance or failed cleanup instead of claiming success.
        """
        from .setup.models import DatabaseTarget

        try:
            DatabaseTarget.from_path(path)
        except ValueError:
            raise SecurityError("vault_credential_path") from None
        lifecycle = self.credential_lifecycle
        if lifecycle:
            lifecycle.start()
        try:
            result = await self.read(token, path)
        except BaseException as error:
            if lifecycle:
                lifecycle.uncertain(
                    "provider_access_denied"
                    if isinstance(error, SecurityError)
                    and str(error) in {"vault_http_401", "vault_http_403"}
                    else "acquisition_uncertain"
                )
            if self.operation_observer and not (
                isinstance(error, SecurityError)
                and str(error) in {"vault_http_401", "vault_http_403"}
            ):
                self.operation_observer.fact("credential_uncertain")
            raise
        # Obtain revocation handle first: malformed credentials must still be cleaned up.
        lease_id = result.get("lease_id")
        if not isinstance(lease_id, str) or not lease_id:
            if lifecycle:
                lifecycle.uncertain()
            if self.operation_observer:
                self.operation_observer.fact("credential_uncertain")
            raise SecurityError("vault_lease_missing")
        if self.operation_observer:
            self.operation_observer.record("credential", "acquired")
        try:
            if lifecycle:
                lifecycle.acquired(lease_id, result.get("request_id"))
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
            # Keep the client and revocation token alive until the child actually stops.
            observer = self.operation_observer
            if observer:
                observer.fact("cleanup_pending")
            if lifecycle:
                lifecycle.pending()
            cleanup = asyncio.create_task(
                revoke(lease_id) if revoke else self.revoke(token, lease_id)
            )
            deadline = asyncio.get_running_loop().time() + cleanup_timeout
            # Cancellation is deferred until cleanup stops; abandoning its task would lose
            # the client/token needed for revocation while leaving issuance unresolved.
            interrupted = False
            timed_out = False
            while not cleanup.done():
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    if not timed_out:
                        timed_out = True
                        cleanup.cancel()
                        deadline = asyncio.get_running_loop().time() + cleanup_drain_timeout
                        continue
                    if observer:
                        observer.fact("cleanup_unknown")
                    # No further admission; retaining this frame retains private cleanup context.
                    # A timeout cannot kill a cancellation-resistant coroutine. Retain this
                    # frame and quarantine admission until it actually exits.
                    remaining = 1
                try:
                    await asyncio.wait_for(asyncio.shield(cleanup), remaining)
                except asyncio.CancelledError:
                    if cleanup.done():
                        break
                    interrupted = True
                except TimeoutError:
                    continue
                except Exception:
                    break
            if timed_out or cleanup.cancelled():
                if not cleanup.cancelled():
                    try:
                        cleanup.result()
                    except Exception:
                        pass
                if observer:
                    observer.fact("cleanup_failed")
                if lifecycle:
                    lifecycle.uncertain("cleanup_unconfirmed")
                raise SecurityError("cleanup_failed") from None
            try:
                cleanup.result()
            except Exception:
                if observer:
                    observer.fact("cleanup_failed")
                if lifecycle:
                    lifecycle.uncertain("cleanup_unconfirmed")
                raise SecurityError("cleanup_failed") from None
            if lifecycle:
                lifecycle.completed()
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
