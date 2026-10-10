"""Intent-before-send, handle-before-SQL, and cleanup despite persistence failure."""

import asyncio
import json

import httpx
import pytest
from pydantic import SecretStr

from agent.recovery.lifecycle import CredentialLifecycle
from agent.recovery.store import RecoveryError
from agent.security import SecurityError
from agent.vault import VaultClient


@pytest.mark.parametrize("failure", [None, "malformed", "read", "cancel", "cleanup"])
async def test_ordering_and_terminal_state(recovery_store, failure):
    calls = []

    async def handler(request):
        calls.append(request)
        item = recovery_store.read().attempts[-1]
        if request.method == "GET":
            assert item.state == "intent"
            assert request.headers["X-Correlation-Id"] == str(item.operation_id)
            data = {
                "lease_id": "database/creds/read/fixture",
                "lease_duration": 30,
                "data": {"username": "user", "password": "PRIVATE PASSWORD"},
            }
            if failure == "malformed":
                data["data"] = {}
            return httpx.Response(200, json=data)
        assert item.state == "cleanup_pending"
        return httpx.Response(500 if failure == "cleanup" else 204)

    with recovery_store.effect() as owner:
        lifecycle = CredentialLifecycle(recovery_store, owner)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            vault = VaultClient(
                "https://vault.example", "fixture", http, credential_lifecycle=lifecycle
            )
            try:
                async with vault.credentials(SecretStr("PRIVATE TOKEN"), "database/creds/read"):
                    assert recovery_store.read().attempts[-1].state == "acquired"
                    if failure == "read":
                        raise ValueError("PRIVATE SQL")
                    if failure == "cancel":
                        raise asyncio.CancelledError
            except (ValueError, asyncio.CancelledError, SecurityError):
                assert failure is not None
    item = recovery_store.read().attempts[-1]
    assert item.state == ("unresolved" if failure == "cleanup" else "resolved")
    assert len(calls) == 2
    assert json.loads(calls[-1].content)["sync"] is True
    assert "PRIVATE" not in (recovery_store.root / "state.json").read_text()


async def test_lost_response_stays_uncertain_without_retry(recovery_store):
    calls = []

    async def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("PRIVATE")

    with recovery_store.effect() as owner:
        lifecycle = CredentialLifecycle(recovery_store, owner)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            vault = VaultClient(
                "https://vault.example", "fixture", http, credential_lifecycle=lifecycle
            )
            with pytest.raises(SecurityError):
                async with vault.credentials(SecretStr("private"), "database/creds/read"):
                    pytest.fail("issued credentials without response")
    assert len(calls) == 1 and recovery_store.read().attempts[0].state == "unresolved"


async def test_handle_storage_failure_still_cleans_and_never_yields(recovery_store, monkeypatch):
    methods = []

    async def handler(request):
        methods.append(request.method)
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "lease_id": "database/creds/read/fixture",
                    "lease_duration": 30,
                    "data": {"username": "user", "password": "private"},
                },
            )
        return httpx.Response(204)

    original = recovery_store.update

    def fail(*args, **kwargs):
        if kwargs.get("state") == "acquired":
            recovery_store.failed = True
            raise RecoveryError()
        return original(*args, **kwargs)

    monkeypatch.setattr(recovery_store, "update", fail)
    with recovery_store.effect() as owner:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            vault = VaultClient(
                "https://vault.example",
                "fixture",
                http,
                credential_lifecycle=CredentialLifecycle(recovery_store, owner),
            )
            with pytest.raises(SecurityError):
                async with vault.credentials(SecretStr("private"), "database/creds/read"):
                    pytest.fail("SQL must not run")
    assert methods == ["GET", "PUT"]
