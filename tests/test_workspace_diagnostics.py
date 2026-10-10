"""Read-only fixed-target diagnostics distinguish observations from authority and proof."""

import asyncio

import httpx
import pytest

from agent.recovery.store import RecoveryError
from agent.workspace.diagnostics import Diagnostics


async def test_fixed_checks_are_unauthenticated_and_bounded(recovery_settings, recovery_store):
    calls = []

    async def handler(request):
        calls.append(request)
        assert not any(k.lower() in {"authorization", "x-vault-token"} for k in request.headers)
        return httpx.Response(
            200,
            json={"sealed": False}
            if "seal-status" in request.url.path
            else {"issuer": "https://id.example"},
        )

    async def tcp(host, port):
        assert host == "database.example" and port == 5432

    diagnostics = Diagnostics(
        recovery_settings, recovery_store, transport=httpx.MockTransport(handler), tcp=tcp
    )
    report = await diagnostics.check(authentication=True)
    assert len(report.checks) <= 8
    assert {c.check_id for c in report.checks} >= {"configuration", "identity", "vault", "database"}
    assert next(c for c in report.checks if c.check_id == "database").state == "observed"
    assert [r.url.path for r in calls] == ["/discovery", "/v1/sys/seal-status"]
    assert all(r.method == "GET" and not r.content for r in calls)
    assert recovery_store.read().attempts == ()
    assert not report.stale


@pytest.mark.parametrize(
    "failure,category,reason",
    [
        ("refused", "reachability", "dependency_unreachable"),
        ("timeout", "timeout", "diagnostic_timeout"),
        ("authorization", "authorization", "provider_access_denied"),
    ],
)
async def test_classifies_facts_without_inventing_network_ban(
    recovery_settings, recovery_store, failure, category, reason
):
    async def handler(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("PRIVATE MESSAGE")
        if failure == "refused":
            raise httpx.ConnectError("PRIVATE MESSAGE")
        return httpx.Response(403, text="PRIVATE MESSAGE")

    async def tcp(*args):
        return None

    d = Diagnostics(
        recovery_settings, recovery_store, transport=httpx.MockTransport(handler), tcp=tcp
    )
    report = await d.check(authentication=False)
    assert any(c.category == category and c.reason_code == reason for c in report.checks)
    assert "PRIVATE" not in report.model_dump_json()
    assert "ban" not in report.model_dump_json()
    assert any(c.category == "sign_in" for c in report.checks)


async def test_deadline_and_slot_retained_until_stubborn_worker_stops(
    recovery_settings, recovery_store
):
    entered = asyncio.Event()
    release = asyncio.Event()

    async def stubborn(request):
        entered.set()
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                pass
        return httpx.Response(200, json={"issuer": "https://id.example"})

    d = Diagnostics(
        recovery_settings,
        recovery_store,
        transport=httpx.MockTransport(stubborn),
        check_timeout=0.01,
        total_timeout=0.04,
    )
    report = await asyncio.wait_for(d.check(authentication=False), 0.2)
    assert any(c.reason_code == "diagnostic_timeout" for c in report.checks)
    with pytest.raises(RecoveryError, match="diagnostics_busy"):
        await d.check(authentication=False)
    release.set()
    await asyncio.wait_for(d.shutdown(), 1)
    assert not d.active


async def test_missing_configuration_and_recovery_separate(recovery_settings, recovery_store):
    with recovery_store.effect() as owner:
        item = recovery_store.begin(owner)
        recovery_store.update(item.incident_id, 1, state="unresolved")
    d = Diagnostics(recovery_settings.model_copy(update={"database_name": None}), recovery_store)
    report = await d.check(authentication=False)
    assert any(c.category == "configuration" and c.state == "failed" for c in report.checks)
    assert any(c.category == "recovery" for c in report.checks)
    assert any(c.category == "sign_in" for c in report.checks)
