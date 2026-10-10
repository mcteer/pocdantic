"""Bounded read-only observations, independent of authorization and credential recovery.

Targets come only from trusted settings. No tokens, SQL, acquisitions, or provider
mutations are sent. Production network workers run in killable subprocesses so canceled
DNS/transport work cannot accumulate; injected transports support deterministic tests.
"""

import asyncio
import json
import sys
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
from pydantic import Field, computed_field, model_validator

from agent.recovery.models import REASONS, Contract, now
from agent.recovery.store import RecoveryError


class DiagnosticCheck(Contract):
    check_id: Literal[
        "configuration", "identity", "vault", "database", "authorization", "sign_in", "recovery"
    ]
    category: Literal[
        "configuration", "reachability", "timeout", "authorization", "sign_in", "recovery"
    ]
    state: Literal["observed", "failed", "unavailable", "inconclusive"]
    reason_code: str | None = None
    next_action: str | None = None
    checked_at: datetime = Field(default_factory=now)

    @model_validator(mode="after")
    def mapping(self):
        """Reject arbitrary provider text and unsupported reason/action combinations."""
        if self.reason_code:
            if self.reason_code not in REASONS or self.next_action != REASONS[self.reason_code][1]:
                raise ValueError("invalid_request")
        elif self.next_action is not None:
            raise ValueError("invalid_request")
        return self


class DiagnosticReport(Contract):
    report_id: UUID = Field(default_factory=uuid4)
    started_at: datetime
    finished_at: datetime
    checks: tuple[DiagnosticCheck, ...] = Field(max_length=8)

    @model_validator(mode="after")
    def unique(self):
        """Keep check IDs unique and the report time window ordered."""
        if (
            len({c.check_id for c in self.checks}) != len(self.checks)
            or self.finished_at < self.started_at
        ):
            raise ValueError("invalid_request")
        return self

    @computed_field
    @property
    def stale(self) -> bool:
        """Label observations older than sixty seconds; they never serve as admission tokens."""
        return (now() - self.finished_at).total_seconds() > 60


def check_value(key, category, state, reason=None):
    """Build one closed diagnostic projection without a provider message or target URL."""
    return DiagnosticCheck(
        check_id=key,
        category=category,
        state=state,
        reason_code=reason,
        next_action=REASONS[reason][1] if reason else None,
    )


async def http_observation(url, transport=None):
    """Read at most 64 KiB from a fixed public HTTPS endpoint, with no redirects or ambient auth."""
    p = urlsplit(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.query or p.fragment:
        return "configuration_missing"
    try:
        async with httpx.AsyncClient(
            timeout=10, follow_redirects=False, trust_env=False, transport=transport
        ) as http:
            async with http.stream("GET", url) as response:
                raw = bytearray()
                async for part in response.aiter_bytes():
                    raw.extend(part)
                    if len(raw) > 65536:
                        return "inconclusive"
                if response.status_code in {401, 403}:
                    return "provider_access_denied"
                if response.status_code != 200:
                    return "inconclusive"
                data = json.loads(raw)
                if not isinstance(data, dict):
                    return "inconclusive"
                if p.path.endswith("/sys/seal-status"):
                    return "observed" if data.get("sealed") is False else "inconclusive"
                return "observed" if isinstance(data.get("issuer"), str) else "inconclusive"
    except httpx.TimeoutException:
        return "diagnostic_timeout"
    except httpx.HTTPError:
        return "dependency_unreachable"
    except (ValueError, TypeError):
        return "inconclusive"


async def tcp_observation(host, port):
    """Open and close one configured TCP transport without authenticating or sending data."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
        writer.close()
        await writer.wait_closed()
        return "observed"
    except TimeoutError:
        return "diagnostic_timeout"
    except OSError:
        return "dependency_unreachable"


class Diagnostics:
    def __init__(
        self, settings, recovery, *, transport=None, tcp=None, check_timeout=10, total_timeout=30
    ):
        """Own one active diagnostic worker and the latest bounded in-memory report."""
        self.settings, self.recovery = settings, recovery
        self.transport, self.tcp = transport, tcp
        self.check_timeout = min(check_timeout, 10)
        self.total_timeout = min(total_timeout, 30)
        self.worker = None
        self.latest = None

    @property
    def active(self):
        """Keep the slot occupied while canceled or overdue work is still draining."""
        return self.worker is not None and not self.worker.done()

    async def _process(self, kind, *arguments):
        """Run a trusted isolated network worker and kill/drain it before releasing ownership."""
        from agent.recovery.workers import network_process

        async with network_process(__name__, kind, *arguments) as process:
            raw, _ = await process.communicate()
            value = (
                raw.decode().strip()
                if len(raw) <= 128 and process.returncode == 0
                else "inconclusive"
            )
            return (
                value
                if value
                in {
                    "observed",
                    "configuration_missing",
                    "provider_access_denied",
                    "inconclusive",
                    "diagnostic_timeout",
                    "dependency_unreachable",
                }
                else "inconclusive"
            )

    async def _http(self, url):
        """Use a controlled test transport or the production process boundary."""
        return (
            await http_observation(url, self.transport)
            if self.transport is not None
            else await self._process("http", url)
        )

    async def _tcp(self, host, port):
        """Use the injected no-auth transport check or an isolated production worker."""
        if self.tcp:
            await self.tcp(host, port)
            return "observed"
        return await self._process("tcp", host, port)

    async def _bounded(self, operation):
        """Apply a per-check deadline and retain canceled child ownership through termination."""
        task = asyncio.create_task(operation)
        try:
            done, _ = await asyncio.wait({task}, timeout=self.check_timeout)
            if not done:
                return "diagnostic_timeout"
            return task.result()
        except (TimeoutError, httpx.TimeoutException):
            return "diagnostic_timeout"
        except (OSError, httpx.HTTPError):
            return "dependency_unreachable"
        except Exception:
            return "inconclusive"
        finally:
            if not task.done():
                task.cancel()
                while not task.done():
                    try:
                        await asyncio.shield(task)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break

    async def _collect(self, checks, *, authentication, last_failure):
        """Collect fixed local and network facts sequentially without acquiring user authority."""
        s = self.settings
        missing = bool(
            s.database_host
            and not all((s.database_name, s.vault_addr, s.vault_audience, s.oauth_audience))
        )
        checks.append(
            check_value(
                "configuration",
                "configuration",
                "failed" if missing else "observed",
                "configuration_missing" if missing else None,
            )
        )
        checks.append(
            check_value(
                "sign_in",
                "sign_in",
                "observed" if authentication else "failed",
                None if authentication else "sign_in_required",
            )
        )
        view = self.recovery.status(authentication=authentication)
        checks.append(
            check_value(
                "recovery",
                "recovery",
                "failed" if view.recovery not in {"clear", "not_configured"} else "observed",
                view.reason_code,
            )
        )
        if last_failure == "provider_access_denied":
            checks.append(
                check_value("authorization", "authorization", "failed", "provider_access_denied")
            )
        identity = s.oauth_discovery_url or (
            s.verify_tenant_url + "/v1.0/endpoint/default/.well-known/openid-configuration"
            if s.verify_tenant_url
            else None
        )
        jobs = (
            ("identity", self._http, (identity,)),
            ("vault", self._http, ((s.vault_addr or "") + "/v1/sys/seal-status",)),
            ("database", self._tcp, (s.database_host, s.database_port)),
        )
        for key, operation, arguments in jobs:
            absent = not {"identity": identity, "vault": s.vault_addr, "database": s.database_host}[
                key
            ]
            if missing or absent:
                checks.append(
                    check_value(key, "configuration", "unavailable", "configuration_missing")
                )
                continue
            observed = await self._bounded(operation(*arguments))
            category = {
                "configuration_missing": "configuration",
                "diagnostic_timeout": "timeout",
                "provider_access_denied": "authorization",
            }.get(observed, "reachability")
            checks.append(
                check_value(
                    key,
                    category,
                    "observed"
                    if observed == "observed"
                    else "inconclusive"
                    if observed == "inconclusive"
                    else "failed",
                    observed if observed in REASONS else None,
                )
            )

    async def check(self, *, authentication, last_failure=None):
        """Return by the total deadline; draining workers retain the diagnostic slot."""
        if self.active:
            raise RecoveryError("diagnostics_busy")
        started = now()
        checks = []
        self.worker = asyncio.create_task(
            self._collect(checks, authentication=authentication, last_failure=last_failure)
        )
        task = self.worker
        try:
            done, _ = await asyncio.wait({task}, timeout=self.total_timeout)
            if not done:
                task.cancel()
            else:
                task.result()
        except asyncio.CancelledError:
            task.cancel()
            raise
        keys = {c.check_id for c in checks}
        for key in ("configuration", "sign_in", "recovery", "identity", "vault", "database"):
            if key not in keys:
                checks.append(check_value(key, "timeout", "inconclusive", "diagnostic_timeout"))
        self.latest = DiagnosticReport(started_at=started, finished_at=now(), checks=tuple(checks))
        return self.latest

    async def shutdown(self):
        """Cancel and drain outstanding diagnostic work before the workspace process exits."""
        if self.active:
            self.worker.cancel()
            await asyncio.gather(self.worker, return_exceptions=True)


if __name__ == "__main__":
    # Only the parent chooses worker targets. Output is one closed result, never exception text.
    try:
        kind, *arguments = sys.argv[1:]
        operation = (
            http_observation(arguments[0])
            if kind == "http"
            else tcp_observation(arguments[0], int(arguments[1]))
        )
        print(asyncio.run(operation))
    except Exception:
        print("inconclusive")
