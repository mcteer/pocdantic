"""Owned Monty execution with explicit callback authority, budgets and bounded drain.

Worker cancellation does not revoke credentials: separately tracked host tasks retain
broker ownership until their shielded connection/credential cleanup has completed.
"""

import asyncio
import base64
import hashlib
import importlib.metadata
import threading
from dataclasses import dataclass, field

from pydantic import ValidationError

from agent.security import SecurityError

from . import available
from .models import (
    BoundaryObservation,
    QueryRequest,
    bounded_text,
    encoded,
    program_payload,
    result_rows,
)
from .sql import admit

_WORKER_SLOT = threading.Lock()


def worker_binary():
    """Resolve and verify the locked runtime's executable, ignoring PATH/MONTY_BIN."""
    if not available():
        raise SecurityError("sandbox_unavailable")
    dist = importlib.metadata.distribution("pydantic-monty-runtime")
    file = next((p for p in dist.files if str(p).endswith("/monty")), None)
    if not file or not file.hash or file.hash.mode != "sha256":
        raise SecurityError("sandbox_unavailable")
    path = dist.locate_file(file).resolve(strict=True)
    if path.stat().st_size != file.size or file.size > 64 * 1024 * 1024:
        raise SecurityError("sandbox_unavailable")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if base64.urlsafe_b64encode(digest.digest()).decode().rstrip("=") != file.hash.value:
        raise SecurityError("sandbox_unavailable")
    return str(path)


@dataclass(repr=False)
class SandboxExecution:
    """One private run. Only its trusted handler receives a validated ReadPlan."""

    handler: object
    guard: object
    code: str = ""
    submitted: bool = False
    exercised: bool = False
    completed: bool = False
    closed: bool = False
    failure: str | None = None
    attempted: int = 0
    admitted: int = 0
    reads: int = 0
    busy: bool = False
    queries: list = field(default_factory=list)
    observations: list = field(default_factory=list)
    tasks: set = field(default_factory=set)
    output_bytes: int = 0
    active_seconds: float = 30

    def check(self):
        """Reject resumed or caught-failure work and recheck trusted containment."""
        if self.closed or self.failure:
            raise SecurityError(self.failure or "sandbox_closed")
        self.guard()

    def observe(self, boundary, outcome, reason=None):
        """Record bounded closed metadata, without copying any source or parameters."""
        if len(self.observations) < 32:
            self.observations.append(
                BoundaryObservation(boundary=boundary, outcome=outcome, reason=reason).model_dump()
            )

    async def query(self, *args, **kwargs):
        """Reserve a sequential slot before suspension; register host custody separately."""
        self.check()
        if self.busy or self.attempted >= 3:
            self.failure = "sandbox_calls_limit"
            self.observe("query_policy", "denied", self.failure)
            raise SecurityError(self.failure)
        self.busy = True
        self.attempted += 1
        if len(args) == 2 and not kwargs:
            sql, parameters = args
        elif len(args) == 1 and set(kwargs) == {"parameters"}:
            sql, parameters = args[0], kwargs["parameters"]
        elif not args and set(kwargs) == {"sql", "parameters"}:
            sql, parameters = kwargs["sql"], kwargs["parameters"]
        else:
            self.busy = False
            self.failure = "sandbox_query_denied"
            self.observe("query_policy", "denied", self.failure)
            raise SecurityError(self.failure)
        task = asyncio.create_task(self._query(sql, parameters))
        self.tasks.add(task)
        try:
            return await asyncio.shield(task)
        finally:
            if task.done():
                self.tasks.discard(task)
            self.busy = False

    async def _query(self, sql, parameters):
        """Validate before dispatch; latch all failures even if generated code catches them."""
        try:
            self.check()
            request = QueryRequest(sql=sql, parameters=parameters)
            plan = await admit(request)
            self.check()
            self.admitted += 1
            self.queries.append(request.sql)
            self.observe("query_policy", "passed")
            result = await self.handler(plan)
            self.check()
            if (
                type(result) is not dict
                or set(result) != {"rows", "row_count", "truncated"}
                or type(result["truncated"]) is not bool
                or type(result["row_count"]) is not int
                or result["row_count"] != len(result["rows"])
                or len(encoded(result)) > 65536
            ):
                raise SecurityError("sandbox_result_invalid")
            result_rows(result["rows"], plan)
            self.reads += 1
            self.observe("database", "passed")
            return result
        except asyncio.CancelledError:
            self.failure = self.failure or "sandbox_cancelled"
            raise
        except (ValidationError, ValueError, TypeError):
            self.failure = "sandbox_query_denied"
            self.observe("query_policy", "denied", self.failure)
            raise SecurityError(self.failure) from None
        except SecurityError as error:
            known = {
                "sandbox_query_denied",
                "sandbox_result_invalid",
                "sandbox_rows_limit",
                "sandbox_database_unavailable",
                "sandbox_calls_limit",
                "identity_expired",
                "policy_denied",
                "contained",
                "database_request_failed",
                "database_subject_invalid",
            }
            from agent.recovery.models import REASONS

            code = str(error)
            self.failure = code if code in known or code in REASONS else "sandbox_query_failed"
            boundary = (
                "database"
                if self.failure == "database_request_failed"
                else (
                    "identity"
                    if self.failure in {"identity_expired", "database_subject_invalid"}
                    else ("cleanup" if self.failure in REASONS else "query_policy")
                )
            )
            self.observe(
                boundary,
                "failed" if boundary in {"database", "cleanup"} else "denied",
                self.failure,
            )
            raise
        except Exception:
            self.failure = "sandbox_query_failed"
            self.observe("database", "failed", self.failure)
            raise SecurityError(self.failure) from None

    def printed(self, *args):
        """Discard raw print content after checking its combined output budget."""
        text = args[-1]
        if type(text) is not str:
            self.failure = "sandbox_output_limit"
            raise SecurityError(self.failure)
        self.output_bytes += len(text.encode())
        if self.output_bytes > 16384:
            self.failure = "sandbox_output_limit"
            raise SecurityError(self.failure)

    async def drain(self):
        """Close admission first, then cancel/drain independently owned host callbacks."""
        self.closed = True
        pending = list(self.tasks)
        for task in pending:
            if not task.done():
                task.cancel()
        if pending:
            cleanup = asyncio.gather(*pending, return_exceptions=True)
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    # Repeated cancellation cannot release another task's credential custody.
                    continue
        self.tasks.clear()

    async def execute(self, code):
        """Run one feed and return bounded finite JSON; terminal sessions never resume."""
        self.check()
        if self.submitted:
            self.failure = "sandbox_replay_denied"
            raise SecurityError(self.failure)
        self.submitted = True
        leased_slot = False
        try:
            if not _WORKER_SLOT.acquire(blocking=False):
                raise SecurityError("sandbox_busy")
            leased_slot = True
            self.code = bounded_text(code, 16384)
            binary = worker_binary()
            from pydantic_monty import AsyncMonty

            limits = {
                "max_memory": 33554432,
                "max_feed_duration_secs": 2,
                "max_turn_duration_secs": 2,
                "max_recursion_depth": 64,
                "max_suspensions": 16,
                "max_total_sleep_secs": 0,
            }
            async with asyncio.timeout(self.active_seconds):
                async with AsyncMonty(
                    binary_path=binary,
                    max_processes=1,
                    checkout_timeout=1,
                    request_timeout=5,
                    max_checkouts_per_worker=1,
                    feed_duration_limit_grace=0.5,
                    turn_duration_limit_grace=0.5,
                ) as pool:
                    async with pool.checkout(
                        limits=limits, os_policy={"sleep": "call_host"}
                    ) as session:
                        self.exercised = True
                        result = await session.feed_run(
                            code,
                            external_lookup={"query_database": self.query},
                            print_callback=self.printed,
                        )
            self.check()
            payload = program_payload(result)
            if len(payload) + self.output_bytes > 16384:
                raise SecurityError("sandbox_output_limit")
            self.completed = True
            self.observe("sandbox", "passed")
            return result
        except asyncio.CancelledError:
            self.failure = self.failure or "sandbox_cancelled"
            self.observe("sandbox", "cancelled", self.failure)
            raise
        except SecurityError as error:
            self.failure = self.failure or str(error)
            self.observe("sandbox", "failed", self.failure)
            raise SecurityError(self.failure) from None
        except Exception as error:
            kind = type(error).__name__
            if hasattr(error, "exception"):
                kind = type(error.exception()).__name__
            reason = {
                "MemoryError": "sandbox_memory_limit",
                "TimeoutError": "sandbox_compute_limit",
                "RecursionError": "sandbox_recursion_limit",
                "MontySyntaxError": "sandbox_syntax_invalid",
            }.get(kind, "sandbox_execution_failed")
            if type(error) is TimeoutError:
                reason = "sandbox_wall_limit"
            self.failure = self.failure or reason
            self.observe("sandbox", "denied", self.failure)
            raise SecurityError(self.failure) from None
        finally:
            try:
                await self.drain()
            finally:
                if leased_slot:
                    _WORKER_SLOT.release()

    def inspection(self):
        """Session-owned raw source plus metadata; no parameters, native handles or rows."""
        return {
            "code": self.code,
            "queries": list(self.queries),
            "completed": self.completed,
            "attempted": self.attempted,
            "admitted": self.admitted,
            "reads": self.reads,
            "observations": list(self.observations),
            "error_code": self.failure,
            "engine": "monty" if self.exercised else "not_exercised",
        }
