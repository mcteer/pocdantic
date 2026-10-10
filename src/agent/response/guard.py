"""Trusted root ownership and cross-process containment checks around live execution.

Descendants share the root guard. Watchers need only the short control lock; inherited
OS descriptors keep lifetime ownership valid even when a parent process dies.
"""

import asyncio
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass

from agent.recovery.workers import descriptor_scope

from .models import ResponseError, RunBinding


@dataclass(repr=False)
class RootGuard:
    """One registered root, never authority supplied by a model or browser body."""

    store: object
    binding: RunBinding
    fd: int | None = None
    active: bool = True

    def check(self):
        """Recheck durable admission immediately before a trusted execution boundary."""
        if not self.active:
            raise ResponseError("contained")
        self.store.check(self.binding)

    def bind_actor(self, issuer, subject):
        """Capture a freshly verified workload actor before privileged acquisition."""
        self.check()
        self.store.bind_actor(self.binding, issuer, subject)

    def ownership(self):
        """Return immutable attribution for the acquisition intent, after a fresh guard."""
        self.check()
        return self.binding.ownership()


@asynccontextmanager
async def root_scope(store, request_id, root_id, principal, on_contained):
    """Register, watch and retain root ownership until awaited cleanup has drained."""
    binding, fd = store.register(request_id, root_id, principal)
    guard = RootGuard(store, binding, fd)
    task = asyncio.current_task()

    async def watch():
        """Request cancellation on a hold/storage failure without waiting for effects."""
        while True:
            await asyncio.sleep(0.25)
            try:
                guard.check()
            except ResponseError as error:
                if str(error) == "response_busy":
                    # A short control transaction is contention, not another root's hold.
                    # Effects still require their own fresh successful guard.
                    continue
                on_contained(root_id)
                task.cancel()
                return

    watcher = asyncio.create_task(watch())
    try:
        with descriptor_scope(fd):
            yield guard
    finally:
        watcher.cancel()
        await asyncio.gather(watcher, return_exceptions=True)
        guard.active = False
        try:
            store.finish(binding)
        finally:
            if fd is not None:
                os.close(fd)


class MemoryStore:
    """Explicit synthetic dependency: no files, network or provider acceptance claims."""

    def __init__(self, settings):
        """Own only fixture roots; production entry points never select this implicitly."""
        self.settings = settings
        self.runs = {}
        self.blocked = set()
        self.definition_held = False

    def register(self, request_id, root_id, principal):
        """Apply the same fresh-root semantics to synthetic execution."""
        if self.definition_held or root_id in self.runs:
            raise ResponseError("contained")
        run = RunBinding(
            root_run_id=root_id,
            request_id=request_id,
            generation=1,
            workload_definition=self.settings.workload_definition,
            issuer=principal.issuer,
            subject=principal.subject,
        )
        self.runs[root_id] = run
        return run, None

    def check(self, binding):
        """Reject fixture holds and ended roots without reading ambient local state."""
        if (
            self.definition_held
            or binding.root_run_id in self.blocked
            or self.runs.get(binding.root_run_id) is None
            or self.runs[binding.root_run_id].state != "active"
            or self.runs[binding.root_run_id].ownership() != binding.ownership()
        ):
            raise ResponseError("contained")

    def bind_actor(self, binding, issuer, subject):
        """Capture synthetic verified metadata without changing immutable ownership."""
        self.check(binding)
        updated = binding.model_copy(update={"actor_issuer": issuer, "actor_subject": subject})
        self.runs[binding.root_run_id] = updated

    def finish(self, binding):
        """Keep a terminal root in fixture memory so it cannot be registered again."""
        self.runs[binding.root_run_id] = self.runs[binding.root_run_id].model_copy(
            update={"state": "terminal"}
        )
