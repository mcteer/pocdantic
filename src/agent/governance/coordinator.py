"""Effect admission and containment with the existing response/recovery lock order.

Authority checks never modify response holds. A cancellation may stop local work while
an already dispatched provider request completes; its durable intent remains uncertain.
"""

import asyncio
from contextlib import ExitStack, contextmanager

from agent.recovery.workers import descriptor_scope

from .models import GovernanceError, require


def admit(response, recovery):
    """Reject every active hold, unsettled provider response and unresolved acquisition."""
    require(
        not response.holds
        and not response.root_holds
        and not getattr(response, "subject_holds", ()),
        "contained",
    )
    require(all(i.phase == "settled" for i in response.incidents), "contained")
    require(all(a.state == "resolved" for a in recovery.attempts), "issuance_unresolved")
    require(
        all(
            a.state in {"acknowledged", "denied", "failed", "reconciled"}
            for a in getattr(response, "provider_actions", ())
        ),
        "contained",
    )
    require(
        all(a.state in {"bound", "denied"} for a in getattr(response, "native_acquisitions", ())),
        "issuance_unresolved",
    )
    require(
        all(
            a.state in {"denied_no_issuance", "cleaned"}
            for a in getattr(response, "probe_acquisitions", ())
        ),
        "issuance_unresolved",
    )


class Coordinator:
    """Hold lifetime descriptors around privileged work, never short locks around I/O."""

    def __init__(self, governance, response, recovery):
        """Inject separately anchored stores; a missing existing installation is a block."""
        self.governance, self.response, self.recovery = governance, response, recovery
        self.active = False

    def check(self):
        """Recheck current containment before dispatch without granting new authority."""
        try:
            require(self.active, "workspace_busy")
            with self.response.transaction() as (_, response):
                # The response control lock precedes governance control. Recovery is
                # already exclusively owned, so read it outside its journal lock only
                # through its verified directory/snapshot reader.
                with self.recovery._directory() as directory:
                    recovery = self.recovery._read(directory)
                admit(response, recovery)
                self.governance.read()
        except GovernanceError:
            raise
        except Exception:
            raise GovernanceError("missing_authority") from None

    @contextmanager
    def ownership(self, *, allow_unresolved=False):
        """Acquire the specified nonblocking order and release all locks on contention."""
        try:
            with ExitStack() as stack:
                for context in (
                    self.recovery.workspace(),
                    self.response._lock("worker.lock"),
                    self.response._lock("probe.lock"),
                    self.governance.lock("effect.lock"),
                    self.recovery.effect(),
                ):
                    owner = stack.enter_context(context)
                    fd = owner.fd if hasattr(owner, "fd") else owner
                    stack.enter_context(descriptor_scope(fd))
                self.active = True
                try:
                    self.check()
                    state = self.governance.read()
                    if not allow_unresolved:
                        require(
                            not any(i.unresolved for i in state.credentials), "issuance_unresolved"
                        )
                        require(
                            not any(
                                a.state in {"prepared", "submitted", "uncertain", "conflict"}
                                for a in state.registrations
                            ),
                            "creation_uncertain",
                        )
                    yield self
                finally:
                    self.active = False
        except GovernanceError:
            raise
        except Exception as error:
            raise GovernanceError(
                "workspace_busy"
                if str(error) in {"recovery_busy", "response_busy"}
                else "missing_authority"
            ) from None


async def guarded(operation, check, *, timeout=120):
    """Watch holds every quarter-second and drain cancellation within the overall bound."""
    require(0 < timeout <= 120)
    check()
    task = asyncio.create_task(operation())
    try:
        async with asyncio.timeout(timeout):
            while not task.done():
                await asyncio.wait({task}, timeout=0.25)
                check()
            result = await task
            check()
            return result
    except TimeoutError:
        raise GovernanceError("effect_uncertain") from None
    finally:
        if not task.done():
            task.cancel()
            # Provider adapters obey cancellation. Process workers impose the hard
            # deadline on uncooperative provider libraries, retaining intent on exit.
            await asyncio.gather(task, return_exceptions=True)


def contained_change(governance, response, recovery, operation, *, revision=None):
    """Serialize final authority decisions with hold ingestion using the shared lock order.

    Only local bounded reads/transforms occur here. A hold already durably accepted wins
    before governance's commit; a hold accepted afterward fences subsequent operations.
    """
    with response.transaction() as (_fd, state):
        admit(state, recovery.read())
        return governance.change(operation, revision=revision)


def commit_checked(store, check, operation, *, revision=None):
    """Use an owning coordinator's atomic containment commit, or an explicit fixture check."""
    owner = getattr(check, "__self__", None)
    if isinstance(owner, Coordinator):
        require(owner.active, "workspace_busy")
        return contained_change(store, owner.response, owner.recovery, operation, revision=revision)
    check()
    return store.change(operation, revision=revision)
