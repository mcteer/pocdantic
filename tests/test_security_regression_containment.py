"""Root and definition containment cover real model/tool ingress and independent providers."""

import os
from uuid import uuid4

import pytest
from pydantic_ai.models.function import FunctionModel
from response_support import enrolled, principal, signal
from security_regression_support import dependencies

from agent.response.coordinator import Coordinator
from agent.response.guard import RootGuard
from agent.response.models import ResponseError
from agent.runtime import Runtime
from agent.schemas import Action, RequestEnvelope


@pytest.mark.parametrize("scope", ["root", "definition"])
async def test_root_and_definition_containment_across_access_paths(
    tmp_path, workspace_settings, scope
):
    """Durable checks deny held roots and tools; siblings survive only a root-scoped hold."""
    store = enrolled(workspace_settings, tmp_path)
    first, owner = store.register(uuid4(), uuid4(), principal(workspace_settings))
    sibling, other_owner = store.register(uuid4(), uuid4(), principal(workspace_settings))
    guard = RootGuard(store, first, owner)
    try:
        Coordinator(store).submit(
            signal(workspace_settings, root=first.root_run_id)
            if scope == "root"
            else signal(workspace_settings)
        )
        with pytest.raises(ResponseError):
            guard.check()
        deps = dependencies(principal(workspace_settings))
        from dataclasses import replace

        deps = replace(deps, root_guard=guard)
        for action in (
            Action(operation="ticket.read", resource="POC-1"),
            Action(operation="database.read", resource="poc-records"),
        ):
            with pytest.raises(ResponseError):
                deps.authorize(action)
        if scope == "root":
            store.check(sibling)
            fresh, fresh_owner = store.register(uuid4(), uuid4(), principal(workspace_settings))
            store.finish(fresh)
            os.close(fresh_owner)
        else:
            with pytest.raises(ResponseError):
                store.check(sibling)
            with pytest.raises(ResponseError):
                store.register(uuid4(), uuid4(), principal(workspace_settings))
            called = []

            def forbidden(messages, info):
                """No held definition may dispatch a model through either runtime profile."""
                called.append(1)
                pytest.fail("contained model")

            runtime = Runtime(
                workspace_settings, model=FunctionModel(forbidden), response_store=store
            )
            for profile in ("parent", "ticket-reader"):
                result = await runtime.run(
                    RequestEnvelope(task="Read POC-1", profile=profile),
                    principal(workspace_settings),
                )
                assert result.error_code == "contained"
            assert called == []
        # Local containment does not manufacture external JWT/lease/session revocation.
        from test_provider_database_proof import Session

        session = Session("isolated")
        assert await (await session.execute("SELECT 1")).fetchone() == (1,)
    finally:
        store.finish(first)
        store.finish(sibling)
        os.close(owner)
        os.close(other_owner)
    # Separate real release regression proves old roots remain denied after fresh-root recovery.
    from test_provider_recovery import (
        test_release_needs_complete_hold_set_and_admits_only_fresh_roots,
    )

    recovery_project = tmp_path / "recovery-control"
    recovery_project.mkdir()
    test_release_needs_complete_hold_set_and_admits_only_fresh_roots(
        recovery_project, workspace_settings
    )
