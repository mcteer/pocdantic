"""Lease revocation does not imply JWT invalidation or server session termination."""

import pytest
from test_broker import chain as chain
from test_provider_database_proof import Failure, Session

from agent.response.providers.proof import DatabaseProbe
from agent.security import SecurityError


@pytest.mark.parametrize("healthy,cleanup_ok", [(True, True), (False, True), (True, False)])
async def test_revocation_paths_remain_independent(chain, healthy, cleanup_ok):
    """Join actual cleanup and database proof while retaining usable JWT/session outcomes."""
    state, factory = chain
    broker = factory()
    original_token = broker.subject_token.get_secret_value()
    if not cleanup_ok:
        state["revoke_status"] = 503
    if cleanup_ok:
        assert await broker(1)
    else:
        with pytest.raises(SecurityError):
            await broker(1)
    assert [r.method for r in state["vault"]] == ["GET", "PUT"]
    denied = False

    async def connect(parameters):
        """Reject only old passwords after cleanup; the existing held session stays usable."""
        if denied and parameters["password"] == "old":
            raise Failure("28P01")
        if denied and parameters["user"] == "healthy" and not healthy:
            raise Failure(None)
        return Session(parameters["user"])

    parameters = {
        "host": "db.example",
        "port": "5432",
        "dbname": "fixture",
        "user": "isolated",
        "password": "old",
    }
    probe = DatabaseProbe(
        parameters, parameters | {"user": "healthy", "password": "peer"}, connect=connect
    )
    try:
        assert await probe.prepare()
        denied = True
        if not healthy:
            probe.healthy.terminated = True
        outcomes, peer = await probe.observe(replacement=parameters | {"password": "new"})
        assert peer == healthy
        assert outcomes["session"] != "proven"
        assert outcomes["fresh"] == ("proven" if healthy else "inconclusive")
        # Reusing the actual still-valid signed chain yields another independent issuance.
        assert broker.subject_token.get_secret_value() == original_token
        state["revoke_status"] = 204
        if cleanup_ok:
            assert await broker(1)
            assert len([r for r in state["vault"] if r.method == "GET"]) == 2
        else:
            from agent.recovery.store import RecoveryError

            with pytest.raises(RecoveryError, match="cleanup_unconfirmed"):
                await broker(1)
            assert len([r for r in state["vault"] if r.method == "GET"]) == 1
    finally:
        await probe.close()
