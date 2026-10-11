"""One-use relying challenges bind the current candidate, intent and implementation."""

import asyncio

import pytest
from governance_support import binding, installed, source

from agent.governance.models import GovernanceError, now


def test_challenge_consumed_even_when_verification_fails(tmp_path):
    from agent.governance.relying import challenge, verify_request

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture")
    c = c.model_copy(
        update={
            "binding": binding(),
            "registration_id": "fixture",
            "state": "registered",
            "registration_digest": "0" * 64,
            "registered_at": now(),
        }
    )
    s.change(lambda j: j.model_copy(update={"candidates": (c,)}))
    intent = s.intent(c.candidate_id, "svid")
    from agent.governance.bootstrap import update_intent

    update_intent(s, intent, state="submitted", submitted_at=now())
    request = challenge(s, c, intent)

    class Verifier:
        async def check(self, raw):
            raise GovernanceError("identity_rejected")

    async def check():
        result = await verify_request(s, request | {"token": "canary"}, Verifier(), lambda: None)
        assert result["result"] == "fail"
        with pytest.raises(GovernanceError, match="challenge_invalid"):
            await verify_request(s, request | {"token": "canary"}, Verifier(), lambda: None)

    asyncio.run(check())
    assert s.read().challenges[0].consumed
    assert "canary" not in (s.root / "state.json").read_text()


@pytest.mark.parametrize("timing", ["during_verify", "before_commit"])
def test_hold_during_public_key_work_consumes_nonce_without_promoting_proof(tmp_path, timing):
    """A real durable response hold wins before the independent proof is committed."""
    from governance_support import anchors
    from response_support import signal

    from agent.governance.bootstrap import update_intent
    from agent.governance.coordinator import admit
    from agent.governance.relying import challenge, verify_request
    from agent.response.coordinator import Coordinator as ResponseCoordinator

    settings, store, response, recovery = anchors(tmp_path)
    store.configure((source(),), 1)
    item = store.case("fixture")
    b = binding()
    item = item.model_copy(
        update={
            "binding": b,
            "registration_id": "fixture",
            "state": "registered",
            "registration_digest": "0" * 64,
            "registered_at": now(),
        }
    )
    store.change(lambda j: j.model_copy(update={"candidates": (item,)}))
    intent = store.intent(item.candidate_id, "svid")
    update_intent(store, intent, state="submitted", submitted_at=now())
    envelope = challenge(store, item, intent)

    class Verifier:
        trust = b.trust

        async def check(self, _raw):
            if timing == "during_verify":
                ResponseCoordinator(response).submit(signal(settings))
            return {"vault": {"entity": {"id": b.entity_id}}, "exp": int(now().timestamp()) + 60}

    def check():
        admit(response.read(), recovery.read())

    def commit_change(operation):
        """Insert a durable hold in the final-check gap, then use the atomic commit helper."""
        from agent.governance.coordinator import contained_change

        if timing == "before_commit":
            ResponseCoordinator(response).submit(signal(settings))
        return contained_change(store, response, recovery, operation)

    with pytest.raises(GovernanceError, match="contained"):
        asyncio.run(
            verify_request(
                store,
                envelope | {"token": "synthetic"},
                Verifier(),
                check,
                commit_change=commit_change,
            )
        )
    assert store.read().challenges[0].consumed
    assert not store.read().verifications


def test_stale_generation_cannot_use_an_old_challenge(tmp_path):
    """Even the correct nonce cannot certify an enrollment generation that changed."""
    from agent.governance.bootstrap import update_intent
    from agent.governance.relying import challenge, verify_request

    s = installed(tmp_path)
    s.configure((source(),), 1)
    c = s.case("fixture").model_copy(
        update={
            "binding": binding(),
            "state": "registered",
            "registration_id": "fixture",
            "registration_digest": "0" * 64,
            "registered_at": now(),
        }
    )
    s.change(lambda j: j.model_copy(update={"candidates": (c,)}))
    intent = s.intent(c.candidate_id, "svid")
    update_intent(s, intent, state="submitted", submitted_at=now())
    value = challenge(s, c, intent)
    s.change(
        lambda j: j.model_copy(update={"candidates": (c.model_copy(update={"generation": 2}),)})
    )
    with pytest.raises(GovernanceError, match="challenge_invalid"):
        asyncio.run(verify_request(s, value | {"token": "fixture"}, None, lambda: None))
    assert not s.read().verifications


@pytest.mark.parametrize("unsafe", ["regular", "symlink", "permissions"])
def test_private_socket_refuses_unsafe_existing_entries(tmp_path, unsafe):
    """Startup never removes another file or follows an unsafe socket link."""
    import socket

    from agent.governance.relying import private_socket

    s = installed(tmp_path)
    path = s.root / "relying.sock"
    if unsafe == "regular":
        path.touch(mode=0o600)
    elif unsafe == "symlink":
        path.symlink_to(s.root / "state.json")
    else:
        # Use a short Unix path, then move that same socket inode to the private root.
        import tempfile
        from pathlib import Path

        base = Path("/private/tmp") if Path("/private/tmp").exists() else Path("/tmp")
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            sock = socket.socket(socket.AF_UNIX)
            try:
                short = Path(temporary) / "socket"
                sock.bind(str(short))
                short.rename(path)
                path.chmod(0o666)
            finally:
                sock.close()
    with pytest.raises(GovernanceError, match="storage_error"):
        private_socket(s)
    assert path.exists() or path.is_symlink()
