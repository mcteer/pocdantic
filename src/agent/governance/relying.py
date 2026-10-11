"""Independent private relying service with one-use proof challenges.

This process owns no administrative or minting credential. It fetches pinned public
verification metadata itself and exposes only a mode-0600 Unix socket, never browser TCP.
"""

import hashlib
import secrets
import socket
import stat
from datetime import UTC, datetime, timedelta
from uuid import UUID

from pydantic import Field, SecretStr

from agent.validation.models import implementation_revision

from .config import binding_digest
from .models import Challenge, GovernanceError, Record, Verification, now, require


class Request(Record):
    """Bounded secret-bearing IPC envelope; serialization stays inside the private socket."""

    candidate_id: UUID
    challenge_id: UUID
    intent_id: UUID
    generation: int = Field(strict=True, gt=0)
    nonce: SecretStr = Field(min_length=64, max_length=64)
    token: SecretStr = Field(min_length=1, max_length=16384)


def challenge(store, candidate, intent):
    """Persist only a digest of a random 32-byte nonce and return its private IPC envelope."""
    nonce = secrets.token_hex(32)
    record = Challenge(
        candidate_id=candidate.candidate_id,
        generation=candidate.generation,
        intent_id=intent.intent_id,
        binding_digest=binding_digest(candidate.binding),
        implementation=implementation_revision(),
        nonce_digest=hashlib.sha256(nonce.encode()).hexdigest(),
    )

    def update(state):
        """Bind this challenge to the current registered candidate and exact SVID intent."""
        current = next(
            (c for c in state.candidates if c.candidate_id == candidate.candidate_id), None
        )
        require(current == candidate and current.state == "registered", "configuration_changed")
        retained = next((i for i in state.credentials if i.intent_id == intent.intent_id), None)
        require(
            retained
            and retained.kind == "svid"
            and retained.state == "submitted"
            and retained.profile_digest == binding_digest(current.binding)
            and retained.generation == current.generation
            and intent.candidate_id == candidate.candidate_id,
            "challenge_invalid",
        )
        return state.model_copy(update={"challenges": (*state.challenges, record)})

    store.change(update)
    return {
        "schema_version": 1,
        "candidate_id": str(candidate.candidate_id),
        "challenge_id": str(record.challenge_id),
        "intent_id": str(intent.intent_id),
        "generation": candidate.generation,
        "nonce": nonce,
    }


async def verify_request(store, value, verifier, check, *, commit_change=None):
    """Consume before verification, then recheck current holds/profile before committing proof."""
    try:
        request = Request.model_validate(value)
    except Exception:
        raise GovernanceError("challenge_invalid") from None
    check()
    selected = None
    profile = None

    def consume(state):
        """Consume the current challenge atomically before fetching public keys."""
        nonlocal selected, profile
        selected = next(
            (c for c in state.challenges if c.challenge_id == request.challenge_id), None
        )
        candidate = next(
            (c for c in state.candidates if c.candidate_id == request.candidate_id), None
        )
        require(
            selected is not None and candidate is not None and candidate.binding is not None,
            "challenge_invalid",
        )
        profile = candidate.binding.trust
        require(
            not selected.consumed
            and selected.candidate_id == request.candidate_id
            and selected.intent_id == request.intent_id
            and selected.generation == request.generation == candidate.generation
            and candidate.state == "registered"
            and selected.binding_digest == binding_digest(candidate.binding)
            and selected.implementation == implementation_revision()
            and timedelta(0) <= now() - selected.created_at <= timedelta(seconds=60)
            and secrets.compare_digest(
                selected.nonce_digest,
                hashlib.sha256(request.nonce.get_secret_value().encode()).hexdigest(),
            ),
            "challenge_invalid",
        )
        consumed = selected.model_copy(update={"consumed": True})
        return state.model_copy(
            update={
                "challenges": tuple(
                    consumed if c.challenge_id == selected.challenge_id else c
                    for c in state.challenges
                )
            }
        )

    store.change(consume)
    raw = request.token.get_secret_value()
    try:
        require(getattr(verifier, "trust", None) == profile, "configuration_changed")
        claims = await verifier.check(raw)
        require(
            isinstance(claims.get("vault"), dict)
            and isinstance(claims["vault"].get("entity"), dict)
            and claims["vault"]["entity"].get("id") == profile.entity_id,
            "identity_rejected",
        )
        expiry = datetime.fromtimestamp(claims["exp"], UTC)
        result, reason = "pass", "ok"
    except Exception:
        expiry = None
        result, reason = "fail", "identity_rejected"
    check()
    proof = Verification(
        candidate_id=request.candidate_id,
        generation=request.generation,
        challenge_id=request.challenge_id,
        token_digest=hashlib.sha256(raw.encode()).hexdigest(),
        trust_digest=binding_digest(profile),
        expires_at=expiry,
        result=result,
        reason=reason,
    )

    def commit(state):
        """Commit a safe proof only if the independently checked profile remains current."""
        candidate = next(
            (c for c in state.candidates if c.candidate_id == request.candidate_id), None
        )
        require(
            candidate
            and candidate.binding
            and candidate.binding.trust == profile
            and candidate.generation == request.generation
            and candidate.state == "registered"
            and selected.implementation == implementation_revision(),
            "configuration_changed",
        )
        return state.model_copy(update={"verifications": (*state.verifications, proof)})

    if commit_change is not None:
        commit_change(commit)
    else:
        check()
        store.change(commit)
    return {
        "schema_version": 1,
        "proof_id": str(proof.proof_id),
        "candidate_id": str(request.candidate_id),
        "generation": request.generation,
        "result": result,
        "reason_code": reason,
    }


def private_socket(store):
    """Bind only the compiled socket path after service ownership; reject foreign stale files."""
    store._validate_root()
    target = store.root / "relying.sock"
    if target.exists() or target.is_symlink():
        value = target.lstat()
        import os

        require(
            stat.S_ISSOCK(value.st_mode)
            and stat.S_IMODE(value.st_mode) == 0o600
            and value.st_uid == os.getuid(),
            "storage_error",
        )
        target.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        import os

        old = os.umask(0o177)
        try:
            server.bind(str(target))
        finally:
            os.umask(old)
        server.listen(16)
        return server
    except Exception:
        server.close()
        raise GovernanceError("storage_error") from None


def create_app(store, check, verifier_factory, *, commit_change=None):
    """Expose bounded health/verify only on the private socket, with no access or body logs."""
    from fastapi import FastAPI
    from fastapi import Request as HTTPRequest
    from fastapi.responses import JSONResponse

    from agent.validation.store import decode_json

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    async def health():
        """Report only local initialized readiness, never trust/identity details."""
        try:
            store.read()
            check()
            return {"schema_version": 1, "ready": True}
        except Exception:
            return JSONResponse({"schema_version": 1, "ready": False}, status_code=503)

    @app.post("/verify")
    async def incoming(request: HTTPRequest):
        """Read a bounded private envelope and obtain independently loaded pinned trust."""
        try:
            require(request.headers.get("content-encoding", "identity") in {"", "identity"})
            raw = b""
            import asyncio

            async with asyncio.timeout(10):
                async for chunk in request.stream():
                    raw += chunk
                    require(len(raw) <= 65536, "capacity_exhausted")
            value = decode_json(raw)
            envelope = Request.model_validate(value)
            state = store.read()
            candidate = next(
                (c for c in state.candidates if c.candidate_id == envelope.candidate_id), None
            )
            require(candidate and candidate.binding, "challenge_invalid")
            async with verifier_factory(candidate.binding.trust) as verifier:
                async with asyncio.timeout(30):
                    result = await verify_request(
                        store, value, verifier, check, commit_change=commit_change
                    )
            return result
        except GovernanceError as error:
            return JSONResponse({"schema_version": 1, "reason_code": str(error)}, status_code=409)
        except Exception:
            return JSONResponse(
                {"schema_version": 1, "reason_code": "challenge_invalid"}, status_code=400
            )

    return app


async def serve(store, response, recovery):
    """Run one independent relying process using public trust and readonly anchor checks."""
    from contextlib import asynccontextmanager

    import httpx
    import uvicorn

    from .coordinator import admit, contained_change
    from .verifier import Verifier

    def check():
        """Read containment without claiming mint authority or changing existing holds."""
        admit(response.read(), recovery.read())

    cache = {}

    @asynccontextmanager
    async def verifier_factory(trust):
        """Reuse one atomic public-key cache per current trust profile, without credentials."""
        active = {
            binding_digest(c.binding.trust)
            for c in store.read().candidates
            if c.binding and c.state == "registered"
        }
        for digest in tuple(cache):
            if digest not in active:
                del cache[digest]
        digest = binding_digest(trust)
        require(digest in active, "configuration_changed")
        if digest not in cache:
            cache[digest] = Verifier(trust, http)
        yield cache[digest]

    def commit_change(operation):
        """Commit proof while response control prevents a hold-ingestion race."""
        return contained_change(store, response, recovery, operation)

    with store.lock("service.lock"):
        sock = private_socket(store)
        try:
            async with httpx.AsyncClient(
                timeout=10, trust_env=False, follow_redirects=False
            ) as http:
                config = uvicorn.Config(
                    create_app(store, check, verifier_factory, commit_change=commit_change),
                    log_config=None,
                    access_log=False,
                )
                await uvicorn.Server(config).serve(sockets=[sock])
        finally:
            sock.close()
