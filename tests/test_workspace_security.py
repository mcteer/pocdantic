import httpx
import pytest
from fastapi import FastAPI

from agent.security import SecurityError
from agent.workspace.security import Boundary, check_csrf


@pytest.mark.parametrize(
    "headers",
    [
        {"host": "evil.example:8000"},
        {"host": "localhost:8000"},
        {"host": "127.0.0.1:8001"},
        {"origin": "null"},
        {"origin": "http://evil.example"},
        {"origin": "http://127.0.0.1:8001"},
    ],
)
async def test_foreign_request_boundary(headers):
    app = FastAPI()
    app.add_middleware(Boundary, origin="http://127.0.0.1:8000")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
    ) as h:
        response = await h.get("/", headers=headers)
    assert response.status_code == 400
    assert response.headers["cache-control"] == "no-store"


async def test_mutation_body_and_origin_guards():
    app = FastAPI()
    app.add_middleware(Boundary, origin="http://127.0.0.1:8000")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
    ) as h:
        assert (await h.post("/", json={})).status_code == 400
        assert (
            await h.post("/", headers={"Origin": "http://127.0.0.1:8000"}, content=b"x" * 65537)
        ).status_code == 400
        assert (
            await h.get("/auth/callback", headers={"Origin": "https://identity.example"})
        ).status_code == 404
        assert (await h.options("/")).status_code == 400


def test_csrf_cannot_be_substituted():
    with pytest.raises(SecurityError):
        check_csrf("wrong", "expected")


@pytest.mark.parametrize("name", ["host", "origin", "content-type", "x-csrf-token"])
async def test_duplicate_security_headers_rejected(name):
    app = FastAPI()

    @app.post("/")
    async def root():
        return {}

    app.add_middleware(Boundary, origin="http://127.0.0.1:8000")
    headers = [
        ("Host", "127.0.0.1:8000"),
        ("Origin", "http://127.0.0.1:8000"),
        ("Content-Type", "application/json"),
        ("X-CSRF-Token", "one"),
    ]
    headers.append((name, dict((k.lower(), v) for k, v in headers)[name]))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
    ) as h:
        assert (await h.post("/", content=b"{}", headers=headers)).status_code == 400


def test_duplicate_cookie_and_invalid_cookie_rejected():
    from agent.workspace.security import cookie_value

    for raw in ("test=a; test=b", "test=short", "test=" + "x" * 44):
        with pytest.raises(SecurityError):
            cookie_value(raw, "test")
