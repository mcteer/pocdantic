"""The local browser is a distinct, strictly same-origin surface."""

import hmac
import re
from urllib.parse import urlparse

from agent.security import SecurityError

HEADERS = {
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "content-security-policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
}


def check_csrf(actual, expected):
    if (
        not isinstance(actual, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", actual)
        or not expected
        or not hmac.compare_digest(actual, expected)
    ):
        raise SecurityError("request_forbidden")


def cookie_value(raw, name):
    values = []
    for item in raw.split(";"):
        key, _, value = item.strip().partition("=")
        if key == name:
            values.append(value)
    if len(values) > 1 or (values and not re.fullmatch(r"[A-Za-z0-9_-]{43}", values[0])):
        raise SecurityError("request_forbidden")
    return values[0] if values else None


class Boundary:
    def __init__(self, app, origin):
        self.app, self.origin, self.host = app, origin, urlparse(origin).netloc

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        pairs = scope["headers"]
        headers = dict(pairs)
        method, path = scope["method"], scope["path"]
        origin = headers.get(b"origin", b"").decode("latin1")
        callback = path == "/auth/callback" and method == "GET"
        valid = (
            sum(k == b"host" for k, _ in pairs) == 1
            and headers.get(b"host", b"").decode("latin1") == self.host
            and all(
                sum(k == name for k, _ in pairs) <= 1
                for name in (b"origin", b"content-type", b"x-csrf-token")
            )
            and method in {"GET", "POST"}
            and (not origin or origin == self.origin or callback)
        )
        body = b""
        if method == "POST":
            valid = (
                valid
                and origin == self.origin
                and headers.get(b"content-type", b"").split(b";")[0] == b"application/json"
            )
            while valid:
                chunk = await receive()
                if chunk["type"] == "http.disconnect":
                    valid = False
                    break
                body += chunk.get("body", b"")
                if len(body) > 65536:
                    valid = False
                    break
                if not chunk.get("more_body"):
                    break

        async def guarded_send(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.decode().lower() not in HEADERS
                ] + [(k.encode(), v.encode()) for k, v in HEADERS.items()]
            await send(message)

        if not valid:
            await guarded_send(
                {
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": (
                        b'{"error":{"code":"request_forbidden",'
                        b'"stage":"request","next_action":"reload"}}'
                    ),
                }
            )
            return
        used = False

        async def buffered_receive():
            nonlocal used
            if method == "POST" and not used:
                used = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, buffered_receive, guarded_send)
