"""Middleware ASGI : request-id, limite de taille, en-têtes de sécurité, journal d'accès sans query-string."""

from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger("lasthop.access")
_RID = re.compile(r"^[A-Za-z0-9-]{8,64}$")

SECURITY_HEADERS = {
    b"content-security-policy": b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    b"x-content-type-options": b"nosniff",
    b"referrer-policy": b"no-referrer",
    b"strict-transport-security": b"max-age=63072000; includeSubDomains",
    b"cache-control": b"no-store",
    b"cross-origin-resource-policy": b"same-origin",
    b"permissions-policy": b"geolocation=(), camera=(), microphone=()",
}


class _TooLarge(Exception):
    pass


class SecurityMiddleware:
    def __init__(self, app: ASGIApp, max_body: int) -> None:
        self.app, self.max_body = app, max_body

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        incoming = headers.get(b"x-request-id", b"").decode("latin-1")
        rid = incoming if _RID.match(incoming) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = rid
        start, status, started = time.monotonic(), 500, False

        if int(headers.get(b"content-length", b"0") or 0) > self.max_body:
            await self._reject(send, rid)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > self.max_body:
                    raise _TooLarge
            return msg

        async def send_wrapper(message: Message) -> None:
            nonlocal status, started
            if message["type"] == "http.response.start":
                started, status = True, message["status"]
                hdrs: list[Any] = [(k, v) for k, v in message["headers"] if k.lower() not in SECURITY_HEADERS]
                hdrs += list(SECURITY_HEADERS.items()) + [(b"x-request-id", rid.encode())]
                message["headers"] = hdrs
            await send(message)

        try:
            await self.app(scope, limited_receive, send_wrapper)
        except _TooLarge:
            if not started:
                await self._reject(send, rid)
            status = 413
        finally:
            log.info(
                "request",
                extra={
                    "request_id": rid,
                    "method": scope["method"],
                    "path": scope["path"],  # pas de query-string (peut contenir code/state OIDC)
                    "status": status,
                    "ms": round((time.monotonic() - start) * 1000, 1),
                },
            )

    @staticmethod
    async def _reject(send: Send, rid: str) -> None:
        body = b'{"detail":"Requ\xc3\xaate trop volumineuse"}'
        hdrs = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
        hdrs += list(SECURITY_HEADERS.items()) + [(b"x-request-id", rid.encode())]
        await send({"type": "http.response.start", "status": 413, "headers": hdrs})
        await send({"type": "http.response.body", "body": body})
