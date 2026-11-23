"""Sessions serveur dans Redis. La clé Redis est le SHA-256 de l'identifiant de session (cookie)."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from dataclasses import dataclass

from redis.asyncio import Redis

COOKIE_NAME = "__Host-lasthop_session"
LOGIN_COOKIE = "__Host-lasthop_login"


def _key(session_id: str) -> str:
    return "sess:" + hashlib.sha256(session_id.encode()).hexdigest()


def session_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode()).hexdigest()


@dataclass
class SessionData:
    user_id: uuid.UUID
    csrf: str
    created: float


class SessionStore:
    def __init__(self, redis: Redis, idle: int, absolute: int) -> None:
        self.redis, self.idle, self.absolute = redis, idle, absolute

    async def create(self, user_id: uuid.UUID) -> tuple[str, SessionData]:
        sid = secrets.token_urlsafe(32)
        data = SessionData(user_id=user_id, csrf=secrets.token_urlsafe(32), created=time.time())
        await self.redis.set(
            _key(sid), json.dumps({"u": str(user_id), "c": data.csrf, "t": data.created}), ex=self.idle
        )
        return sid, data

    async def get(self, session_id: str) -> SessionData | None:
        raw = await self.redis.get(_key(session_id))
        if raw is None:
            return None
        d = json.loads(raw)
        if time.time() - d["t"] > self.absolute:
            await self.redis.delete(_key(session_id))
            return None
        await self.redis.expire(_key(session_id), self.idle)  # expiration glissante
        return SessionData(user_id=uuid.UUID(d["u"]), csrf=d["c"], created=d["t"])

    async def destroy(self, session_id: str) -> None:
        await self.redis.delete(_key(session_id))
