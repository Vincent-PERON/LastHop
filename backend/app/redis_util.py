"""Client Redis (ACL, TLS optionnel) et publication des événements de recherche en direct dans un Redis Stream."""

from __future__ import annotations

import json
from typing import Any

import redis.asyncio as aioredis

from app.config import Settings

STREAM_TTL_S = 900
STREAM_MAXLEN = 1000


def make_redis(s: Settings) -> aioredis.Redis:
    kwargs: dict[str, Any] = {"decode_responses": True, "health_check_interval": 30}
    if s.redis_tls_ca_file:
        kwargs["ssl_ca_certs"] = s.redis_tls_ca_file
    return aioredis.from_url(s.redis_url, **kwargs)


def stream_key(job_id: object) -> str:
    return f"rt:{job_id}"


class StreamPublisher:
    """Publie les événements d'un job. Un Stream (et non du pub/sub) permet de rejouer l'historique à un client qui se
    connecte en retard ou se reconnecte (Last-Event-ID)."""

    def __init__(self, redis: aioredis.Redis, job_id: object) -> None:
        self.redis, self.key = redis, stream_key(job_id)

    async def __call__(self, type_: str, data: dict[str, Any]) -> None:
        await self.redis.xadd(
            self.key, {"type": type_, "data": json.dumps(data, default=str)}, maxlen=STREAM_MAXLEN, approximate=True
        )
        await self.redis.expire(self.key, STREAM_TTL_S)
