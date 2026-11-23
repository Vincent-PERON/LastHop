"""Limiteur à fenêtre fixe sur Redis (compteurs atomiques INCR + EXPIRE)."""

from __future__ import annotations

from fastapi import HTTPException, Request
from redis.asyncio import Redis


async def hit(redis: Redis, bucket: str, limit: int, window_s: int) -> tuple[bool, int]:
    key = f"rl:{bucket}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, window_s)
    ttl = await redis.ttl(key)
    if ttl < 0:  # clé sans TTL (course) : on la répare
        await redis.expire(key, window_s)
        ttl = window_s
    return count <= limit, max(ttl, 1)


def ip_limiter(name: str, limit: int, window_s: int):  # type: ignore[no-untyped-def]
    async def dep(request: Request) -> None:
        ip = request.client.host if request.client else "unknown"
        ok, retry = await hit(request.app.state.redis, f"{name}:{ip}", limit, window_s)
        if not ok:
            raise HTTPException(429, "Trop de requêtes", headers={"Retry-After": str(retry)})

    return dep
