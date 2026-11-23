"""Résolution DNS inverse des adresses des endpoints (le nom reçu du DNS est NON FIABLE : validé et borné)."""

from __future__ import annotations

import asyncio
import re
import socket
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Endpoint

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
RECHECK_AFTER = timedelta(hours=24)

Resolver = Callable[[str], Awaitable[str | None]]


def clean_hostname(name: str | None) -> str | None:
    if not name:
        return None
    n = name.strip().rstrip(".").lower()
    return n if len(n) <= 253 and HOSTNAME_RE.match(n) else None


async def reverse_lookup(ip: str, wait_s: float = 2.0) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        host, _, _ = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), wait_s)
    except (TimeoutError, OSError):
        return None
    return clean_hostname(host)


async def resolve_pending(
    db: AsyncSession, *, limit: int = 500, concurrency: int = 20, resolver: Resolver = reverse_lookup
) -> int:
    now = datetime.now(UTC)
    eps = (
        (
            await db.execute(
                select(Endpoint)
                .where(
                    Endpoint.ip.is_not(None),
                    Endpoint.active.is_(True),
                    or_(Endpoint.hostname_checked_at.is_(None), Endpoint.hostname_checked_at < now - RECHECK_AFTER),
                )
                .order_by(Endpoint.hostname_checked_at.asc().nulls_first())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    sem = asyncio.Semaphore(concurrency)

    async def one(ep: Endpoint) -> None:
        async with sem:
            name = await resolver(str(ep.ip))
        ep.hostname, ep.hostname_checked_at = clean_hostname(name), now

    await asyncio.gather(*(one(e) for e in eps))
    await db.commit()
    return len(eps)
