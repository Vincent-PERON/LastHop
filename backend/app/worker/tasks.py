from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_settings
from app.redis_util import make_redis
from app.security.crypto import keyring_from_settings
from app.services.jobs import JOB_TASK
from app.services.probe import process_job
from app.worker.celery_app import celery_app


async def _run(job_id: str) -> None:
    s = get_settings()
    engine = create_async_engine(s.database_url, poolclass=NullPool)
    redis = make_redis(s)
    try:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            await process_job(db, keyring_from_settings(s.master_keys, s.master_key_active), uuid.UUID(job_id), redis)
    finally:
        await redis.aclose()
        await engine.dispose()


@celery_app.task(name=JOB_TASK, ignore_result=True)  # type: ignore[untyped-decorator]
def process(job_id: str) -> None:
    asyncio.run(_run(job_id))


SCHEDULE_TASK = "lasthop.topology.schedule"


async def _schedule() -> list[str]:
    from app.services.scheduler import (
        create_due_backup_jobs,
        create_due_learning_jobs,
        create_due_topology_jobs,
    )

    s = get_settings()
    engine = create_async_engine(s.database_url, poolclass=NullPool)
    try:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            topo = await create_due_topology_jobs(db)  # d'abord : le learning a besoin des ports/rôles
            learn = await create_due_learning_jobs(db)
            backups = await create_due_backup_jobs(db)
            return [str(i) for i in [*topo, *learn, *backups]]
    finally:
        await engine.dispose()


@celery_app.task(name=SCHEDULE_TASK, ignore_result=True)  # type: ignore[untyped-decorator]
def schedule_topology() -> None:
    for job_id in asyncio.run(_schedule()):
        celery_app.send_task(JOB_TASK, args=[job_id])


PURGE_TASK = "lasthop.maintenance.purge"
DNS_TASK = "lasthop.dns.resolve"
OUI_TASK = "lasthop.oui.update"


async def _with_db(fn: Callable[[AsyncSession], Awaitable[Any]]) -> Any:
    s = get_settings()
    engine = create_async_engine(s.database_url, poolclass=NullPool)
    try:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            return await fn(db)
    finally:
        await engine.dispose()


@celery_app.task(name=PURGE_TASK, ignore_result=True)  # type: ignore[untyped-decorator]
def purge_old_data() -> None:
    from app.services.retention import purge

    asyncio.run(_with_db(purge))


@celery_app.task(name=DNS_TASK, ignore_result=True)  # type: ignore[untyped-decorator]
def resolve_hostnames() -> None:
    from app.services.dns import resolve_pending

    asyncio.run(_with_db(resolve_pending))


@celery_app.task(name=OUI_TASK, ignore_result=True)  # type: ignore[untyped-decorator]
def update_oui_db() -> None:
    from app.services.oui import update_oui

    asyncio.run(_with_db(update_oui))
