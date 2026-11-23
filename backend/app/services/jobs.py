"""Création et envoi des jobs au worker Celery (arguments JSON : uniquement l'identifiant du job)."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Job
from app.security.ratelimit import hit
from app.security.rbac import Principal

JOB_TASK = "lasthop.jobs.process"


async def default_dispatch(job_id: uuid.UUID, queue: str | None = None) -> None:
    from app.worker.celery_app import celery_app

    kwargs: dict[str, Any] = {"queue": queue} if queue else {}
    await asyncio.to_thread(celery_app.send_task, JOB_TASK, args=[str(job_id)], **kwargs)


async def create_and_dispatch(
    request: Request,
    db: AsyncSession,
    principal: Principal,
    kind: str,
    params: dict[str, Any],
    *,
    queue: str | None = None,
    audit: Callable[[Job], Awaitable[None]] | None = None,
) -> Job:
    """Crée le job, l'audite dans la MÊME transaction (la tentative est tracée même si le broker est indisponible),
    puis l'envoie au worker (JSON : uniquement l'identifiant)."""
    ok, retry = await hit(request.app.state.redis, f"jobs:{principal.user_id}", 10, 60)
    if not ok:
        raise HTTPException(429, "Trop de requêtes", headers={"Retry-After": str(retry)})
    job = Job(kind=kind, requested_by=principal.user_id, params=params)
    db.add(job)
    await db.flush()
    if audit is not None:
        await audit(job)
    await db.commit()
    try:
        await request.app.state.dispatch_job(job.id, queue)
    except Exception:  # noqa: BLE001 - broker indisponible
        await db.execute(update(Job).where(Job.id == job.id).values(status="failed", error_code="DISPATCH_FAILED"))
        await db.commit()
        raise HTTPException(503, "File de tâches indisponible") from None
    return job
