"""Real-Time Location : lancement (job) + flux SSE authentifié des résultats progressifs."""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.db.models import Job, Role, Site
from app.deps import DbSession, require, still_authenticated
from app.redis_util import stream_key
from app.security.audit import record
from app.security.ratelimit import hit
from app.security.rbac import Perm, Principal
from app.services.jobs import create_and_dispatch
from app.services.realtime import parse_query
from app.services.settings_store import get_value

router = APIRouter(prefix="/api/v1/realtime", tags=["realtime"])
Operator = Annotated[Principal, Depends(require(Perm.realtime))]

MAX_PER_MINUTE = 6  # requêtes coûteuses pour le réseau : limite stricte par utilisateur
MAX_CONCURRENT = 2
TERMINAL = {"done"}
_LAST_ID = re.compile(r"^\d{1,20}-\d{1,20}$")


class RealtimeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: Annotated[str, Field(min_length=7, max_length=64)]  # IP ou MAC, tous formats
    site_id: uuid.UUID | None = None


async def _own_job(db: DbSession, job_id: uuid.UUID, p: Principal) -> Job:
    j = (await db.execute(select(Job).where(Job.id == job_id, Job.kind == "realtime"))).scalar_one_or_none()
    if j is None or (j.requested_by != p.user_id and p.role != Role.admin):
        raise HTTPException(404, "Introuvable")
    return j


@router.post("", status_code=202)
async def start(body: RealtimeIn, request: Request, db: DbSession, p: Operator) -> dict[str, str]:
    try:
        kind, value = parse_query(body.query)
    except ValueError:
        raise HTTPException(
            422, "Saisie invalide : adresse IP ou MAC attendue (aa:bb:cc:dd:ee:ff, aabb.ccdd.eeff, ...)"
        ) from None
    ok, retry = await hit(request.app.state.redis, f"realtime:{p.user_id}", MAX_PER_MINUTE, 60)
    if not ok:
        raise HTTPException(429, "Trop de recherches en direct", headers={"Retry-After": str(retry)})
    window = int(await get_value(db, "realtime_timeout_s")) + 60
    active = (
        await db.execute(
            select(func.count())
            .select_from(Job)
            .where(
                Job.kind == "realtime",
                Job.requested_by == p.user_id,
                Job.status.in_(("pending", "running")),
                Job.created_at > datetime.now(UTC) - timedelta(seconds=window),
            )
        )
    ).scalar_one()
    if active >= MAX_CONCURRENT:
        raise HTTPException(429, "Recherches en cours trop nombreuses", headers={"Retry-After": "5"})
    if body.site_id and (await db.execute(select(Site.id).where(Site.id == body.site_id))).first() is None:
        raise HTTPException(422, "Site inconnu")

    params = {
        "query": body.query[:64],
        "kind": kind,
        "value": value,
        "site_id": str(body.site_id) if body.site_id else None,
    }

    async def audit(job: Job) -> None:  # tracé dans la même transaction que la création du job
        await record(
            db,
            request,
            "realtime.search",
            principal=p,
            target_type="job",
            target_id=str(job.id),
            details={"query": value, "kind": kind, "site_id": params["site_id"]},
        )

    job = await create_and_dispatch(request, db, p, "realtime", params, queue="realtime", audit=audit)
    return {"job_id": str(job.id), "events_url": f"/api/v1/realtime/{job.id}/events"}


@router.get("/{job_id}")
async def result(job_id: uuid.UUID, db: DbSession, p: Operator) -> dict[str, Any]:
    j = await _own_job(db, job_id, p)
    return {
        "id": str(j.id),
        "status": j.status,
        "error_code": j.error_code,
        "result": j.result,
        "created_at": j.created_at.isoformat(),
        "finished_at": j.finished_at.isoformat() if j.finished_at else None,
    }


def _sse(event_id: str | None, type_: str, data: str) -> str:
    head = f"id: {event_id}\n" if event_id else ""
    return f"{head}event: {type_}\ndata: {data}\n\n"


@router.get("/{job_id}/events")
async def events(job_id: uuid.UUID, request: Request, db: DbSession, p: Operator) -> StreamingResponse:
    job = await _own_job(db, job_id, p)
    budget = int(await get_value(db, "realtime_timeout_s")) + 45
    last = request.headers.get("last-event-id", "0-0")
    if not _LAST_ID.match(last):
        last = "0-0"
    redis, key = request.app.state.redis, stream_key(job_id)
    status, final = job.status, job.result

    async def gen() -> AsyncIterator[str]:
        cursor, start, quiet = last, time.monotonic(), 0
        yield ": connected\n\n"
        while time.monotonic() - start < budget:
            if await request.is_disconnected():
                return
            res = await redis.xread({key: cursor}, count=50, block=5000)
            if not res:
                quiet += 1
                yield ": ping\n\n"
                if not await still_authenticated(request, p):  # session fermée / token révoqué : on coupe le flux
                    yield _sse(None, "auth_expired", "{}")
                    return
                if quiet >= 2 and status in ("done", "failed") and cursor == "0-0":
                    # flux expiré de Redis : on restitue le résultat final stocké en base
                    kind = "located" if final and final.get("ok") else "failed"
                    yield _sse(None, kind, json.dumps(final or {}, default=str))
                    yield _sse(None, "done", json.dumps({"ok": bool(final and final.get("ok"))}))
                    return
                continue
            quiet = 0
            for _, entries in res:
                for eid, fields in entries:
                    cursor = eid
                    yield _sse(eid, fields["type"], fields["data"])
                    if fields["type"] in TERMINAL:
                        return
        yield _sse(None, "failed", json.dumps({"error_code": "STREAM_TIMEOUT"}))

    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    _ = asyncio
    return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)
