"""Sauvegardes de configuration : lancement, historique, journal lisible, consultation (masquée) et comparaison."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import BackupEvent, BackupRun, ConfigBackup, Device
from app.deps import DbSession, require
from app.security.audit import record
from app.security.crypto import CryptoError, keyring_from_settings
from app.security.rbac import Perm, Principal
from app.services import cli
from app.services.jobs import create_and_dispatch
from app.services.ssh_backup import unseal_config

router = APIRouter(prefix="/api/v1", tags=["backups"])
Runner = Annotated[Principal, Depends(require(Perm.backups_run))]
Reader = Annotated[Principal, Depends(require(Perm.backups_read))]


def _run_view(r: BackupRun) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "device_id": str(r.device_id) if r.device_id else None,
        "device": r.device_name,
        "trigger": r.trigger,
        "requested_by": r.requested_by,
        "status": r.status,
        "error_code": r.error_code,
        "summary": r.summary,
        "results": r.results,
        "started_at": r.started_at.isoformat(),
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
    }


async def _text_of(db: AsyncSession, request: Request, b: ConfigBackup) -> str:
    owner = b if b.status == "success" else (await db.get(ConfigBackup, b.same_as_id) if b.same_as_id else None)
    if owner is None or owner.content_blob is None:
        raise HTTPException(410, "Le contenu de cette version a été purgé (rétention)")
    s = request.app.state.settings
    try:
        return unseal_config(keyring_from_settings(s.master_keys, s.master_key_active), owner)
    except CryptoError:
        raise HTTPException(500, "Contenu illisible (clé de chiffrement)") from None


@router.post("/devices/{device_id}/backup", status_code=202)
async def start_backup(device_id: uuid.UUID, request: Request, db: DbSession, p: Runner) -> dict[str, str]:
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if d is None:
        raise HTTPException(404, "Introuvable")
    params = {"device_id": str(d.id), "trigger": "manual", "requested_by": p.label}

    async def audit(job: Any) -> None:
        await record(
            db,
            request,
            "backup.run",
            principal=p,
            target_type="device",
            target_id=str(d.id),
            details={"job_id": str(job.id), "device": d.name},
        )

    job = await create_and_dispatch(request, db, p, "backup", params, audit=audit)
    return {"job_id": str(job.id)}


@router.get("/backups/runs")
async def list_runs(
    db: DbSession,
    _: Reader,
    device_id: Annotated[uuid.UUID | None, Query()] = None,
    status: Annotated[str | None, Query(pattern="^(running|success|partial|failed)$")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> dict[str, Any]:
    q = select(BackupRun)
    if device_id:
        q = q.where(BackupRun.device_id == device_id)
    if status:
        q = q.where(BackupRun.status == status)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows = (await db.execute(q.order_by(BackupRun.started_at.desc()).limit(limit).offset(offset))).scalars()
    return {"total": total, "items": [_run_view(r) for r in rows]}


@router.get("/backups/runs/{run_id}")
async def run_detail(run_id: uuid.UUID, db: DbSession, _: Reader) -> dict[str, Any]:
    r = (await db.execute(select(BackupRun).where(BackupRun.id == run_id))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404, "Introuvable")
    events = (
        await db.execute(select(BackupEvent).where(BackupEvent.run_id == run_id).order_by(BackupEvent.id))
    ).scalars()
    return {
        **_run_view(r),
        "events": [
            {"ts": e.ts.isoformat(), "level": e.level, "message": e.message, "advice": e.advice, "detail": e.detail}
            for e in events
        ],
    }


@router.get("/devices/{device_id}/backups")
async def device_backups(
    device_id: uuid.UUID, db: DbSession, _: Reader, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(ConfigBackup)
            .where(ConfigBackup.device_id == device_id)
            .order_by(ConfigBackup.created_at.desc())
            .limit(limit)
        )
    ).scalars()
    return [
        {
            "id": str(b.id),
            "kind": b.kind,
            "status": b.status,
            "size_bytes": b.size_bytes,
            "sha256": b.sha256,
            "created_at": b.created_at.isoformat(),
            "run_id": str(b.run_id) if b.run_id else None,
        }
        for b in rows
    ]


@router.get("/backups/diff")
async def diff(
    request: Request, db: DbSession, p: Reader, a: Annotated[uuid.UUID, Query()], b: Annotated[uuid.UUID, Query()]
) -> dict[str, Any]:
    ra = (await db.execute(select(ConfigBackup).where(ConfigBackup.id == a))).scalar_one_or_none()
    rb = (await db.execute(select(ConfigBackup).where(ConfigBackup.id == b))).scalar_one_or_none()
    if ra is None or rb is None or ra.device_id != rb.device_id:
        raise HTTPException(404, "Versions introuvables ou d'équipements différents")
    ta, tb = cli.mask_secrets(await _text_of(db, request, ra)), cli.mask_secrets(await _text_of(db, request, rb))
    await record(
        db,
        request,
        "backup.diff",
        principal=p,
        target_type="device",
        target_id=str(ra.device_id),
        details={"a": str(a), "b": str(b)},
    )
    await db.commit()
    added, removed = cli.diff_stats(ta, tb)
    return {
        "added": added,
        "removed": removed,
        "diff": cli.unified_diff(
            ta, tb, f"{ra.kind} {ra.created_at:%Y-%m-%d %H:%M}", f"{rb.kind} {rb.created_at:%Y-%m-%d %H:%M}"
        ),
    }


@router.get("/backups/{backup_id}")
async def view_backup(
    backup_id: uuid.UUID, request: Request, db: DbSession, p: Reader, raw: Annotated[bool, Query()] = False
) -> dict[str, Any]:
    """Par défaut les secrets (mots de passe, communities, clés) sont masqués. `raw=true` renvoie le contenu intégral :
    chaque accès est tracé dans l'audit."""
    b = (await db.execute(select(ConfigBackup).where(ConfigBackup.id == backup_id))).scalar_one_or_none()
    if b is None:
        raise HTTPException(404, "Introuvable")
    text = await _text_of(db, request, b)
    await record(
        db,
        request,
        "backup.view_raw" if raw else "backup.view",
        principal=p,
        target_type="config_backup",
        target_id=str(b.id),
        details={"device_id": str(b.device_id), "kind": b.kind},
    )
    await db.commit()
    return {
        "id": str(b.id),
        "kind": b.kind,
        "status": b.status,
        "size_bytes": b.size_bytes,
        "sha256": b.sha256,
        "created_at": b.created_at.isoformat(),
        "masked": not raw,
        "content": text if raw else cli.mask_secrets(text),
    }
