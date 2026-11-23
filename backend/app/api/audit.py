from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select

from app.db.models import AuditLog
from app.deps import DbSession, require
from app.security.audit import record, verify_chain
from app.security.rbac import Perm, Principal

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("")
async def list_audit(
    request: Request,
    db: DbSession,
    principal: Annotated[Principal, Depends(require(Perm.audit_read))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    before_id: Annotated[int | None, Query(ge=1)] = None,
    action: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z_.]+$")] = None,
) -> list[dict[str, Any]]:
    q = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if before_id:
        q = q.where(AuditLog.id < before_id)
    if action:
        q = q.where(AuditLog.action == action)
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": r.id,
            "ts": r.ts.isoformat(),
            "actor_type": r.actor_type,
            "actor_label": r.actor_label,
            "action": r.action,
            "outcome": r.outcome,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "source_ip": str(r.source_ip) if r.source_ip else None,
            "request_id": r.request_id,
            "details": r.details,
        }
        for r in rows
    ]


@router.get("/verify")
async def verify(
    request: Request, db: DbSession, principal: Annotated[Principal, Depends(require(Perm.audit_read))]
) -> dict[str, Any]:
    broken = await verify_chain(db)
    await record(db, request, "audit.verify", principal=principal, details={"intact": broken is None})
    await db.commit()
    return {"intact": broken is None, "first_broken_id": broken}
