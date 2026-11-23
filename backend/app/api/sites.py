from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.models import Site
from app.deps import DbSession, require
from app.security.audit import record
from app.security.rbac import Perm, Principal

router = APIRouter(prefix="/api/v1/sites", tags=["inventory"])
NAME = Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[\w .\-()]+$")]


class SiteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: NAME


@router.get("")
async def list_sites(
    db: DbSession, _: Annotated[Principal, Depends(require(Perm.topology_read))]
) -> list[dict[str, str]]:
    rows = (await db.execute(select(Site).order_by(Site.name))).scalars()
    return [{"id": str(s.id), "name": s.name} for s in rows]


@router.post("", status_code=201)
async def create_site(
    body: SiteIn, request: Request, db: DbSession, p: Annotated[Principal, Depends(require(Perm.inventory_write))]
) -> dict[str, str]:
    site = Site(name=body.name)
    db.add(site)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Ce site existe déjà") from None
    await record(
        db, request, "site.create", principal=p, target_type="site", target_id=str(site.id), details={"name": body.name}
    )
    await db.commit()
    return {"id": str(site.id), "name": site.name}


@router.delete("/{site_id}", status_code=204)
async def delete_site(
    site_id: uuid.UUID,
    request: Request,
    db: DbSession,
    p: Annotated[Principal, Depends(require(Perm.inventory_write))],
) -> None:
    site = (await db.execute(select(Site).where(Site.id == site_id))).scalar_one_or_none()
    if site is None:
        raise HTTPException(404, "Introuvable")
    try:
        await db.delete(site)
        await record(
            db,
            request,
            "site.delete",
            principal=p,
            target_type="site",
            target_id=str(site_id),
            details={"name": site.name},
        )
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Site utilisé par des équipements") from None
