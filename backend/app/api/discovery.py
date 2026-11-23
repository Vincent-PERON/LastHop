from __future__ import annotations

import ipaddress
import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.devices import NAME, _check_refs
from app.db.models import Device, Job, Role, SnmpCredentialRow
from app.deps import CurrentPrincipal, DbSession, require
from app.security.audit import record
from app.security.rbac import Perm, Principal
from app.security.targets import TargetNotAllowed, parse_discovery_cidr
from app.services.jobs import create_and_dispatch
from app.services.settings_store import get_value

router = APIRouter(prefix="/api/v1", tags=["discovery"])
Writer = Annotated[Principal, Depends(require(Perm.inventory_write))]


class DiscoveryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cidr: Annotated[str, Field(min_length=7, max_length=43)]
    credential_id: uuid.UUID
    port: Annotated[int, Field(ge=1, le=65535)] = 161


class AdoptItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: IPvAnyAddress
    name: NAME
    role: Literal["core", "distribution", "access"]
    site_id: uuid.UUID | None = None


class AdoptIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: Annotated[list[AdoptItem], Field(min_length=1, max_length=200)]


@router.post("/discovery", status_code=202)
async def start_discovery(body: DiscoveryIn, request: Request, db: DbSession, p: Writer) -> dict[str, str]:
    try:
        net = parse_discovery_cidr(body.cidr, await get_value(db, "snmp_allowed_cidrs"))
    except TargetNotAllowed as exc:
        await record(
            db,
            request,
            "discovery.run",
            principal=p,
            outcome="denied",
            details={"cidr": body.cidr[:43], "reason": str(exc)},
        )
        await db.commit()
        raise HTTPException(422, "Plage refusée (hors des réseaux SNMP autorisés, trop large ou interdite)") from None
    await _check_refs(db, None, body.credential_id)
    job = await create_and_dispatch(
        request,
        db,
        p,
        "discovery",
        {"cidr": str(net), "credential_id": str(body.credential_id), "port": body.port},
    )
    await record(
        db,
        request,
        "discovery.run",
        principal=p,
        target_type="job",
        target_id=str(job.id),
        details={"cidr": str(net), "port": body.port},
    )
    await db.commit()
    return {"job_id": str(job.id)}


@router.get("/jobs/{job_id}")
async def get_job(job_id: uuid.UUID, db: DbSession, p: CurrentPrincipal) -> dict[str, Any]:
    j = (await db.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
    if j is None or (j.requested_by != p.user_id and p.role != Role.admin) or Perm.inventory_write not in p.permissions:
        raise HTTPException(404, "Introuvable")
    return {
        "id": str(j.id),
        "kind": j.kind,
        "status": j.status,
        "error_code": j.error_code,
        "result": j.result,
        "created_at": j.created_at.isoformat(),
        "finished_at": j.finished_at.isoformat() if j.finished_at else None,
    }


@router.post("/discovery/{job_id}/adopt", status_code=201)
async def adopt(job_id: uuid.UUID, body: AdoptIn, request: Request, db: DbSession, p: Writer) -> dict[str, Any]:
    j = (await db.execute(select(Job).where(Job.id == job_id, Job.kind == "discovery"))).scalar_one_or_none()
    if j is None or j.status != "done" or not j.result:
        raise HTTPException(404, "Découverte introuvable ou non terminée")
    found = {h["ip"]: h for h in j.result["hosts"]}
    cred_id = uuid.UUID(j.params["credential_id"])
    if (await db.execute(select(SnmpCredentialRow.id).where(SnmpCredentialRow.id == cred_id))).first() is None:
        raise HTTPException(409, "Le profil d'identifiants a été supprimé")
    created: list[str] = []
    for item in body.items:
        ip = str(ipaddress.ip_address(str(item.ip)))
        h = found.get(ip)
        if h is None:  # on n'adopte que ce que la découverte a réellement vu
            raise HTTPException(422, "Adresse absente des résultats de la découverte")
        await _check_refs(db, item.site_id, None)
        d = Device(
            name=item.name,
            mgmt_ip=ip,
            role=item.role,
            site_id=item.site_id,
            credential_id=cred_id,
            snmp_port=int(j.params.get("port", 161)),
            driver=h["driver"],
            vendor=h["vendor"],
            model=h["model"],
            sys_name=h["sys_name"],
            sys_descr=h["sys_descr"],
            sys_object_id=h["sys_object_id"],
        )
        db.add(d)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            raise HTTPException(409, "Nom ou adresse déjà utilisés") from None
        created.append(str(d.id))
    await record(
        db,
        request,
        "discovery.adopt",
        principal=p,
        target_type="job",
        target_id=str(job_id),
        details={"count": len(created)},
    )
    await db.commit()
    return {"created": created}
