from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from app.db.models import Device, Interface, Neighbor
from app.deps import DbSession, require
from app.security.audit import record
from app.security.rbac import Perm, Principal
from app.services.jobs import create_and_dispatch
from app.services.topology import build_graph

router = APIRouter(prefix="/api/v1", tags=["topology"])
Reader = Annotated[Principal, Depends(require(Perm.inventory_read))]
GraphReader = Annotated[Principal, Depends(require(Perm.topology_read))]
Writer = Annotated[Principal, Depends(require(Perm.inventory_write))]


class RoleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["access", "uplink"] | None  # None = retour à la détection automatique


def _iface_view(i: Interface, nbrs: list[Neighbor], dev_names: dict[uuid.UUID, str]) -> dict[str, Any]:
    return {
        "id": str(i.id),
        "if_index": i.if_index,
        "name": i.name,
        "descr": i.descr,
        "alias": i.alias,
        "oper_status": i.oper_status,
        "is_trunk": i.is_trunk,
        "mac_count": i.mac_count,
        "role": i.role_override or i.role_detected,
        "role_detected": i.role_detected,
        "role_reason": i.role_reason,
        "role_override": i.role_override,
        "neighbors": [
            {
                "protocol": n.protocol,
                "sysname": n.remote_sysname,
                "port": n.remote_port_id,
                "is_network_device": n.remote_is_network_device,
                "matched_device_id": str(n.matched_device_id) if n.matched_device_id else None,
                "matched_device_name": dev_names.get(n.matched_device_id) if n.matched_device_id else None,
            }
            for n in nbrs
        ],
    }


@router.post("/devices/{device_id}/topology", status_code=202)
async def collect_topology(device_id: uuid.UUID, request: Request, db: DbSession, p: Writer) -> dict[str, str]:
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if d is None:
        raise HTTPException(404, "Introuvable")
    job = await create_and_dispatch(request, db, p, "topology", {"device_id": str(d.id)})
    await record(
        db,
        request,
        "topology.collect",
        principal=p,
        target_type="device",
        target_id=str(d.id),
        details={"job_id": str(job.id)},
    )
    await db.commit()
    return {"job_id": str(job.id)}


@router.get("/devices/{device_id}/interfaces")
async def list_interfaces(device_id: uuid.UUID, db: DbSession, _: Reader) -> list[dict[str, Any]]:
    if (await db.execute(select(Device.id).where(Device.id == device_id))).first() is None:
        raise HTTPException(404, "Introuvable")
    ifs = (
        (await db.execute(select(Interface).where(Interface.device_id == device_id).order_by(Interface.if_index)))
        .scalars()
        .all()
    )
    nbrs: dict[uuid.UUID, list[Neighbor]] = {}
    for n in (await db.execute(select(Neighbor).where(Neighbor.device_id == device_id))).scalars():
        nbrs.setdefault(n.interface_id, []).append(n)
    names = {d.id: d.name for d in (await db.execute(select(Device))).scalars()}
    return [_iface_view(i, nbrs.get(i.id, []), names) for i in ifs]


@router.put("/interfaces/{interface_id}/role")
async def set_role(
    interface_id: uuid.UUID, body: RoleBody, request: Request, db: DbSession, p: Writer
) -> dict[str, Any]:
    i = (await db.execute(select(Interface).where(Interface.id == interface_id))).scalar_one_or_none()
    if i is None:
        raise HTTPException(404, "Introuvable")
    previous = i.role_override
    i.role_override = body.role
    i.override_by, i.override_at = (p.user_id, datetime.now(UTC)) if body.role else (None, None)
    await record(
        db,
        request,
        "interface.role_override",
        principal=p,
        target_type="interface",
        target_id=str(i.id),
        details={"device_id": str(i.device_id), "port": i.name, "from": previous, "to": body.role},
    )
    await db.commit()
    return {
        "id": str(i.id),
        "role": i.role_override or i.role_detected,
        "role_override": i.role_override,
        "role_detected": i.role_detected,
    }


@router.get("/topology/graph")
async def graph(
    db: DbSession,
    _: GraphReader,
    site_id: Annotated[uuid.UUID | None, Query()] = None,
    include_unmanaged: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    q = select(Device).order_by(Device.name)
    if site_id:
        q = q.where(Device.site_id == site_id)
    devices = list((await db.execute(q)).scalars())
    ids = {d.id for d in devices}
    ifs = {i.id: i for i in (await db.execute(select(Interface).where(Interface.device_id.in_(ids)))).scalars()}
    nbrs = [
        n
        for n in (await db.execute(select(Neighbor).where(Neighbor.device_id.in_(ids)))).scalars()
        if n.matched_device_id is None or n.matched_device_id in ids
    ]
    # les ports distants appartiennent à des équipements de la sélection : déjà chargés ci-dessus
    return build_graph(devices, ifs, nbrs, include_unmanaged)
