from __future__ import annotations

import csv
import io
import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import Text, cast, func, or_, select
from sqlalchemy.dialects.postgresql import INET

from app.db.models import Device, Endpoint, EndpointHistory, Job, OuiEntry
from app.deps import DbSession, require
from app.security.audit import record
from app.security.rbac import Perm, Principal
from app.services.jobs import create_and_dispatch
from app.services.macs import parse_mac_input, to_canonical

router = APIRouter(prefix="/api/v1", tags=["learning"])
Searcher = Annotated[Principal, Depends(require(Perm.search))]
Writer = Annotated[Principal, Depends(require(Perm.inventory_write))]
Admin = Annotated[Principal, Depends(require(Perm.settings_write))]


def _view(e: Endpoint, vendor: str | None) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "mac": str(e.mac),
        "ip": str(e.ip) if e.ip is not None else None,
        "vlan": e.vlan,
        "vendor": vendor,
        "hostname": e.hostname,
        "device_id": str(e.device_id) if e.device_id else None,
        "device": e.device_name,
        "port": e.port_name,
        "first_seen": e.first_seen.isoformat(),
        "last_seen": e.last_seen.isoformat(),
        "active": e.active,
    }


@router.post("/devices/{device_id}/learn", status_code=202)
async def learn_device(device_id: uuid.UUID, request: Request, db: DbSession, p: Writer) -> dict[str, str]:
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if d is None:
        raise HTTPException(404, "Introuvable")
    job = await create_and_dispatch(request, db, p, "learning", {"device_id": str(d.id)})
    await record(
        db,
        request,
        "learning.collect",
        principal=p,
        target_type="device",
        target_id=str(d.id),
        details={"job_id": str(job.id)},
    )
    await db.commit()
    return {"job_id": str(job.id)}


class Filters:
    """Filtres de recherche communs à la liste et à l'export CSV (validés strictement, aucun joker SQL)."""

    def __init__(
        self,
        mac: Annotated[str | None, Query(max_length=32)] = None,
        ip: Annotated[str | None, Query(max_length=43)] = None,
        vlan: Annotated[int | None, Query(ge=1, le=4094)] = None,
        device_id: Annotated[uuid.UUID | None, Query()] = None,
        hostname: Annotated[str | None, Query(max_length=100)] = None,
        port: Annotated[str | None, Query(max_length=64)] = None,
        interface_id: Annotated[uuid.UUID | None, Query()] = None,
        q: Annotated[str | None, Query(max_length=100)] = None,
        active: Annotated[bool | None, Query()] = None,
    ) -> None:
        self.mac, self.ip, self.vlan, self.device_id = mac, ip, vlan, device_id
        self.hostname, self.port, self.q, self.active = hostname, port, q, active
        self.interface_id = interface_id  # filtre EXACT sur un port (le filtre `port` est une sous-chaîne)

    def describe(self) -> dict[str, Any]:
        return {k: str(v) for k, v in vars(self).items() if v not in (None, "")}


def _contains(column: Any, needle: str) -> Any:
    return func.strpos(func.lower(column), needle.lower()) > 0  # sous-chaîne littérale : pas de LIKE, donc pas de joker


def _ip_condition(value: str) -> Any:
    try:
        net = ipaddress.ip_network(value, strict=False)  # adresse seule ou CIDR
    except ValueError:
        raise HTTPException(422, "IP invalide") from None
    return Endpoint.ip.op("<<=")(cast(str(net), INET))


def _mac_condition(value: str) -> Any:
    try:
        hexa = parse_mac_input(value, allow_partial=True)  # tous formats ; partiel = sous-chaîne hexadécimale
    except ValueError:
        raise HTTPException(422, "MAC invalide") from None
    if len(hexa) == 12:
        return Endpoint.mac == to_canonical(hexa)
    return func.strpos(func.replace(cast(Endpoint.mac, Text), ":", ""), hexa) > 0


def _apply(q: Any, f: Filters) -> Any:
    if f.mac:
        q = q.where(_mac_condition(f.mac))
    if f.ip:
        q = q.where(_ip_condition(f.ip))
    if f.vlan is not None:
        q = q.where(Endpoint.vlan == f.vlan)
    if f.device_id:
        q = q.where(Endpoint.device_id == f.device_id)
    if f.hostname:
        q = q.where(_contains(Endpoint.hostname, f.hostname))
    if f.interface_id:
        q = q.where(Endpoint.interface_id == f.interface_id)
    if f.port:
        q = q.where(_contains(Endpoint.port_name, f.port))
    if f.active is not None:
        q = q.where(Endpoint.active.is_(f.active))
    if f.q and f.q.strip():  # recherche globale : IP, MAC partielle, nom d'hôte, port, équipement, fabricant, VLAN
        text_q = f.q.strip()
        conds = [
            _contains(Endpoint.hostname, text_q),
            _contains(Endpoint.port_name, text_q),
            _contains(Endpoint.device_name, text_q),
            _contains(OuiEntry.vendor, text_q),
        ]
        if "." in text_q or ":" in text_q:
            try:
                conds.append(_ip_condition(text_q))
            except HTTPException:
                pass
        try:
            hexa = parse_mac_input(text_q, allow_partial=True)
            if len(hexa) >= 4:
                conds.append(_mac_condition(text_q))
        except ValueError:
            pass
        if text_q.isdigit() and 1 <= int(text_q) <= 4094:
            conds.append(Endpoint.vlan == int(text_q))
        q = q.where(or_(*conds))
    return q


def _base() -> Any:
    return select(Endpoint, OuiEntry.vendor).outerjoin(OuiEntry, OuiEntry.prefix == func.trunc(Endpoint.mac))


@router.get("/endpoints")
async def list_endpoints(
    db: DbSession,
    _: Searcher,
    f: Annotated[Filters, Depends()],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> dict[str, Any]:
    q = _apply(_base(), f)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows = (await db.execute(q.order_by(Endpoint.last_seen.desc(), Endpoint.id).limit(limit).offset(offset))).all()
    return {"total": total, "items": [_view(e, v) for e, v in rows]}


EXPORT_MAX_ROWS = 50_000
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: Any) -> str:
    """Neutralise l'injection de formules (tableur) : une cellule commençant par = + - @ reçoit une apostrophe."""
    text_v = "" if value is None else str(value)
    return "'" + text_v if text_v.startswith(_FORMULA_PREFIXES) else text_v


@router.get("/endpoints/export.csv")
async def export_endpoints(
    request: Request,
    db: DbSession,
    p: Annotated[Principal, Depends(require(Perm.export))],
    f: Annotated[Filters, Depends()],
) -> Response:
    q = _apply(_base(), f)
    rows = (await db.execute(q.order_by(Endpoint.last_seen.desc(), Endpoint.id).limit(EXPORT_MAX_ROWS + 1))).all()
    truncated = len(rows) > EXPORT_MAX_ROWS
    rows = rows[:EXPORT_MAX_ROWS]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(["mac", "ip", "hostname", "vendor", "vlan", "switch", "port", "first_seen", "last_seen", "active"])
    for e, vendor in rows:
        w.writerow(
            [
                csv_safe(x)
                for x in (
                    e.mac,
                    e.ip,
                    e.hostname,
                    vendor,
                    e.vlan,
                    e.device_name,
                    e.port_name,
                    e.first_seen.isoformat(),
                    e.last_seen.isoformat(),
                    "yes" if e.active else "no",
                )
            ]
        )
    await record(
        db,
        request,
        "endpoints.export",
        principal=p,
        details={"filters": f.describe(), "rows": len(rows), "truncated": truncated},
    )
    await db.commit()
    name = f"endpoints-{datetime.now(UTC):%Y%m%d-%H%M}.csv"
    return Response(
        "\ufeff" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"', "X-Export-Truncated": str(truncated).lower()},
    )


@router.get("/endpoints/{endpoint_id}/history")
async def endpoint_history(
    endpoint_id: uuid.UUID, db: DbSession, _: Searcher, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> list[dict[str, Any]]:
    if (await db.execute(select(Endpoint.id).where(Endpoint.id == endpoint_id))).first() is None:
        raise HTTPException(404, "Introuvable")
    rows = (
        await db.execute(
            select(EndpointHistory)
            .where(EndpointHistory.endpoint_id == endpoint_id)
            .order_by(EndpointHistory.ts.desc(), EndpointHistory.id.desc())
            .limit(limit)
        )
    ).scalars()
    return [{"ts": h.ts.isoformat(), "change": h.change, "old": h.old, "new": h.new} for h in rows]


@router.post("/oui/update", status_code=202)
async def update_oui(request: Request, db: DbSession, p: Admin) -> dict[str, str]:
    job = await create_and_dispatch(request, db, p, "oui_update", {})
    await record(db, request, "oui.update", principal=p, target_type="job", target_id=str(job.id))
    await db.commit()
    return {"job_id": str(job.id)}


_ = Job
