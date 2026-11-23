from __future__ import annotations

import ipaddress
import uuid
from typing import Annotated, Any, Literal

import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress
from sqlalchemy import case, func, select, update
from sqlalchemy.exc import IntegrityError

from app.db.models import Device, Endpoint, Interface, Job, Role, Site, SnmpCredentialRow, SshCredentialRow
from app.deps import DbSession, require
from app.security.audit import record
from app.security.rbac import Perm, Principal
from app.security.targets import TargetNotAllowed, check_address
from app.services.jobs import create_and_dispatch
from app.services.settings_store import get_value

router = APIRouter(prefix="/api/v1/devices", tags=["inventory"])
Reader = Annotated[Principal, Depends(require(Perm.inventory_read))]
Writer = Annotated[Principal, Depends(require(Perm.inventory_write))]

NAME = Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[\w .\-()]+$")]
SnmpContext = Annotated[str, Field(max_length=32, pattern=r"^[\w.\-]*$")]  # contextName SNMPv3 de base
DriverName = Literal["generic", "aruba_os", "comware", "cisco_ios"]


class DeviceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: NAME
    mgmt_ip: IPvAnyAddress
    site_id: uuid.UUID | None = None
    role: Literal["core", "distribution", "access"]
    credential_id: uuid.UUID
    driver: DriverName = "generic"
    is_l3: bool = False
    is_l2: bool = True
    snmp_port: Annotated[int, Field(ge=1, le=65535)] = 161
    timeout_ms: Annotated[int, Field(ge=500, le=30000)] = 3000
    retries: Annotated[int, Field(ge=0, le=5)] = 1
    max_repetitions: Annotated[int, Field(ge=1, le=100)] = 25
    poll_interval_s: Annotated[int, Field(ge=60, le=86400)] = 900
    enabled: bool = True
    snmp_context: SnmpContext = ""
    ssh_credential_id: uuid.UUID | None = None
    ssh_port: Annotated[int, Field(ge=1, le=65535)] = 22
    ssh_allow_legacy: bool = False
    backup_enabled: bool = False


class DeviceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: NAME | None = None
    mgmt_ip: IPvAnyAddress | None = None
    site_id: uuid.UUID | None = None
    role: Literal["core", "distribution", "access"] | None = None
    credential_id: uuid.UUID | None = None
    driver: DriverName | None = None
    is_l3: bool | None = None
    is_l2: bool | None = None
    snmp_port: Annotated[int, Field(ge=1, le=65535)] | None = None
    timeout_ms: Annotated[int, Field(ge=500, le=30000)] | None = None
    retries: Annotated[int, Field(ge=0, le=5)] | None = None
    max_repetitions: Annotated[int, Field(ge=1, le=100)] | None = None
    poll_interval_s: Annotated[int, Field(ge=60, le=86400)] | None = None
    enabled: bool | None = None
    snmp_context: SnmpContext | None = None
    ssh_credential_id: uuid.UUID | None = None
    ssh_port: Annotated[int, Field(ge=1, le=65535)] | None = None
    ssh_allow_legacy: bool | None = None
    backup_enabled: bool | None = None


def _view(d: Device, admin: bool) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(d.id),
        "name": d.name,
        "mgmt_ip": str(d.mgmt_ip),
        "site_id": str(d.site_id) if d.site_id else None,
        "role": d.role,
        "driver": d.driver,
        "vendor": d.vendor,
        "model": d.model,
        "sys_name": d.sys_name,
        "sys_descr": d.sys_descr,
        "sys_object_id": d.sys_object_id,
        "is_l3": d.is_l3,
        "is_l2": d.is_l2,
        "enabled": d.enabled,
        "last_identified_at": d.last_identified_at.isoformat() if d.last_identified_at else None,
        "last_poll_status": d.last_poll_status,
        "last_topology_at": d.last_topology_at.isoformat() if d.last_topology_at else None,
        "last_topology_status": d.last_topology_status,
        "chassis_mac": str(d.chassis_mac) if d.chassis_mac else None,
        "last_learning_at": d.last_learning_at.isoformat() if d.last_learning_at else None,
        "last_learning_status": d.last_learning_status,
        "last_backup_at": d.last_backup_at.isoformat() if d.last_backup_at else None,
        "last_backup_status": d.last_backup_status,
    }
    if admin:  # paramètres SNMP : réservés aux administrateurs
        out.update(
            credential_id=str(d.credential_id),
            snmp_port=d.snmp_port,
            timeout_ms=d.timeout_ms,
            retries=d.retries,
            max_repetitions=d.max_repetitions,
            poll_interval_s=d.poll_interval_s,
            snmp_context=d.snmp_context,
            ssh_credential_id=str(d.ssh_credential_id) if d.ssh_credential_id else None,
            ssh_port=d.ssh_port,
            ssh_allow_legacy=d.ssh_allow_legacy,
            backup_enabled=d.backup_enabled,
            ssh_host_fingerprint=_fingerprint(d.ssh_host_key),
        )
    return out


def _fingerprint(key: str | None) -> str | None:
    if not key:
        return None
    try:
        return str(asyncssh.import_public_key(key).get_fingerprint("sha256"))
    except (asyncssh.KeyImportError, ValueError):
        return "illisible"


async def _check_ip(db: Any, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    try:
        check_address(str(ip), await get_value(db, "snmp_allowed_cidrs"))
    except TargetNotAllowed:
        raise HTTPException(
            422, "Adresse de management refusée (hors des réseaux SNMP autorisés ou interdite)"
        ) from None


async def _check_refs(
    db: Any, site_id: uuid.UUID | None, credential_id: uuid.UUID | None, ssh_credential_id: uuid.UUID | None = None
) -> None:
    if (
        ssh_credential_id
        and (await db.execute(select(SshCredentialRow.id).where(SshCredentialRow.id == ssh_credential_id))).first()
        is None
    ):
        raise HTTPException(422, "Profil SSH inconnu")
    if site_id and (await db.execute(select(Site.id).where(Site.id == site_id))).first() is None:
        raise HTTPException(422, "Site inconnu")
    if (
        credential_id
        and (await db.execute(select(SnmpCredentialRow.id).where(SnmpCredentialRow.id == credential_id))).first()
        is None
    ):
        raise HTTPException(422, "Profil d'identifiants inconnu")


async def _extras(db: Any, ids: list[uuid.UUID]) -> dict[uuid.UUID, dict[str, Any]]:
    """Compteurs de ports (up / down / total) et version SNMP : affichage seulement, aucune donnée sensible."""
    out: dict[uuid.UUID, dict[str, Any]] = {
        i: {"ports_up": 0, "ports_down": 0, "ports_total": 0, "snmp_version": None} for i in ids
    }
    up = func.count(case((Interface.oper_status == 1, 1)))
    for dev_id, total, n_up in (
        await db.execute(
            select(Interface.device_id, func.count(), up)
            .where(Interface.device_id.in_(ids))
            .group_by(Interface.device_id)
        )
    ).all():
        out[dev_id].update(ports_total=total, ports_up=n_up, ports_down=total - n_up)
    for dev_id, version in (
        await db.execute(
            select(Device.id, SnmpCredentialRow.version)
            .join(SnmpCredentialRow, SnmpCredentialRow.id == Device.credential_id)
            .where(Device.id.in_(ids))
        )
    ).all():
        out[dev_id]["snmp_version"] = version
    return out


@router.get("")
async def list_devices(db: DbSession, p: Reader) -> list[dict[str, Any]]:
    rows = list((await db.execute(select(Device).order_by(Device.name).limit(5000))).scalars())
    extras = await _extras(db, [d.id for d in rows])
    return [{**_view(d, p.role == Role.admin), **extras[d.id]} for d in rows]


@router.get("/{device_id}")
async def get_device(device_id: uuid.UUID, db: DbSession, p: Reader) -> dict[str, Any]:
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if d is None:
        raise HTTPException(404, "Introuvable")
    return {**_view(d, p.role == Role.admin), **(await _extras(db, [d.id]))[d.id]}


@router.post("", status_code=201)
async def create_device(body: DeviceIn, request: Request, db: DbSession, p: Writer) -> dict[str, Any]:
    await _check_ip(db, body.mgmt_ip)
    await _check_refs(db, body.site_id, body.credential_id, body.ssh_credential_id)
    d = Device(**{**body.model_dump(), "mgmt_ip": str(body.mgmt_ip)})
    db.add(d)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Nom ou adresse déjà utilisés") from None
    await record(
        db,
        request,
        "device.create",
        principal=p,
        target_type="device",
        target_id=str(d.id),
        details={"name": d.name, "mgmt_ip": str(d.mgmt_ip), "role": d.role},
    )
    await db.commit()
    return _view(d, True)


@router.put("/{device_id}")
async def update_device(
    device_id: uuid.UUID, body: DeviceUpdate, request: Request, db: DbSession, p: Writer
) -> dict[str, Any]:
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if d is None:
        raise HTTPException(404, "Introuvable")
    changes = body.model_dump(exclude_unset=True)
    if "mgmt_ip" in changes and changes["mgmt_ip"] is not None:
        await _check_ip(db, changes["mgmt_ip"])
        changes["mgmt_ip"] = str(changes["mgmt_ip"])
    await _check_refs(db, changes.get("site_id"), changes.get("credential_id"), changes.get("ssh_credential_id"))
    if "mgmt_ip" in changes and changes["mgmt_ip"] != str(d.mgmt_ip):
        d.ssh_host_key = None  # autre adresse = autre équipement : l'empreinte doit être revalidée
    for k, v in changes.items():
        if v is None and k not in ("site_id",):
            continue
        setattr(d, k, v)
    try:
        await record(
            db,
            request,
            "device.update",
            principal=p,
            target_type="device",
            target_id=str(d.id),
            details={"changed_fields": sorted(changes)},
        )
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Nom ou adresse déjà utilisés") from None
    return _view(d, True)


@router.delete("/{device_id}", status_code=204)
async def delete_device(device_id: uuid.UUID, request: Request, db: DbSession, p: Writer) -> None:
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if d is None:
        raise HTTPException(404, "Introuvable")
    await db.execute(update(Endpoint).where(Endpoint.device_id == d.id).values(active=False))
    await db.delete(d)
    await record(
        db,
        request,
        "device.delete",
        principal=p,
        target_type="device",
        target_id=str(device_id),
        details={"name": d.name, "mgmt_ip": str(d.mgmt_ip)},
    )
    await db.commit()


@router.post("/{device_id}/test", status_code=202)
async def test_device(device_id: uuid.UUID, request: Request, db: DbSession, p: Writer) -> dict[str, str]:
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if d is None:
        raise HTTPException(404, "Introuvable")
    job = await create_and_dispatch(request, db, p, "device_test", {"device_id": str(d.id)})
    await record(
        db,
        request,
        "device.test",
        principal=p,
        target_type="device",
        target_id=str(d.id),
        details={"job_id": str(job.id)},
    )
    await db.commit()
    return {"job_id": str(job.id)}


_ = Job
