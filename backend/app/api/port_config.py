# ruff: noqa: E501  (messages d'aide affichés à l'utilisateur)
"""Modification d'un port (VLAN d'accès, PVID/VLAN natif, mode accès/trunk) : aperçu obligatoire puis application.

Super admin uniquement ; désactivé par défaut (réglage `port_config_enabled`). Voir `services/port_config.py`."""

from __future__ import annotations

import json
import secrets
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.db.models import Device, DeviceVlan, Interface, Neighbor
from app.deps import DbSession, require
from app.security.audit import record
from app.security.ratelimit import hit
from app.security.rbac import Perm, Principal
from app.services import port_config as pc
from app.services.jobs import create_and_dispatch
from app.services.settings_store import all_values

router = APIRouter(prefix="/api/v1", tags=["port-config"])
Admin = Annotated[Principal, Depends(require(Perm.ports_configure))]
PLAN_TTL = 600
Vlan = Annotated[int, Field(ge=1, le=4094)]


class ChangeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Annotated[str, Field(pattern=r"^(access|trunk)$")]
    access_vlan: Vlan | None = None
    native_vlan: Vlan | None = None
    allowed_vlans: Annotated[list[Vlan], Field(max_length=pc.MAX_VLANS_IN_TRUNK)] = []
    save: bool = True


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan_id: Annotated[str, Field(min_length=20, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]
    acknowledge: Annotated[str | None, Field(max_length=128)] = None


async def _load(db: DbSession, interface_id: uuid.UUID) -> tuple[Interface, Device, dict[int, str]]:
    iface = (await db.execute(select(Interface).where(Interface.id == interface_id))).scalar_one_or_none()
    if iface is None:
        raise HTTPException(404, "Introuvable")
    dev = (await db.execute(select(Device).where(Device.id == iface.device_id))).scalar_one()
    vlans = {
        v.vlan_id: v.name
        for v in (await db.execute(select(DeviceVlan).where(DeviceVlan.device_id == dev.id))).scalars()
    }
    return iface, dev, vlans


async def _require_enabled(db: DbSession) -> dict[str, Any]:
    cfg = await all_values(db)
    if not cfg["port_config_enabled"]:
        raise HTTPException(
            409,
            "La modification des ports est désactivée : un super admin doit activer « port_config_enabled » dans Paramètres.",
        )
    return cfg


def _change(body: ChangeIn) -> pc.PortChange:
    return pc.PortChange(
        mode=body.mode,
        access_vlan=body.access_vlan,
        native_vlan=body.native_vlan,
        allowed_vlans=tuple(sorted(set(body.allowed_vlans))),
        save=body.save,
    )


@router.get("/devices/{device_id}/vlans")
async def device_vlans(device_id: uuid.UUID, db: DbSession, _: Admin) -> list[dict[str, Any]]:
    rows = (
        await db.execute(select(DeviceVlan).where(DeviceVlan.device_id == device_id).order_by(DeviceVlan.vlan_id))
    ).scalars()
    return [{"id": v.vlan_id, "name": v.name} for v in rows]


@router.post("/interfaces/{interface_id}/port-config/preview")
async def preview(interface_id: uuid.UUID, body: ChangeIn, request: Request, db: DbSession, p: Admin) -> dict[str, Any]:
    cfg = await _require_enabled(db)
    iface, dev, vlans = await _load(db, interface_id)
    change = _change(body)
    syntax = pc.variant(dev.driver, dev.sys_object_id)
    if syntax is None:
        raise HTTPException(422, "La modification des ports n'est pas prise en charge pour ce type d'équipement.")
    if dev.ssh_credential_id is None or not dev.ssh_host_key:
        raise HTTPException(
            422,
            "Cet équipement n'a pas d'accès SSH approuvé : choisissez un profil SSH et approuvez l'empreinte (fiche équipement).",
        )
    current = pc.PortState(iface.port_mode, iface.pvid, tuple(iface.tagged_vlans or ()))
    try:
        pc.validate_change(change, set(vlans))
        if pc.same_as_current(current, change):
            raise pc.PortConfigError("Aucun changement : le port est déjà dans cet état.")
        port_id = _port_id(syntax, iface)
        neighbors = (await db.execute(select(Neighbor).where(Neighbor.interface_id == iface.id))).scalars().all()
        alerts = pc.assess(
            port_name=iface.name,
            current=current,
            change=change,
            role=iface.role_override or iface.role_detected,
            is_trunk=iface.is_trunk,
            neighbor_names=[n.remote_sysname or n.remote_chassis_id for n in neighbors if n.remote_is_network_device],
            mac_count=iface.mac_count,
            mac_threshold=cfg["uplink_mac_threshold"],
            device_role=dev.role,
        )
        plan = pc.make_plan(syntax, port_id, current, change, alerts=alerts)
    except pc.PortConfigError as exc:
        raise HTTPException(422, str(exc)) from None
    token = secrets.token_urlsafe(32)
    stored = {
        "user": str(p.user_id),
        "interface": str(iface.id),
        "change": {
            "mode": change.mode,
            "access_vlan": change.access_vlan,
            "native_vlan": change.native_vlan,
            "allowed_vlans": list(change.allowed_vlans),
            "save": change.save,
        },
        "digest": plan.digest(),
        "commands": plan.commands + plan.save_commands,
        "requires_ack": plan.requires_ack,
    }
    await request.app.state.redis.set(f"portcfg:{token}", json.dumps(stored), ex=PLAN_TTL)
    await record(
        db,
        request,
        "port_config.preview",
        principal=p,
        target_type="interface",
        target_id=str(iface.id),
        details={"device": dev.name, "port": iface.name, "commands": stored["commands"], "danger": plan.requires_ack},
    )
    await db.commit()
    return {
        "plan_id": token,
        "device": {"id": str(dev.id), "name": dev.name, "role": dev.role},
        "port": {"id": str(iface.id), "name": iface.name},
        "current": {"mode": current.mode, "pvid": current.pvid, "tagged": list(current.tagged)},
        "desired": stored["change"],
        "commands": plan.commands,
        "save_commands": plan.save_commands,
        "alerts": [{"level": a.level, "text": a.text} for a in plan.alerts],
        "requires_ack": plan.requires_ack,
        "ack_phrase": iface.name if plan.requires_ack else None,
        "expires_in": PLAN_TTL,
    }


def _port_id(syntax: str, iface: Interface) -> str:
    from app.services.port_config_job import _port_id as port_id

    return port_id(syntax, iface)


@router.post("/interfaces/{interface_id}/port-config/apply", status_code=202)
async def apply(interface_id: uuid.UUID, body: ApplyIn, request: Request, db: DbSession, p: Admin) -> dict[str, str]:
    await _require_enabled(db)
    ok, retry = await hit(request.app.state.redis, f"portcfg:{p.user_id}", 10, 60)
    if not ok:
        raise HTTPException(429, "Trop de modifications de ports", headers={"Retry-After": str(retry)})
    raw = await request.app.state.redis.getdel(f"portcfg:{body.plan_id}")  # usage unique
    if raw is None:
        raise HTTPException(409, "Aperçu expiré ou déjà utilisé : refaites l'aperçu.")
    plan = json.loads(raw)
    if plan["user"] != str(p.user_id) or plan["interface"] != str(interface_id):
        raise HTTPException(403, "Cet aperçu ne vous appartient pas ou concerne un autre port.")
    iface, dev, _ = await _load(db, interface_id)
    if plan["requires_ack"] and (body.acknowledge or "").strip() != iface.name:
        # l'aperçu est consommé : on oblige à le refaire plutôt que d'accepter une confirmation approximative
        raise HTTPException(
            422, f"Confirmation manquante : saisissez exactement le nom du port « {iface.name} ». Refaites l'aperçu."
        )
    params = {
        **plan["change"],
        "interface_id": str(iface.id),
        "digest": plan["digest"],
        "by": p.label,
    }

    async def audit(job: Any) -> None:
        await record(
            db,
            request,
            "port_config.apply",
            principal=p,
            target_type="interface",
            target_id=str(iface.id),
            details={
                "job_id": str(job.id),
                "device": dev.name,
                "port": iface.name,
                "from": {"mode": iface.port_mode, "pvid": iface.pvid, "tagged": iface.tagged_vlans},
                "to": plan["change"],
                "commands": plan["commands"],
                "acknowledged": bool(plan["requires_ack"]),
            },
        )

    job = await create_and_dispatch(request, db, p, "port_config", params, audit=audit)
    return {"job_id": str(job.id)}
