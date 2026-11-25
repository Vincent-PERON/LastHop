# ruff: noqa: E501  (messages d'aide affichés à l'utilisateur, volontairement lisibles tels quels)
"""Exécution (worker) d'une modification de port : revalidation complète, puis commandes par SSH."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Device, DeviceVlan, Interface, SshCredentialRow
from app.security.audit import record
from app.security.crypto import KeyRing
from app.security.targets import TargetNotAllowed, check_address
from app.services import cli, port_config
from app.services.backup_messages import human
from app.services.settings_store import all_values
from app.services.ssh_backup import BackupError, CliSession, _connect, unseal_secret

log = logging.getLogger("lasthop.portconfig")

HUMAN_EXTRA = {
    "PORT_CONFIG_DISABLED": (
        "La modification des ports est désactivée.",
        "Un super admin doit l'activer dans Paramètres (port_config_enabled).",
    ),
    "STATE_CHANGED": (
        "Le port a changé depuis l'aperçu : rien n'a été envoyé.",
        "Relancez une collecte de topologie puis refaites l'aperçu avant d'appliquer.",
    ),
    "COMMAND_REJECTED": (
        "L'équipement a refusé une commande : la modification s'est arrêtée là et la configuration n'a PAS été enregistrée.",
        "Lisez le message de l'équipement ci-dessous. Une partie des commandes précédentes a pu être appliquée : "
        "vérifiez le port, ou revenez à la sauvegarde de configuration.",
    ),
    "VALIDATION": ("La demande n'est plus valable.", "Refaites l'aperçu."),
}


def _explain(code: str) -> tuple[str, str]:
    return HUMAN_EXTRA.get(code) or human(code)


def change_from_params(p: dict[str, Any]) -> port_config.PortChange:
    return port_config.PortChange(
        mode=p["mode"],
        access_vlan=p.get("access_vlan"),
        native_vlan=p.get("native_vlan"),
        allowed_vlans=tuple(p.get("allowed_vlans") or ()),
        save=bool(p.get("save", True)),
    )


async def run_port_config(db: AsyncSession, keyring: KeyRing, params: dict[str, Any]) -> dict[str, Any]:
    iface = (await db.execute(select(Interface).where(Interface.id == uuid.UUID(params["interface_id"])))).scalar_one()
    dev = (await db.execute(select(Device).where(Device.id == iface.device_id))).scalar_one()
    steps: list[dict[str, str]] = []

    async def finish(code: str | None, detail: str = "", saved: bool = False) -> dict[str, Any]:
        what, advice = _explain(code) if code else ("Modification appliquée.", "")
        await record(
            db,
            None,
            "port_config.result",
            actor_type="user",
            actor_label=params.get("by"),
            target_type="interface",
            target_id=str(iface.id),
            outcome="failure" if code else "success",
            details={
                "device": dev.name,
                "port": iface.name,
                "commands": [s["command"] for s in steps],
                "saved": saved,
                "error": code,
            },
        )
        await db.commit()
        return {
            "ok": code is None,
            "error_code": code,
            "message": what,
            "advice": advice,
            "detail": detail[:600],
            "steps": steps,
            "saved": saved,
            "device": dev.name,
            "port": iface.name,
        }

    cfg = await all_values(db)
    if not cfg["port_config_enabled"]:
        return await finish("PORT_CONFIG_DISABLED")
    try:
        check_address(str(dev.mgmt_ip), cfg["snmp_allowed_cidrs"])
    except TargetNotAllowed:
        return await finish("TARGET_NOT_ALLOWED")
    syntax = port_config.variant(dev.driver, dev.sys_object_id)
    profile = cli.PROFILES.get(dev.driver)
    if syntax is None or profile is None:
        return await finish("UNSUPPORTED_DRIVER")
    if dev.ssh_credential_id is None:
        return await finish("NO_SSH_PROFILE")
    if not dev.ssh_host_key:
        return await finish("SSH_HOSTKEY_UNKNOWN")

    # Revalidation complète : VLAN connus, mêmes commandes qu'à l'aperçu (sinon l'état du port a changé)
    change = change_from_params(params)
    vlans = {v.vlan_id for v in (await db.execute(select(DeviceVlan).where(DeviceVlan.device_id == dev.id))).scalars()}
    current = port_config.PortState(iface.port_mode, iface.pvid, tuple(iface.tagged_vlans or ()))
    try:
        port_config.validate_change(change, vlans)
        port = _port_id(syntax, iface)
        plan = port_config.make_plan(syntax, port, current, change, alerts=[])
    except port_config.PortConfigError:
        return await finish("VALIDATION")
    if plan.digest() != params.get("digest"):
        return await finish("STATE_CHANGED")

    cred = (await db.execute(select(SshCredentialRow).where(SshCredentialRow.id == dev.ssh_credential_id))).scalar_one()
    conn = None
    try:
        conn = await _connect(dev, cred, unseal_secret(keyring, cred))
        sess = CliSession(conn, profile)
        await sess.open()
        if profile.needs_privilege(sess.prompt):
            return await finish("SSH_PRIVILEGE_REQUIRED")
        for pager in profile.pager_off:
            try:
                await sess.run_any(pager, 10)
            except BackupError:
                pass
        sequence = [(c, False) for c in plan.commands] + [(c, True) for c in plan.save_commands]
        saved = False
        for cmd, is_save in sequence:
            out = await sess.run_any(cmd, 60 if is_save else 20)
            steps.append({"command": cmd, "output": out[:300]})
            if cli.ERROR_MARKERS.search(out[:400]):
                for leave in port_config.PROFILES[syntax].exit:  # on quitte le mode configuration sans rien enregistrer
                    try:
                        await sess.run_any(leave, 10)
                    except BackupError:
                        pass
                return await finish("COMMAND_REJECTED", detail=f"{cmd} → {out[:300]}")
            saved = saved or is_save
        return await finish(None, saved=saved)
    except BackupError as exc:
        return await finish(exc.code, detail=exc.detail or "")
    finally:
        if conn is not None:
            conn.close()


def _port_id(syntax: str, iface: Interface) -> str:
    """Identifiant du port dans la CLI : nom complet (Cisco/Comware : ifDescr), numéro (ArubaOS-Switch), ifName (AOS-CX)."""
    if syntax in ("cisco_ios", "comware"):
        return iface.descr or iface.name
    return iface.name
