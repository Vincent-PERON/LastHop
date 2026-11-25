"""Topologie L2 : enregistrement des interfaces/voisins, corrélation LLDP/CDP ↔ inventaire, rôles des ports, graphe."""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Device, DeviceVlan, Interface, Neighbor
from app.drivers.models import TopologySnapshot

TOPOLOGY_LOCK = (
    727275  # sérialise l'écriture/la corrélation entre jobs concurrents (la collecte SNMP, elle, est parallèle)
)

_ABBREV = [
    (r"^(?:gi|gig|ge)(?=\d)", "gigabitethernet"),
    (r"^(?:xge|te)(?=\d)", "tengigabitethernet"),
    (r"^fa(?=\d)", "fastethernet"),
    (r"^eth(?=\d)", "ethernet"),
    (r"^po(?=\d)", "port-channel"),
    (r"^bagg(?=\d)", "bridge-aggregation"),
    (r"^twe(?=\d)", "twentyfivegige"),
    (r"^hu(?=\d)", "hundredgige"),
    (r"^fo(?=\d)", "fortygigabitethernet"),
]


def norm_ifname(name: str) -> str:
    n = name.strip().lower()
    for pat, repl in _ABBREV:
        n, k = re.subn(pat, repl, n)
        if k:
            break
    return n


def first_label(host: str) -> str:
    return host.strip().lower().split(".", 1)[0]


def compute_role(*, network_neighbor: str | None, is_trunk: bool, mac_count: int, threshold: int) -> tuple[str, str]:
    """Rôle détecté d'un port. Ordre : voisin réseau (LLDP/CDP) > trunk 802.1Q > trop de MAC > accès."""
    if network_neighbor:
        return "uplink", f"{network_neighbor}_neighbor"
    if is_trunk:
        return "uplink", "trunk"
    if mac_count > threshold:
        return "uplink", "mac_count"
    return "access", "none"


# --------------------------------------------------------------------------- enregistrement


async def persist_snapshot(db: AsyncSession, device: Device, snap: TopologySnapshot) -> dict[str, int]:
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": TOPOLOGY_LOCK})
    now = datetime.now(UTC)
    device.chassis_mac = snap.chassis_mac
    if snap.sys_name:  # indispensable à la corrélation CDP (identifiant = nom d'hôte)
        device.sys_name = snap.sys_name
    device.last_topology_at, device.last_topology_status = now, "ok"

    existing = {
        i.if_index: i for i in (await db.execute(select(Interface).where(Interface.device_id == device.id))).scalars()
    }
    seen: set[int] = set()
    for info in snap.interfaces:
        row = existing.get(info.if_index) or Interface(device_id=device.id, if_index=info.if_index, name=info.name)
        row.name, row.descr, row.alias = info.name, info.descr or None, info.alias or None
        row.if_type, row.oper_status, row.bridge_port = info.if_type, info.oper_status, info.bridge_port
        row.is_trunk = info.if_index in snap.trunk_if_indexes
        pv = snap.port_vlans.get(info.if_index)
        row.pvid, row.port_mode = (pv.pvid, pv.mode) if pv else (None, None)
        row.tagged_vlans = list(pv.tagged) if pv else []
        row.mac_count = snap.mac_counts.get(info.if_index, 0)
        row.updated_at = now
        if info.if_index not in existing:
            db.add(row)
            existing[info.if_index] = row
        seen.add(info.if_index)
    await db.execute(delete(DeviceVlan).where(DeviceVlan.device_id == device.id))
    for vid, vname in snap.vlans.items():
        db.add(DeviceVlan(device_id=device.id, vlan_id=vid, name=vname))
    for idx in set(existing) - seen:  # interfaces disparues (le surcharge manuel disparaît avec elles)
        await db.delete(existing.pop(idx))
    await db.flush()

    old = {
        (n.interface_id, n.protocol, n.remote_chassis_id, n.remote_port_id): n
        for n in (await db.execute(select(Neighbor).where(Neighbor.device_id == device.id))).scalars()
    }
    keep: set[tuple[uuid.UUID, str, str, str]] = set()
    for nb in snap.neighbors:
        iface = existing.get(nb.local_if_index)
        if iface is None:
            continue
        key = (iface.id, nb.protocol, nb.remote_chassis_id, nb.remote_port_id)
        if key in keep:
            continue
        keep.add(key)
        nrow = old.get(key) or Neighbor(
            device_id=device.id,
            interface_id=iface.id,
            protocol=nb.protocol,
            remote_chassis_id=nb.remote_chassis_id,
            remote_port_id=nb.remote_port_id,
        )
        nrow.remote_port_desc, nrow.remote_sysname = nb.remote_port_desc or None, nb.remote_sysname or None
        nrow.remote_sysdescr, nrow.remote_ip = nb.remote_sysdescr or None, nb.remote_ip
        nrow.remote_is_network_device, nrow.last_seen = nb.is_network_device, now
        if key not in old:
            db.add(nrow)
    for key, n in old.items():
        if key not in keep:
            await db.delete(n)
    await db.flush()

    changed = await reconcile(db, device.id)
    for dev_id in changed | {device.id}:
        await recompute_roles(db, dev_id)
    return {"interfaces": len(seen), "neighbors": len(keep)}


# --------------------------------------------------------------------------- corrélation


async def reconcile(db: AsyncSession, polled_device_id: uuid.UUID) -> set[uuid.UUID]:
    """Associe chaque voisin à un équipement/port de l'inventaire. Unicité exigée : en cas d'ambiguïté, pas de lien."""
    devices = (await db.execute(select(Device))).scalars().all()
    by_chassis: dict[str, list[uuid.UUID]] = defaultdict(list)
    by_name: dict[str, list[uuid.UUID]] = defaultdict(list)
    by_ip: dict[str, list[uuid.UUID]] = defaultdict(list)
    for d in devices:
        if d.chassis_mac:
            by_chassis[str(d.chassis_mac).lower()].append(d.id)
        for nm in {n for n in (d.sys_name, d.name) if n}:
            by_name[nm.lower()].append(d.id)
            by_name[first_label(nm)].append(d.id)
        by_ip[str(d.mgmt_ip)].append(d.id)
    iface_keys: dict[uuid.UUID, dict[str, uuid.UUID]] = defaultdict(dict)
    for i in (await db.execute(select(Interface))).scalars():
        for k in (i.name, i.descr, i.alias):
            if k:
                iface_keys[i.device_id].setdefault(norm_ifname(k), i.id)

    def unique(cands: list[uuid.UUID], exclude: uuid.UUID) -> uuid.UUID | None:
        s = {c for c in cands if c != exclude}
        return next(iter(s)) if len(s) == 1 else None

    todo = (
        await db.execute(
            select(Neighbor).where(
                (Neighbor.device_id == polled_device_id)
                | Neighbor.matched_device_id.is_(None)
                | Neighbor.matched_interface_id.is_(None)
            )
        )
    ).scalars()
    changed: set[uuid.UUID] = set()
    for n in todo:
        target = (
            unique(by_chassis.get(n.remote_chassis_id.lower(), []), n.device_id)
            or (unique(by_ip.get(str(n.remote_ip), []), n.device_id) if n.remote_ip else None)
            or (unique(by_name.get(first_label(n.remote_sysname), []), n.device_id) if n.remote_sysname else None)
        )
        port = None
        if target:
            keys = iface_keys.get(target, {})
            for cand in (n.remote_port_id, n.remote_port_desc or ""):
                if cand and norm_ifname(cand) in keys:
                    port = keys[norm_ifname(cand)]
                    break
        if (n.matched_device_id, n.matched_interface_id) != (target, port):
            n.matched_device_id, n.matched_interface_id = target, port
            changed.update({n.device_id} | ({target} if target else set()))
    await db.flush()
    return changed


async def recompute_roles(db: AsyncSession, device_id: uuid.UUID) -> None:
    from app.services.settings_store import all_values

    cfg = await all_values(db)
    threshold = int(cfg["uplink_mac_threshold"])
    ifs = (await db.execute(select(Interface).where(Interface.device_id == device_id))).scalars().all()
    proto_by_if: dict[uuid.UUID, str] = {}
    for n in (await db.execute(select(Neighbor).where(Neighbor.device_id == device_id))).scalars():
        if n.matched_device_id is not None or n.remote_is_network_device:
            proto_by_if.setdefault(n.interface_id, n.protocol)
    for i in ifs:
        role, reason = compute_role(
            network_neighbor=proto_by_if.get(i.id), is_trunk=i.is_trunk, mac_count=i.mac_count, threshold=threshold
        )
        if (i.role_detected, i.role_reason) != (role, reason):
            i.role_detected, i.role_reason = role, reason
    await db.flush()


async def purge_neighbors_of(db: AsyncSession, device_id: uuid.UUID) -> None:
    await db.execute(delete(Neighbor).where(Neighbor.device_id == device_id))


# --------------------------------------------------------------------------- graphe


def build_graph(
    devices: list[Device],
    interfaces: dict[uuid.UUID, Interface],
    neighbors: list[Neighbor],
    include_unmanaged: bool = False,
) -> dict[str, Any]:
    dev_by_id = {d.id: d for d in devices}
    nodes = [
        {
            "id": str(d.id),
            "label": d.sys_name or d.name,
            "name": d.name,
            "role": d.role,
            "driver": d.driver,
            "vendor": d.vendor,
            "model": d.model,
            "site_id": str(d.site_id) if d.site_id else None,
            "managed": True,
        }
        for d in devices
    ]
    keys: dict[Any, dict[str, Any]] = {}

    def port_name(i: uuid.UUID | None) -> str | None:
        return interfaces[i].name if i in interfaces else None

    for n in neighbors:
        if n.device_id not in dev_by_id or n.interface_id not in interfaces:
            continue
        if n.matched_device_id and n.matched_device_id in dev_by_id:
            a = (n.device_id, n.interface_id)
            b = (n.matched_device_id, n.matched_interface_id)
            key = tuple(sorted([a, b], key=lambda x: (str(x[0]), str(x[1]))))
            e = keys.setdefault(key, {"a": a, "b": b, "protocols": set(), "last_seen": n.last_seen})
            e["protocols"].add(n.protocol)
            e["last_seen"] = max(e["last_seen"], n.last_seen)
        elif include_unmanaged and n.remote_is_network_device:
            ext = f"ext:{n.remote_chassis_id}"
            if not any(x["id"] == ext for x in nodes):
                nodes.append(
                    {
                        "id": ext,
                        "label": n.remote_sysname or n.remote_chassis_id,
                        "name": n.remote_sysname,
                        "role": None,
                        "managed": False,
                    }
                )
            ukey: Any = ((n.device_id, n.interface_id), (ext, None))
            e = keys.setdefault(
                ukey,
                {"a": (n.device_id, n.interface_id), "b": (ext, None), "protocols": set(), "last_seen": n.last_seen},
            )
            e["protocols"].add(n.protocol)
    # une liaison vue d'un seul côté (port distant non résolu) disparaît si l'autre côté l'a vue avec le port
    full = {frozenset([x[0] for x in k] + [x[1] for x in k]) for k, e in keys.items() if e["b"][1] is not None}
    edges = []
    for k, e in keys.items():
        if e["b"][1] is None and isinstance(e["b"][0], uuid.UUID):
            if any(e["a"][1] in f and e["b"][0] in f for f in full):
                continue
        a_dev, a_if = e["a"]
        b_dev, b_if = e["b"]
        edges.append(
            {
                "id": str(uuid.uuid5(uuid.NAMESPACE_URL, repr(k))),
                "source": str(a_dev),
                "target": str(b_dev),
                "source_port": port_name(a_if),
                "target_port": port_name(b_if),
                "source_port_role": interfaces[a_if].role_override or interfaces[a_if].role_detected
                if a_if in interfaces
                else None,
                "protocols": sorted(e["protocols"]),
                "last_seen": e["last_seen"].isoformat(),
            }
        )
    return {"nodes": nodes, "edges": edges}
