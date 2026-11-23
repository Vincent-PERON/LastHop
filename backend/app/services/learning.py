"""IP/MAC Learning : enregistrement ARP/FDB, corrélation en endpoints, historique des changements."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, insert, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ArpEntry, Device, Endpoint, EndpointHistory, FdbEntry, Interface
from app.drivers.models import ArpInfo, FdbInfo

LEARNING_LOCK = 727276


async def persist_learning(
    db: AsyncSession, device: Device, arp: list[ArpInfo] | None, fdb: list[FdbInfo] | None
) -> dict[str, int]:
    """Remplace les tables ARP/FDB de l'équipement puis recorrèle les MAC concernées. Un échec de collecte ne doit
    jamais arriver ici : une collecte partielle ne doit pas faire « disparaître » des endpoints."""
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": LEARNING_LOCK})
    now = datetime.now(UTC)
    macs: set[str] = set()
    stats = {"arp": 0, "fdb": 0}

    if arp is not None:
        macs |= {
            str(m) for m in (await db.execute(select(ArpEntry.mac).where(ArpEntry.device_id == device.id))).scalars()
        }
        await db.execute(delete(ArpEntry).where(ArpEntry.device_id == device.id))
        rows = {(a.ip, a.mac): a for a in arp}
        if rows:
            await db.execute(
                insert(ArpEntry),
                [
                    {"device_id": device.id, "ip": a.ip, "mac": a.mac, "vlan": a.vlan, "last_seen": now}
                    for a in rows.values()
                ],
            )
        macs |= {a.mac for a in rows.values()}
        stats["arp"] = len(rows)

    if fdb is not None:
        ifaces = {
            i.if_index: i
            for i in (await db.execute(select(Interface).where(Interface.device_id == device.id))).scalars()
        }
        macs |= {
            str(m) for m in (await db.execute(select(FdbEntry.mac).where(FdbEntry.device_id == device.id))).scalars()
        }
        await db.execute(delete(FdbEntry).where(FdbEntry.device_id == device.id))
        keep: dict[tuple[str, int | None], dict[str, Any]] = {}
        for e in fdb:
            iface = ifaces.get(e.if_index)
            # Entrées des ports uplink non conservées : le MAC n'y est que « de passage » (exclusion des uplinks)
            if (
                iface is None
                or iface.role_override == "uplink"
                or (iface.role_override is None and iface.role_detected == "uplink")
            ):
                continue
            keep[(e.mac, e.vlan)] = {
                "device_id": device.id,
                "interface_id": iface.id,
                "mac": e.mac,
                "vlan": e.vlan,
                "last_seen": now,
            }
        if keep:
            await db.execute(insert(FdbEntry), list(keep.values()))
        macs |= {m for m, _ in keep}
        stats["fdb"] = len(keep)

    stats.update(await correlate(db, macs, now))
    return stats


def _where(ep: Endpoint) -> dict[str, Any]:
    return {
        "device": ep.device_name,
        "port": ep.port_name,
        "vlan": ep.vlan,
        "ip": str(ep.ip) if ep.ip is not None else None,
    }


async def correlate(db: AsyncSession, macs: set[str], now: datetime) -> dict[str, int]:
    counts = {"appeared": 0, "moved": 0, "ip_changed": 0, "vlan_changed": 0, "disappeared": 0}
    if not macs:
        return counts
    mac_list = sorted(macs)
    best: dict[str, tuple[FdbEntry, Interface, str]] = {}
    fdb_rows = (
        await db.execute(
            select(FdbEntry, Interface, Device.name)
            .join(Interface, Interface.id == FdbEntry.interface_id)
            .join(Device, Device.id == FdbEntry.device_id)
            .where(FdbEntry.mac.in_(mac_list))
        )
    ).all()
    for f, i, dname in fdb_rows:
        if (i.role_override or i.role_detected) == "uplink":
            continue
        cur = best.get(str(f.mac))
        # observation la plus récente ; à égalité, le port le moins chargé (le plus proche du poste)
        if cur is None or (f.last_seen, -i.mac_count) > (cur[0].last_seen, -cur[1].mac_count):
            best[str(f.mac)] = (f, i, dname)

    ips: dict[str, list[str]] = defaultdict(list)
    for a in (
        await db.execute(
            select(ArpEntry).where(ArpEntry.mac.in_(mac_list)).order_by(ArpEntry.last_seen.desc(), ArpEntry.ip)
        )
    ).scalars():
        if str(a.ip) not in ips[str(a.mac)]:
            ips[str(a.mac)].append(str(a.ip))

    existing: dict[str, list[Endpoint]] = defaultdict(list)
    for ep in (await db.execute(select(Endpoint).where(Endpoint.mac.in_(mac_list)))).scalars():
        existing[str(ep.mac)].append(ep)

    def log(ep: Endpoint, change: str, old: dict[str, Any] | None, new: dict[str, Any] | None) -> None:
        db.add(EndpointHistory(endpoint_id=ep.id, ts=now, change=change, old=old, new=new))
        counts[change] += 1

    for mac in mac_list:
        eps = existing.get(mac, [])
        if mac not in best:  # plus visible sur un port d'accès
            for ep in eps:
                if ep.active:
                    ep.active = False
                    log(ep, "disappeared", _where(ep), None)
            continue
        f, iface, dname = best[mac]
        desired: list[str | None] = list(ips.get(mac) or [])
        if not desired:
            # Plus d'entrée ARP (vieillissement) mais la MAC est toujours vue : on conserve la dernière IP connue
            known = sorted((e for e in eps if e.ip is not None), key=lambda e: e.last_seen, reverse=True)
            actives = [e for e in known if e.active]
            desired = [str(e.ip) for e in (actives or known[:1])] or [None]
        by_ip = {(str(e.ip) if e.ip is not None else None): e for e in eps}
        leftover_old = [e for e in eps if (str(e.ip) if e.ip is not None else None) not in desired]
        for ip in desired:
            cur_ep = by_ip.get(ip)
            if cur_ep is None and leftover_old:  # même MAC, autre IP : changement d'adresse
                changed_ep = leftover_old.pop(0)
                before = _where(changed_ep)
                changed_ep.ip = ip
                _relocate(changed_ep, f, iface, dname, now)
                log(changed_ep, "ip_changed", before, _where(changed_ep))
                continue
            if cur_ep is None:
                new_ep = Endpoint(
                    id=uuid.uuid4(), mac=mac, ip=ip, first_seen=f.last_seen, last_seen=f.last_seen, active=True
                )
                _relocate(new_ep, f, iface, dname, now)
                db.add(new_ep)
                await db.flush()
                log(new_ep, "appeared", None, _where(new_ep))
                continue
            before = _where(cur_ep)
            was_active = cur_ep.active
            moved = (cur_ep.device_id, cur_ep.interface_id) != (iface.device_id, iface.id)
            vlan_changed = cur_ep.vlan != f.vlan
            _relocate(cur_ep, f, iface, dname, now)
            if not was_active:
                log(cur_ep, "appeared", before, _where(cur_ep))
            elif moved:
                log(cur_ep, "moved", before, _where(cur_ep))
            elif vlan_changed:
                log(cur_ep, "vlan_changed", before, _where(cur_ep))
        for stale in leftover_old:  # IP qui n'est plus associée à cette MAC
            if stale.active:
                stale.active = False
                log(stale, "disappeared", _where(stale), None)
    await db.flush()
    return counts


def _relocate(ep: Endpoint, f: FdbEntry, iface: Interface, dname: str, now: datetime) -> None:
    ep.device_id, ep.interface_id, ep.vlan = iface.device_id, iface.id, f.vlan
    ep.device_name, ep.port_name = dname, iface.name
    ep.last_seen, ep.active = f.last_seen, True
