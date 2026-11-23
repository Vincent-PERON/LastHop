"""Real-Time Location : IP/MAC -> switch d'accès + port, par interrogation SNMP en direct (progression publiée)."""

from __future__ import annotations

import asyncio
import ipaddress
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy import cast, func, select
from sqlalchemy.dialects.postgresql import MACADDR
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ArpEntry,
    Device,
    Endpoint,
    EndpointHistory,
    FdbEntry,
    Interface,
    Neighbor,
    OuiEntry,
    SnmpCredentialRow,
)
from app.drivers.models import LiveHit
from app.drivers.registry import detect_driver, get_driver
from app.security.crypto import KeyRing
from app.security.targets import TargetNotAllowed, check_address
from app.services.credentials_store import to_snmp_credential
from app.services.macs import parse_mac_input, to_canonical
from app.services.settings_store import all_values
from app.snmp import oids
from app.snmp.client import SnmpClient, SnmpError, SnmpTarget

Publish = Callable[[str, dict[str, Any]], Awaitable[None]]

MESSAGES = {
    "NO_SWITCHES": "Aucun switch (L2) activé dans le périmètre demandé.",
    "GATEWAY_NOT_MANAGED": "Aucune passerelle (L3) gérée dans le périmètre : impossible de résoudre l'IP en MAC.",
    "IP_NOT_IN_ARP": "L'IP n'apparaît dans l'ARP d'aucune passerelle gérée (entrée expirée ou hôte silencieux).",
    "MAC_AGED_OUT": "La MAC n'est apprise sur aucun switch interrogé (entrée FDB expirée ou hôte éteint).",
    "DEVICE_UNREACHABLE": "Des équipements n'ont pas répondu : la MAC n'a pas pu être localisée de façon fiable.",
    "SNMP_AUTH_FAILURE": "Échec d'authentification SNMP sur des équipements : localisation incomplète.",
    "SNMP_ERROR": "Erreur SNMP sur des équipements : localisation incomplète.",
    "ACCESS_NOT_MANAGED": "La MAC est vue sur un uplink vers un équipement non géré : switch d'accès hors inventaire.",
    "TIMEOUT": "Délai global dépassé avant d'avoir pu localiser la MAC.",
    "INTERNAL_ERROR": "Erreur interne pendant la recherche.",
}


def parse_query(raw: str) -> tuple[str, str]:
    """Retourne (kind, valeur normalisée) : ('mac', 'aa:bb:...') ou ('ip', '10.0.0.1'). Lève ValueError sinon."""
    value = raw.strip()
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    return "mac", to_canonical(parse_mac_input(value))


@dataclass
class Hit:
    device_id: str
    device: str
    if_index: int | None
    port: str | None
    vlan: int | None
    role: str  # access | uplink | unknown
    mac_count: int
    is_self: bool
    neighbor_device_id: str | None
    neighbor_name: str | None


def build_chain(access_device_id: str, uplinks: list[Hit]) -> list[tuple[int, Hit]]:
    """Chaîne des uplinks menant au switch d'accès : parcours en largeur « à rebours » à partir de l'accès.
    Un hit uplink fait partie de la chaîne si son voisin est l'accès ou un autre maillon. Retour : (profondeur, hit),
    de la plus grande profondeur (côté cœur) vers l'accès."""
    depth = {access_device_id: 0}
    chain: dict[int, Hit] = {}
    queue: deque[str] = deque([access_device_id])
    while queue:
        cur = queue.popleft()
        for i, h in enumerate(uplinks):
            if i in chain or h.neighbor_device_id != cur or h.device_id in depth:
                continue
            depth[h.device_id] = depth[cur] + 1
            chain[i] = h
            queue.append(h.device_id)
    return sorted(((depth[h.device_id], h) for h in chain.values()), key=lambda t: (-t[0], t[1].device))


def _pick_error(errors: dict[str, str]) -> str:
    codes = set(errors.values())
    for c in ("DEVICE_UNREACHABLE", "SNMP_AUTH_FAILURE", "SNMP_ERROR"):
        if c in codes:
            return c
    return "SNMP_ERROR"


async def run_realtime(db: AsyncSession, keyring: KeyRing, params: dict[str, Any], publish: Publish) -> dict[str, Any]:
    cfg = await all_values(db)
    budget = int(cfg["realtime_timeout_s"])
    partial: dict[str, Any] = {"queried": [], "errors": {}}
    try:
        async with asyncio.timeout(budget):
            result = await _search(db, keyring, params, publish, cfg, partial)
    except TimeoutError:
        result = _fail("TIMEOUT", partial)
    except SnmpError as exc:
        result = _fail(exc.code, partial)
    await publish("located" if result.get("ok") else "failed", result)
    await publish("done", {"ok": bool(result.get("ok")), "error_code": result.get("error_code")})
    return result


def _fail(code: str, partial: dict[str, Any], extra: str | None = None) -> dict[str, Any]:
    msg = MESSAGES.get(code, code) + (f" {extra}" if extra else "")
    return {"ok": False, "error_code": code, "message": msg, "partial": partial}


async def _search(
    db: AsyncSession,
    keyring: KeyRing,
    params: dict[str, Any],
    publish: Publish,
    cfg: dict[str, Any],
    partial: dict[str, Any],
) -> dict[str, Any]:
    kind, value = params["kind"], params["value"]
    site_id = uuid.UUID(params["site_id"]) if params.get("site_id") else None
    started = time.monotonic()
    await publish("started", {"query": value, "kind": kind, "timeout_s": int(cfg["realtime_timeout_s"])})

    q = select(Device, SnmpCredentialRow).join(SnmpCredentialRow, SnmpCredentialRow.id == Device.credential_id)
    q = q.where(Device.enabled.is_(True))
    if site_id:
        q = q.where(Device.site_id == site_id)
    rows = (await db.execute(q.order_by(Device.name))).all()
    sem = asyncio.Semaphore(int(cfg["snmp_max_concurrency"]))
    allowed = cfg["snmp_allowed_cidrs"]
    creds: dict[uuid.UUID, Any] = {}

    def target_of(dev: Device, cred: SnmpCredentialRow) -> SnmpTarget | str:
        if cred.version == "v2c" and not cfg["snmp_v2c_enabled"]:
            return "V2C_DISABLED"
        try:
            check_address(str(dev.mgmt_ip), allowed)
        except TargetNotAllowed:
            return "TARGET_NOT_ALLOWED"
        if cred.id not in creds:
            creds[cred.id] = to_snmp_credential(keyring, cred)
        return SnmpTarget(
            host=str(dev.mgmt_ip),
            port=dev.snmp_port,
            timeout_s=dev.timeout_ms / 1000,
            retries=dev.retries,
            credential=creds[cred.id],
            context_name=dev.snmp_context,
        )

    async def driver_for(dev: Device, client: SnmpClient) -> Any:
        """Driver de la famille ; un équipement jamais identifié (driver « generic ») est détecté par sysObjectID."""
        if dev.driver != "generic":
            return get_driver(dev.driver)()
        oid = (await client.get(oids.SYS_OBJECT_ID)).get(oids.SYS_OBJECT_ID)
        return detect_driver(str(oid or ""))()

    async def note(dev: Device, status: str, **extra: Any) -> None:
        partial["queried"].append(dev.name)
        if status not in ("found", "not_found"):
            partial["errors"][dev.name] = extra.get("code", status)
        await publish("device_queried", {"device": dev.name, "status": status, **extra})

    # ---------------------------------------------------------------- 1) IP -> MAC (ARP en direct des passerelles)
    arp_gateway: str | None = None
    if kind == "ip":
        l3 = [(d, c) for d, c in rows if d.is_l3]
        if not l3:
            return _fail("GATEWAY_NOT_MANAGED", partial)
        await publish("arp_resolving", {"ip": value, "gateways": [d.name for d, _ in l3]})

        async def ask(dev: Device, cred: SnmpCredentialRow) -> tuple[Device, tuple[str, int] | None, str | None]:
            tgt = target_of(dev, cred)
            if isinstance(tgt, str):
                return dev, None, tgt
            try:
                async with sem, SnmpClient(tgt) as client:
                    driver = await driver_for(dev, client)
                    return dev, await driver.find_arp(client, value, dev.max_repetitions), None
            except SnmpError as exc:
                return dev, None, exc.code

        found_mac: str | None = None
        tasks = [asyncio.create_task(ask(d, c)) for d, c in l3]
        try:
            for arp_fut in asyncio.as_completed(tasks):
                gw, arp_res, arp_err = await arp_fut
                if arp_err:
                    await note(gw, "error", code=arp_err)
                elif arp_res is None:
                    await note(gw, "not_found")
                else:
                    await note(gw, "found")
                    found_mac, arp_gateway = arp_res[0], gw.name
                    break
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        if found_mac is None:
            errs = {k: v for k, v in partial["errors"].items()}
            if errs and len(errs) == len(l3):
                return _fail(_pick_error(errs), partial)
            return _fail("IP_NOT_IN_ARP", partial, f"Passerelles interrogées : {', '.join(d.name for d, _ in l3)}.")
        mac = found_mac
        await publish("arp_resolved", {"ip": value, "mac": mac, "gateway": arp_gateway})
        partial = {"queried": [], "errors": {}, **{"arp_gateway": arp_gateway}}
    else:
        mac = value

    # ------------------------------------------------ 2) MAC -> port (FDB en direct de tous les switchs)
    l2 = [(d, c) for d, c in rows if d.is_l2]
    if not l2:
        return _fail("NO_SWITCHES", partial)
    mac_bytes = bytes.fromhex(mac.replace(":", ""))
    vlan_hints = await _vlan_hints(db, mac)
    ifaces = {
        (str(i.device_id), i.if_index): i
        for i in (await db.execute(select(Interface).where(Interface.device_id.in_([d.id for d, _ in l2])))).scalars()
    }
    nbr_map: dict[tuple[str, str], tuple[str | None, str | None]] = {}
    for n in (await db.execute(select(Neighbor).where(Neighbor.device_id.in_([d.id for d, _ in l2])))).scalars():
        if n.matched_device_id:
            nbr_map[(str(n.device_id), str(n.interface_id))] = (str(n.matched_device_id), n.remote_sysname)
        else:
            nbr_map.setdefault((str(n.device_id), str(n.interface_id)), (None, n.remote_sysname))
    await publish("fdb_querying", {"mac": mac, "switches": [d.name for d, _ in l2]})

    async def probe(dev: Device, cred: SnmpCredentialRow) -> tuple[Device, LiveHit | None, str | None]:
        tgt = target_of(dev, cred)
        if isinstance(tgt, str):
            return dev, None, tgt
        try:
            async with sem:
                if dev.driver != "generic":
                    driver = get_driver(dev.driver)()
                else:
                    async with SnmpClient(tgt) as probe_client:
                        driver = await driver_for(dev, probe_client)
                hit = await driver.lookup_mac(
                    tgt, mac_bytes, vlan_hints, dev.max_repetitions, int(cfg["snmp_max_concurrency"])
                )
            return dev, hit, None
        except SnmpError as exc:
            return dev, None, exc.code

    hits: list[Hit] = []
    tasks2 = [asyncio.create_task(probe(d, c)) for d, c in l2]
    try:
        for fdb_fut in asyncio.as_completed(tasks2):
            dev, hit, err = await fdb_fut
            if err:
                await note(dev, "error", code=err)
                continue
            if hit is None:
                await note(dev, "not_found")
                continue
            iface = ifaces.get((str(dev.id), hit.if_index)) if hit.if_index is not None else None
            role = (iface.role_override or iface.role_detected) if iface else "unknown"
            nb = nbr_map.get((str(dev.id), str(iface.id)), (None, None)) if iface else (None, None)
            h = Hit(
                str(dev.id),
                dev.name,
                hit.if_index,
                iface.name if iface else None,
                hit.vlan,
                role,
                iface.mac_count if iface else 0,
                hit.is_self,
                nb[0],
                nb[1],
            )
            hits.append(h)
            partial.setdefault("hits", []).append({"device": h.device, "port": h.port, "role": h.role, "vlan": h.vlan})
            await note(dev, "found", port=h.port, vlan=h.vlan, role=h.role)
    finally:
        for t2 in tasks2:
            t2.cancel()
        await asyncio.gather(*tasks2, return_exceptions=True)

    errors = dict(partial["errors"])
    access = [h for h in hits if h.role != "uplink"]
    uplinks = [h for h in hits if h.role == "uplink"]

    # ---------------------------------------------------------------- 3) conclusion + chaîne d'uplinks
    if not access:
        if not hits:
            if errors:
                names = ", ".join(f"{n} ({c})" for n, c in errors.items())
                return _fail(_pick_error(errors), partial, f"Équipements en échec : {names}.")
            return _fail("MAC_AGED_OUT", partial)
        # vue uniquement sur des uplinks : où s'arrête la chaîne ?
        by_id = {str(d.id): d for d, _ in rows}
        for h in sorted(uplinks, key=lambda x: x.device):
            if h.neighbor_device_id in by_id and by_id[h.neighbor_device_id].name in errors:
                bad = by_id[h.neighbor_device_id].name
                return _fail(errors[bad], partial, f"Le switch « {bad} » (suite de la chaîne) n'a pas répondu.")
        ends = sorted(
            {
                h.neighbor_name or "inconnu"
                for h in uplinks
                if h.neighbor_device_id not in {u.device_id for u in uplinks}
            }
        )
        return _fail("ACCESS_NOT_MANAGED", partial, f"Dernier maillon : {', '.join(ends)}.")

    best = min(access, key=lambda h: (h.is_self, h.mac_count, h.device))
    warnings: list[dict[str, Any]] = []
    if len(access) > 1:
        warnings.append(
            {
                "code": "MAC_MULTIPLE_LOCATIONS",
                "message": "La MAC est apprise sur plusieurs ports d'accès (entrées périmées ou déplacement récent).",
                "locations": [{"device": h.device, "port": h.port, "vlan": h.vlan} for h in access if h is not best],
            }
        )
    if best.role == "unknown":
        warnings.append(
            {
                "code": "PORT_ROLE_UNKNOWN",
                "message": "Rôle du port inconnu (collecte de topologie manquante) : classé « accès ».",
            }
        )
    if errors:
        warnings.append(
            {"code": "PARTIAL_FAILURE", "message": "Certains équipements n'ont pas répondu.", "devices": errors}
        )
    chain = build_chain(best.device_id, uplinks)
    for depth, h in chain:
        await publish("hop", {"depth": depth, "device": h.device, "port": h.port, "vlan": h.vlan, "role": "uplink"})
    await publish("hop", {"depth": 0, "device": best.device, "port": best.port, "vlan": best.vlan, "role": best.role})

    info = await _enrich(db, mac, value if kind == "ip" else None)
    return {
        "ok": True,
        "query": params["query"],
        "kind": kind,
        "mac": mac,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "arp_gateway": arp_gateway,
        "location": {
            "device": best.device,
            "device_id": best.device_id,
            "port": best.port,
            "vlan": best.vlan,
            "is_device_mac": best.is_self,
        },
        "chain": [
            {"depth": d, **{k: v for k, v in asdict(h).items() if k in ("device", "port", "vlan")}} for d, h in chain
        ],
        "warnings": warnings,
        **info,
    }


async def _vlan_hints(db: AsyncSession, mac: str) -> list[int]:
    """VLAN déjà connus pour cette MAC (apprentissage) : permettent le GET ciblé Q-BRIDGE / Cisco sans parcours."""
    v: set[int] = set()
    for model in (Endpoint, FdbEntry, ArpEntry):
        v |= {int(x) for x in (await db.execute(select(model.vlan).where(model.mac == mac))).scalars() if x}
    return sorted(v)[:8]


async def _enrich(db: AsyncSession, mac: str, ip: str | None) -> dict[str, Any]:
    eps = (
        (await db.execute(select(Endpoint).where(Endpoint.mac == mac).order_by(Endpoint.last_seen.desc())))
        .scalars()
        .all()
    )
    vendor = (
        await db.execute(select(OuiEntry.vendor).where(OuiEntry.prefix == func.trunc(cast(mac, MACADDR))))
    ).scalar_one_or_none()
    hist = []
    if eps:
        rows = (
            await db.execute(
                select(EndpointHistory)
                .where(EndpointHistory.endpoint_id.in_([e.id for e in eps]))
                .order_by(EndpointHistory.ts.desc(), EndpointHistory.id.desc())
                .limit(20)
            )
        ).scalars()
        hist = [{"ts": h.ts.isoformat(), "change": h.change, "old": h.old, "new": h.new} for h in rows]
    known_ips = sorted({str(e.ip) for e in eps if e.ip is not None})
    hostname = next((e.hostname for e in eps if e.hostname), None)
    return {
        "ip": ip or (known_ips[0] if known_ips else None),
        "known_ips": known_ips,
        "vendor": vendor,
        "hostname": hostname,
        "first_seen": min(e.first_seen for e in eps).isoformat() if eps else None,
        "last_seen": max(e.last_seen for e in eps).isoformat() if eps else None,
        "history": hist,
    }
