"""Lecture des tables standard (IF-MIB, BRIDGE/Q-BRIDGE, LLDP, CDP). Fonctions pures de parsing + collecte."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from app.drivers.models import IfInfo, NeighborInfo
from app.snmp import oids
from app.snmp.client import AUTH_FAILURE, TIMEOUT, SnmpClient, SnmpError, SnmpValue, as_text

PHYSICAL_IF_TYPES = {6, 161}  # ethernetCsmacd, ieee8023adLag
MAX_ROWS = 200_000
FDB_LEARNED = 3


def fmt_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _suffix(oid: str, base: str) -> str:
    return oid[len(base) + 1 :]


async def column(client: SnmpClient, base: str, max_rep: int = 25) -> dict[str, SnmpValue]:
    """Walk d'une colonne -> {suffixe d'index: valeur}. Un sous-arbre absent donne un dict vide."""
    return {_suffix(o, base): v async for o, v in client.walk(base, max_repetitions=max_rep, max_rows=MAX_ROWS)}


async def optional(client: SnmpClient, base: str, max_rep: int = 25) -> dict[str, SnmpValue]:
    """Table facultative : une erreur SNMP « fonctionnelle » (vue restreinte…) n'interrompt pas la collecte,
    mais l'indisponibilité ou l'échec d'authentification sont propagés."""
    try:
        return await column(client, base, max_rep)
    except SnmpError as exc:
        if exc.code in (TIMEOUT, AUTH_FAILURE):
            raise
        return {}


def bits_set(bitmap: bytes) -> set[int]:
    """Q-BRIDGE PortList : bit de poids fort de l'octet 0 = port 1."""
    return {i * 8 + b + 1 for i, byte in enumerate(bitmap) for b in range(8) if byte & (0x80 >> b)}


def _to_int(v: SnmpValue) -> int | None:
    return v if isinstance(v, int) else None


async def collect_chassis_mac(client: SnmpClient) -> str | None:
    vals = await client.get(oids.LLDP_LOC_CHASSIS_ID_SUBTYPE, oids.LLDP_LOC_CHASSIS_ID, oids.DOT1D_BASE_BRIDGE_ADDRESS)
    cid, sub = vals.get(oids.LLDP_LOC_CHASSIS_ID), vals.get(oids.LLDP_LOC_CHASSIS_ID_SUBTYPE)
    if sub == 4 and isinstance(cid, bytes) and len(cid) == 6:
        return fmt_mac(cid)
    base = vals.get(oids.DOT1D_BASE_BRIDGE_ADDRESS)
    return fmt_mac(base) if isinstance(base, bytes) and len(base) == 6 else None


async def collect_interfaces(client: SnmpClient, max_rep: int = 25) -> list[IfInfo]:
    descr = await column(client, oids.IF_DESCR, max_rep)
    types = await column(client, oids.IF_TYPE, max_rep)
    oper = await optional(client, oids.IF_OPER_STATUS, max_rep)
    names = await optional(client, oids.IF_NAME, max_rep)
    aliases = await optional(client, oids.IF_ALIAS, max_rep)
    bridge = await optional(client, oids.DOT1D_BASE_PORT_IFINDEX, max_rep)  # bridge port -> ifIndex
    by_if = {int(v): int(k) for k, v in bridge.items() if isinstance(v, int)}
    out: list[IfInfo] = []
    for idx_s, d in descr.items():
        t = _to_int(types.get(idx_s))
        if not idx_s.isdigit() or t not in PHYSICAL_IF_TYPES:
            continue
        idx = int(idx_s)
        d_text = as_text(d)
        out.append(
            IfInfo(
                if_index=idx,
                name=(as_text(names.get(idx_s), 64) or d_text[:64]),
                descr=d_text,
                alias=as_text(aliases.get(idx_s)),
                if_type=t or 0,
                oper_status=_to_int(oper.get(idx_s)),
                bridge_port=by_if.get(idx),
            )
        )
    return out


async def collect_mac_counts(client: SnmpClient, ifs: list[IfInfo], max_rep: int = 25) -> dict[int, int]:
    """Nombre d'adresses MAC *apprises* par port (contexte par défaut). Q-BRIDGE d'abord, repli sur BRIDGE-MIB."""
    by_bp = {i.bridge_port: i.if_index for i in ifs if i.bridge_port is not None}
    counts: dict[int, int] = defaultdict(int)
    for port_oid, status_oid in (
        (oids.DOT1Q_TP_FDB_PORT, oids.DOT1Q_TP_FDB_STATUS),
        (oids.DOT1D_TP_FDB_PORT, oids.DOT1D_TP_FDB_STATUS),
    ):
        ports = await optional(client, port_oid, max_rep)
        if not ports:
            continue
        status = await optional(client, status_oid, max_rep)
        for key, bp in ports.items():
            if status.get(key) == FDB_LEARNED and isinstance(bp, int) and bp in by_bp:
                counts[by_bp[bp]] += 1
        break
    return dict(counts)


async def collect_qbridge_trunks(
    client: SnmpClient, ifs: list[IfInfo], min_tagged_vlans: int, max_rep: int = 25
) -> set[int]:
    """Un port est un trunk s'il est membre *tagué* d'au moins `min_tagged_vlans` VLAN (Q-BRIDGE statique)."""
    egress = await optional(client, oids.DOT1Q_VLAN_STATIC_EGRESS, max_rep)
    untagged = await optional(client, oids.DOT1Q_VLAN_STATIC_UNTAGGED, max_rep)
    by_bp = {i.bridge_port: i.if_index for i in ifs if i.bridge_port is not None}
    tagged_in: dict[int, int] = defaultdict(int)
    for vlan, e in egress.items():
        if not isinstance(e, bytes):
            continue
        u = untagged.get(vlan)
        for bp in bits_set(e) - (bits_set(u) if isinstance(u, bytes) else set()):
            if bp in by_bp:
                tagged_in[by_bp[bp]] += 1
    return {idx for idx, n in tagged_in.items() if n >= min_tagged_vlans}


# ----------------------------------------------------------------------------------- LLDP / CDP

LLDP_STATION_BITS = {3, 5, 7}  # wlanAccessPoint, telephone, stationOnly
LLDP_NETWORK_BITS = {2, 4}  # bridge, router


def lldp_is_network_device(caps: SnmpValue) -> bool:
    if not isinstance(caps, bytes) or not caps:
        return False
    on = {b for b in range(8) if caps[0] & (0x80 >> b)}
    return bool(on & LLDP_NETWORK_BITS) and not (on & LLDP_STATION_BITS)


def cdp_is_network_device(caps: SnmpValue) -> bool:
    if not isinstance(caps, bytes) or not caps:
        return False
    v = int.from_bytes(caps[-4:], "big")
    return bool(v & (0x01 | 0x02 | 0x04 | 0x08)) and not (v & 0x10 and not v & 0x0F)


def _id_text(subtype: int | None, raw: SnmpValue) -> str:
    if isinstance(raw, bytes) and subtype in (3,) and len(raw) == 6:  # macAddress
        return fmt_mac(raw)
    if isinstance(raw, bytes) and subtype == 4 and len(raw) == 6:  # chassis macAddress
        return fmt_mac(raw)
    if isinstance(raw, bytes):
        try:
            txt = raw.decode("ascii")
        except UnicodeDecodeError:
            return raw.hex()[:128]
        return as_text(raw, 128) if txt.isprintable() and subtype in (4, 5, 6, 7, 1, 2) else raw.hex()[:128]
    return as_text(raw, 128)


async def _lldp_local_map(client: SnmpClient, ifs: list[IfInfo], max_rep: int) -> dict[int, int]:
    """lldpLocPortNum -> ifIndex : par nom de port, sinon ifIndex identique, sinon numéro de bridge port."""
    sub = await optional(client, oids.LLDP_LOC_PORT_ID_SUBTYPE, max_rep)
    pid = await optional(client, oids.LLDP_LOC_PORT_ID, max_rep)
    by_name: dict[str, int] = {}
    for i in ifs:
        for key in (i.name, i.descr, i.alias):
            if key:
                by_name.setdefault(key.lower(), i.if_index)
    idxs = {i.if_index for i in ifs}
    by_bp = {i.bridge_port: i.if_index for i in ifs if i.bridge_port is not None}
    out: dict[int, int] = {}
    for num_s, raw in pid.items():
        if not num_s.isdigit():
            continue
        num = int(num_s)
        text = _id_text(_to_int(sub.get(num_s)), raw).lower()
        if text in by_name:
            out[num] = by_name[text]
        elif num in idxs:
            out[num] = num
        elif num in by_bp:
            out[num] = by_bp[num]
    for i in ifs:  # ports sans lldpLocPortTable : repli ifIndex
        out.setdefault(i.if_index, i.if_index)
    return out


async def collect_lldp(client: SnmpClient, ifs: list[IfInfo], max_rep: int = 25) -> list[NeighborInfo]:
    rows = await optional(client, oids.LLDP_REM, max_rep)  # suffixe = col.timeMark.localPort.index
    if not rows:
        return []
    local = await _lldp_local_map(client, ifs, max_rep)
    grouped: dict[tuple[str, str], dict[int, SnmpValue]] = defaultdict(dict)
    for suffix, v in rows.items():
        parts = suffix.split(".")
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            continue
        grouped[(parts[2], parts[3])][int(parts[0])] = v
    out: list[NeighborInfo] = []
    for (port_s, _), c in grouped.items():
        if_index = local.get(int(port_s))
        if if_index is None:
            continue
        cid = _id_text(_to_int(c.get(oids.LLDP_REM_CHASSIS_SUBTYPE)), c.get(oids.LLDP_REM_CHASSIS_ID))
        pid = _id_text(_to_int(c.get(oids.LLDP_REM_PORT_SUBTYPE)), c.get(oids.LLDP_REM_PORT_ID))
        if not cid and not pid:
            continue
        out.append(
            NeighborInfo(
                protocol="lldp",
                local_if_index=if_index,
                remote_chassis_id=cid,
                remote_port_id=pid,
                remote_port_desc=as_text(c.get(oids.LLDP_REM_PORT_DESC)),
                remote_sysname=as_text(c.get(oids.LLDP_REM_SYS_NAME), 100),
                remote_sysdescr=as_text(c.get(oids.LLDP_REM_SYS_DESC)),
                remote_ip=None,
                is_network_device=lldp_is_network_device(c.get(oids.LLDP_REM_SYS_CAP_ENABLED)),
            )
        )
    return out


async def collect_cdp(client: SnmpClient, max_rep: int = 25) -> list[NeighborInfo]:
    rows = await optional(client, oids.CDP_CACHE, max_rep)  # suffixe = col.ifIndex.deviceIndex
    grouped: dict[tuple[int, str], dict[int, SnmpValue]] = defaultdict(dict)
    for suffix, v in rows.items():
        parts = suffix.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            continue
        grouped[(int(parts[1]), parts[2])][int(parts[0])] = v
    out: list[NeighborInfo] = []
    for (if_index, _), c in grouped.items():
        dev = as_text(c.get(oids.CDP_DEVICE_ID), 100)
        if not dev:
            continue
        ip: str | None = None
        addr = c.get(oids.CDP_ADDRESS)
        if c.get(oids.CDP_ADDRESS_TYPE) == 1 and isinstance(addr, bytes) and len(addr) == 4:
            ip = str(ipaddress.IPv4Address(addr))
        out.append(
            NeighborInfo(
                protocol="cdp",
                local_if_index=if_index,
                remote_chassis_id=dev,
                remote_port_id=as_text(c.get(oids.CDP_DEVICE_PORT), 128),
                remote_port_desc="",
                remote_sysname=dev,
                remote_sysdescr=as_text(c.get(oids.CDP_PLATFORM)),
                remote_ip=ip,
                is_network_device=cdp_is_network_device(c.get(oids.CDP_CAPS)),
            )
        )
    return out


async def collect_vtp_trunks(client: SnmpClient, max_rep: int = 25) -> set[int]:
    """CISCO-VTP-MIB vlanTrunkPortDynamicStatus : 1 = trunking."""
    rows = await optional(client, oids.VTP_TRUNK_DYNAMIC_STATUS, max_rep)
    return {int(k) for k, v in rows.items() if k.isdigit() and v == 1}


# ----------------------------------------------------------------------------------- Learning (lot d)

from app.drivers.models import ArpInfo, FdbInfo  # noqa: E402

ARP_PHYSICAL_OK = {1, 2, 3, 4}  # reachable, stale, delay, probe (invalid/unknown/incomplete ignorés)
ARP_MEDIA_OK = {3, 4}  # dynamic, static
_VLAN_NAME = re.compile(r"(?i)vlan\D*(\d{1,4})$")


def is_unicast_mac(raw: bytes) -> bool:
    return len(raw) == 6 and not (raw[0] & 1) and raw != b"\x00" * 6


def _ip_from_index(parts: list[str]) -> str | None:
    """Reconstruit l'adresse depuis l'index OID : [type, len, octets...] (ipNetToPhysical)."""
    try:
        t, n, octets = int(parts[0]), int(parts[1]), [int(p) for p in parts[2:]]
        if len(octets) != n or any(not 0 <= o <= 255 for o in octets):
            return None
        if t == 1 and n == 4:
            return str(ipaddress.IPv4Address(bytes(octets)))
        if t == 2 and n == 16:
            return str(ipaddress.IPv6Address(bytes(octets)))
    except (ValueError, IndexError):
        return None
    return None


async def _vlan_of_ifindexes(client: SnmpClient, if_indexes: set[int], max_rep: int) -> dict[int, int]:
    """VLAN associé aux interfaces de routage (SVI) d'après leur nom (« Vlan10 », « Vlan-interface10 »)."""
    names = await optional(client, oids.IF_NAME, max_rep)
    out: dict[int, int] = {}
    for idx in if_indexes:
        m = _VLAN_NAME.search(as_text(names.get(str(idx)), 64))
        if m and 1 <= int(m.group(1)) <= 4094:
            out[idx] = int(m.group(1))
    return out


async def collect_arp(client: SnmpClient, max_rep: int = 25) -> list[ArpInfo]:
    """ARP : ipNetToPhysicalTable (IPv4+IPv6), repli sur ipNetToMediaTable (IPv4) si la première est vide."""
    found: dict[tuple[str, str], tuple[int, str]] = {}
    macs = await optional(client, oids.IP_NET_TO_PHYSICAL_MAC, max_rep)
    if macs:
        state = await optional(client, oids.IP_NET_TO_PHYSICAL_STATE, max_rep)
        for suffix, raw in macs.items():
            parts = suffix.split(".")
            ip = _ip_from_index(parts[1:]) if len(parts) > 3 and parts[0].isdigit() else None
            if ip is None or not isinstance(raw, bytes) or not is_unicast_mac(raw):
                continue
            if state.get(suffix) not in ARP_PHYSICAL_OK:
                continue
            found[(ip, fmt_mac(raw))] = (int(parts[0]), ip)
    else:
        macs = await optional(client, oids.IP_NET_TO_MEDIA_MAC, max_rep)
        kinds = await optional(client, oids.IP_NET_TO_MEDIA_TYPE, max_rep)
        for suffix, raw in macs.items():
            parts = suffix.split(".")
            ip = _ip_from_index(["1", "4", *parts[1:]]) if len(parts) == 5 and parts[0].isdigit() else None
            if ip is None or not isinstance(raw, bytes) or not is_unicast_mac(raw):
                continue
            if kinds.get(suffix) not in ARP_MEDIA_OK:
                continue
            found[(ip, fmt_mac(raw))] = (int(parts[0]), ip)
    vlans = await _vlan_of_ifindexes(client, {v[0] for v in found.values()}, max_rep) if found else {}
    return [ArpInfo(ip=ip, mac=mac, if_index=idx, vlan=vlans.get(idx)) for (ip, mac), (idx, _) in found.items()]


async def bridge_port_map(client: SnmpClient, max_rep: int = 25) -> dict[int, int]:
    """Numéro de port de bridge -> ifIndex (dans le contexte courant : sur Cisco la numérotation dépend du VLAN)."""
    rows = await optional(client, oids.DOT1D_BASE_PORT_IFINDEX, max_rep)
    return {int(k): int(v) for k, v in rows.items() if k.isdigit() and isinstance(v, int)}


def _mac_from_index(parts: list[str]) -> bytes | None:
    try:
        raw = bytes(int(p) for p in parts)
    except ValueError:
        return None
    return raw if is_unicast_mac(raw) else None


async def collect_fdb(
    client: SnmpClient, max_rep: int = 25, *, force_vlan: int | None = None, bp_map: dict[int, int] | None = None
) -> list[FdbInfo]:
    """MAC apprises (statut « learned » uniquement). Q-BRIDGE (avec VLAN) d'abord, repli sur BRIDGE-MIB.
    `force_vlan` : VLAN de l'instance interrogée (contexte Cisco, où le VLAN n'apparaît pas dans l'index)."""
    mapping = bp_map if bp_map is not None else await bridge_port_map(client, max_rep)
    out: list[FdbInfo] = []
    ports = await optional(client, oids.DOT1Q_TP_FDB_PORT, max_rep)
    if ports:
        status = await optional(client, oids.DOT1Q_TP_FDB_STATUS, max_rep)
        for suffix, bp in ports.items():
            parts = suffix.split(".")
            if len(parts) != 7 or status.get(suffix) != FDB_LEARNED or not isinstance(bp, int) or bp not in mapping:
                continue
            raw = _mac_from_index(parts[1:])
            vlan = int(parts[0]) if parts[0].isdigit() and 1 <= int(parts[0]) <= 4094 else None
            if raw is not None:
                out.append(FdbInfo(mac=fmt_mac(raw), vlan=vlan, if_index=mapping[bp]))
        return out
    ports = await optional(client, oids.DOT1D_TP_FDB_PORT, max_rep)
    status = await optional(client, oids.DOT1D_TP_FDB_STATUS, max_rep)
    for suffix, bp in ports.items():
        parts = suffix.split(".")
        if len(parts) != 6 or status.get(suffix) != FDB_LEARNED or not isinstance(bp, int) or bp not in mapping:
            continue
        raw = _mac_from_index(parts)
        if raw is not None:
            out.append(FdbInfo(mac=fmt_mac(raw), vlan=force_vlan, if_index=mapping[bp]))
    return out


async def collect_vtp_vlans(client: SnmpClient, max_rep: int = 25) -> list[int]:
    """VLAN Ethernet opérationnels (CISCO-VTP-MIB) ; 1002-1005 (FDDI/Token Ring) exclus."""
    state = await optional(client, oids.VTP_VLAN_STATE, max_rep)
    vtype = await optional(client, oids.VTP_VLAN_TYPE, max_rep)
    vlans: set[int] = set()
    for suffix, st in state.items():
        parts = suffix.split(".")
        if len(parts) == 2 and parts[1].isdigit() and st == 1 and vtype.get(suffix) == 1:
            v = int(parts[1])
            if 1 <= v <= 1001:
                vlans.add(v)
    return sorted(vlans)


# ----------------------------------------------------------------------------------- Temps réel (lot e)

from app.drivers.models import LiveHit  # noqa: E402

FDB_SELF = 4


def mac_oid(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


async def _soft_get(client: SnmpClient, *oid_list: str) -> dict[str, SnmpValue]:
    """GET tolérant : une table inaccessible (vue SNMP restreinte, OID non géré) donne un résultat vide, mais
    l'indisponibilité de l'équipement et les échecs d'authentification remontent."""
    try:
        return await client.get(*oid_list)
    except SnmpError as exc:
        if exc.code in (TIMEOUT, AUTH_FAILURE):
            raise
        return {}


async def find_arp(client: SnmpClient, ip: str, max_rep: int = 25) -> tuple[str, int] | None:
    """Cherche la MAC d'une IP dans l'ARP *courante* de l'équipement (parcours, arrêt à la 1re correspondance).
    L'index ipNetToPhysical contient l'ifIndex, inconnu a priori : un GET ciblé n'est donc pas possible."""
    target = ipaddress.ip_address(ip)
    seen_any = False
    async for oid, raw in client.walk(oids.IP_NET_TO_PHYSICAL_MAC, max_repetitions=max_rep, max_rows=MAX_ROWS):
        seen_any = True
        suffix = _suffix(oid, oids.IP_NET_TO_PHYSICAL_MAC)
        parts = suffix.split(".")
        if len(parts) < 4 or not parts[0].isdigit():
            continue
        cand = _ip_from_index(parts[1:])
        if (
            cand is None
            or ipaddress.ip_address(cand) != target
            or not isinstance(raw, bytes)
            or not is_unicast_mac(raw)
        ):
            continue
        state = (await _soft_get(client, f"{oids.IP_NET_TO_PHYSICAL_STATE}.{suffix}")).get(
            f"{oids.IP_NET_TO_PHYSICAL_STATE}.{suffix}"
        )
        if state in ARP_PHYSICAL_OK:
            return fmt_mac(raw), int(parts[0])
    if seen_any or target.version != 4:
        return None
    async for oid, raw in client.walk(oids.IP_NET_TO_MEDIA_MAC, max_repetitions=max_rep, max_rows=MAX_ROWS):
        suffix = _suffix(oid, oids.IP_NET_TO_MEDIA_MAC)
        parts = suffix.split(".")
        if len(parts) != 5 or not parts[0].isdigit() or ".".join(parts[1:]) != str(target):
            continue
        if not isinstance(raw, bytes) or not is_unicast_mac(raw):
            continue
        kind = (await _soft_get(client, f"{oids.IP_NET_TO_MEDIA_TYPE}.{suffix}")).get(
            f"{oids.IP_NET_TO_MEDIA_TYPE}.{suffix}"
        )
        if kind in ARP_MEDIA_OK:
            return fmt_mac(raw), int(parts[0])
    return None


async def _port_to_ifindex(client: SnmpClient, bridge_port: int) -> int | None:
    key = f"{oids.DOT1D_BASE_PORT_IFINDEX}.{bridge_port}"
    v = (await _soft_get(client, key)).get(key)
    return v if isinstance(v, int) else None


async def lookup_mac(
    client: SnmpClient, mac: bytes, vlan_hints: list[int], max_rep: int = 25, *, force_vlan: int | None = None
) -> LiveHit | None:
    """FDB en direct pour UNE adresse MAC. Ordre : GET ciblé dot1qTpFdbPort (VLAN connus), GET ciblé dot1dTpFdbPort
    (index = MAC seule), puis parcours dot1qTpFdbPort avec arrêt à la correspondance. Seul le statut « learned »
    (ou « self ») compte."""
    moid = mac_oid(mac)

    async def check(port_oid: str, status_oid: str, vlan: int | None, vlan_in_index: bool) -> LiveHit | None:
        suffix = f"{vlan}.{moid}" if vlan_in_index else moid
        pk, sk = f"{port_oid}.{suffix}", f"{status_oid}.{suffix}"
        vals = await _soft_get(client, pk, sk)
        bp, st = vals.get(pk), vals.get(sk)
        if isinstance(bp, int) and st in (FDB_LEARNED, FDB_SELF):
            return LiveHit(
                bridge_port=bp, if_index=await _port_to_ifindex(client, bp), vlan=vlan, is_self=st == FDB_SELF
            )
        return None

    for vlan in vlan_hints:
        if (h := await check(oids.DOT1Q_TP_FDB_PORT, oids.DOT1Q_TP_FDB_STATUS, vlan, True)) is not None:
            return h
    if (h := await check(oids.DOT1D_TP_FDB_PORT, oids.DOT1D_TP_FDB_STATUS, force_vlan, False)) is not None:
        return h
    if (
        force_vlan is not None
    ):  # instance VLAN Cisco : la table BRIDGE-MIB du contexte fait foi, pas de parcours Q-BRIDGE
        return None
    try:
        async for oid, bp in client.walk(oids.DOT1Q_TP_FDB_PORT, max_repetitions=max_rep, max_rows=MAX_ROWS):
            parts = _suffix(oid, oids.DOT1Q_TP_FDB_PORT).split(".")
            if len(parts) == 7 and ".".join(parts[1:]) == moid and parts[0].isdigit() and isinstance(bp, int):
                vlan = int(parts[0])
                if (h := await check(oids.DOT1Q_TP_FDB_PORT, oids.DOT1Q_TP_FDB_STATUS, vlan, True)) is not None:
                    return h
    except SnmpError as exc:
        if exc.code in (TIMEOUT, AUTH_FAILURE):
            raise
    return None
