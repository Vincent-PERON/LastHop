"""Interface commune des drivers (une famille de constructeurs = un driver)."""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from typing import ClassVar

from app.drivers.models import ArpInfo, FdbInfo, IfInfo, LiveHit, NeighborInfo, TopologySnapshot
from app.snmp import bridge, oids
from app.snmp.client import SnmpClient, SnmpError, SnmpTarget, as_text


@dataclass(frozen=True)
class DeviceIdentity:
    sys_name: str
    sys_descr: str
    sys_object_id: str
    driver: str
    vendor: str
    model: str | None


class Driver(ABC):
    name: ClassVar[str]
    vendor: ClassVar[str]
    oid_prefixes: ClassVar[tuple[str, ...]] = ()

    @classmethod
    def matches(cls, sys_object_id: str) -> bool:
        return any(sys_object_id == p.rstrip(".") or sys_object_id.startswith(p) for p in cls.oid_prefixes)

    def parse_model(self, sys_descr: str) -> str | None:
        """Extrait le modèle depuis sysDescr (repli quand ENTITY-MIB ne répond pas)."""
        return None

    async def identify(self, client: SnmpClient) -> DeviceIdentity:
        vals = await client.get(oids.SYS_NAME, oids.SYS_DESCR, oids.SYS_OBJECT_ID)
        descr_full = as_text(vals.get(oids.SYS_DESCR), limit=1024, multiline=True)
        model: str | None = None
        try:  # ENTITY-MIB : optionnel, absent sur certains équipements
            ent = await client.get(oids.ENT_PHYSICAL_MODEL_NAME_1)
            model = as_text(ent.get(oids.ENT_PHYSICAL_MODEL_NAME_1), limit=64) or None
        except SnmpError:
            model = None
        model = model or self.parse_model(descr_full)
        return DeviceIdentity(
            sys_name=as_text(vals.get(oids.SYS_NAME), limit=100),
            sys_descr=as_text(vals.get(oids.SYS_DESCR), limit=255),
            sys_object_id=as_text(vals.get(oids.SYS_OBJECT_ID), limit=128),
            driver=self.name,
            vendor=self.vendor,
            model=model[:64] if model else None,
        )

    # --- Topologie (lot c) : implémentation standard (IF-MIB, Q-BRIDGE, LLDP) ; les familles surchargent
    async def collect_neighbors(self, client: SnmpClient, ifs: list[IfInfo], max_rep: int) -> list[NeighborInfo]:
        return await bridge.collect_lldp(client, ifs, max_rep)

    async def collect_trunks(
        self, client: SnmpClient, ifs: list[IfInfo], min_tagged_vlans: int, max_rep: int
    ) -> set[int]:
        return await bridge.collect_qbridge_trunks(client, ifs, min_tagged_vlans, max_rep)

    async def collect_topology(
        self, client: SnmpClient, *, min_tagged_vlans: int = 2, max_repetitions: int = 25
    ) -> TopologySnapshot:
        ifs = await bridge.collect_interfaces(client, max_repetitions)
        return TopologySnapshot(
            chassis_mac=await bridge.collect_chassis_mac(client),
            sys_name=as_text((await client.get(oids.SYS_NAME)).get(oids.SYS_NAME), 100) or None,
            interfaces=ifs,
            neighbors=await self.collect_neighbors(client, ifs, max_repetitions),
            trunk_if_indexes=await self.collect_trunks(client, ifs, min_tagged_vlans, max_repetitions),
            mac_counts=await bridge.collect_mac_counts(client, ifs, max_repetitions),
        )

    # --- Temps réel (lot e)
    async def find_arp(self, client: SnmpClient, ip: str, max_rep: int) -> tuple[str, int] | None:
        return await bridge.find_arp(client, ip, max_rep)

    async def lookup_mac(
        self, target: SnmpTarget, mac: bytes, vlan_hints: list[int], max_rep: int, concurrency: int
    ) -> LiveHit | None:
        async with SnmpClient(target) as client:
            return await bridge.lookup_mac(client, mac, vlan_hints, max_rep)

    # --- Learning (lot d)
    async def collect_arp(self, client: SnmpClient, max_rep: int) -> list[ArpInfo]:
        return await bridge.collect_arp(client, max_rep)

    async def collect_fdb(self, target: SnmpTarget, max_rep: int, concurrency: int) -> list[FdbInfo]:
        """La FDB est lue avec un client dédié : certaines familles (Cisco) ouvrent un contexte par VLAN."""
        async with SnmpClient(target) as client:
            return await bridge.collect_fdb(client, max_rep)
