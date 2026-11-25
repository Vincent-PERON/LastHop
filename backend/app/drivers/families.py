from __future__ import annotations

import asyncio
import re
from dataclasses import replace

from app.drivers.base import Driver
from app.drivers.models import FdbInfo, IfInfo, LiveHit, NeighborInfo, PortVlans
from app.snmp import bridge
from app.snmp.client import SnmpClient, SnmpTarget


class GenericDriver(Driver):
    """Équipement inconnu : tables standard seules, avec les replis les plus tolérants (voir `docs/ADD_DRIVER.md`).
    Voisins : LLDP puis CDP (certains équipements n'annoncent que CDP)."""

    name = "generic"
    vendor = "unknown"

    async def collect_neighbors(self, client: SnmpClient, ifs: list[IfInfo], max_rep: int) -> list[NeighborInfo]:
        return [*await bridge.collect_lldp(client, ifs, max_rep), *await bridge.collect_cdp(client, max_rep)]


class FortinetDriver(Driver):
    """FortiGate / FortiSwitch (enterprise 12356). Le FortiGate est typiquement la passerelle inter-VLAN : sa table ARP
    (ipNetToMedia) fournit le lien IP ↔ MAC ; les ports d'accès sont lus sur les switchs. Non validé sur du matériel."""

    name = "fortinet"
    vendor = "Fortinet"
    oid_prefixes = ("1.3.6.1.4.1.12356.",)

    def parse_model(self, sys_descr: str) -> str | None:
        m = re.search(r"\b(Forti(?:Gate|Switch|Wifi|AP)[-_ ]?[\w\-]*)", sys_descr, re.IGNORECASE)
        return m.group(1)[:64] if m else None


class ArubaOsDriver(Driver):
    """HPE/Aruba ProCurve, ArubaOS-Switch et AOS-CX."""

    name = "aruba_os"
    vendor = "HPE Aruba"
    oid_prefixes = ("1.3.6.1.4.1.11.2.3.7.11.", "1.3.6.1.4.1.47196.", "1.3.6.1.4.1.14823.")

    def parse_model(self, sys_descr: str) -> str | None:
        m = re.search(r"\b(J[A-Z]?\d{3,4}[A-Z]?)\b", sys_descr)
        return m.group(1) if m else None


class ComwareDriver(Driver):
    """HPE Comware / H3C."""

    name = "comware"
    vendor = "HPE Comware"
    oid_prefixes = ("1.3.6.1.4.1.25506.",)

    def parse_model(self, sys_descr: str) -> str | None:
        m = re.search(r"^((?:HPE?|H3C)\s+[\w\-+/]+(?:\s+[A-Z]{2,3})?)\s+(?:Switch|Router)", sys_descr, re.MULTILINE)
        return m.group(1) if m else None


class CiscoIosDriver(Driver):
    name = "cisco_ios"
    vendor = "Cisco"
    oid_prefixes = ("1.3.6.1.4.1.9.",)

    def parse_model(self, sys_descr: str) -> str | None:
        m = re.search(r"Software \(([A-Za-z0-9]+)[-)]", sys_descr)
        return m.group(1) if m else None

    async def collect_neighbors(self, client: SnmpClient, ifs: list[IfInfo], max_rep: int) -> list[NeighborInfo]:
        # CDP en priorité (natif Cisco) puis LLDP ; les doublons sont fusionnés à l'enregistrement
        return [*await bridge.collect_cdp(client, max_rep), *await bridge.collect_lldp(client, ifs, max_rep)]

    async def collect_vlans(self, client: SnmpClient, max_rep: int) -> dict[int, str]:
        return await bridge.collect_cisco_vlans(client, max_rep)

    async def collect_port_vlans(
        self, client: SnmpClient, ifs: list[IfInfo], trunks: set[int], max_rep: int
    ) -> dict[int, PortVlans]:
        return await bridge.collect_cisco_port_vlans(client, ifs, trunks, max_rep)

    async def collect_trunks(
        self, client: SnmpClient, ifs: list[IfInfo], min_tagged_vlans: int, max_rep: int
    ) -> set[int]:
        # IOS n'expose pas les tables Q-BRIDGE de VLAN : l'état de trunk vient de CISCO-VTP-MIB
        return await bridge.collect_vtp_trunks(client, max_rep)

    async def collect_fdb(self, target: SnmpTarget, max_rep: int, concurrency: int) -> list[FdbInfo]:
        """Cisco IOS : une instance de bridge par VLAN (contexte `vlan-X` en v3, `community@X` en v2c), après lecture de
        la table VTP. Les numéros de port de bridge varient selon le VLAN : la correspondance est relue par contexte."""
        async with SnmpClient(target) as client:
            vlans = await bridge.collect_vtp_vlans(client, max_rep)
            if not vlans:  # pas de VTP exploitable : FDB du contexte par défaut
                return await bridge.collect_fdb(client, max_rep)
        sem = asyncio.Semaphore(max(1, min(concurrency, 8)))

        async def one(vlan: int) -> list[FdbInfo]:
            async with sem, SnmpClient(replace(target, context_name=f"vlan-{vlan}")) as c:
                return await bridge.collect_fdb(c, max_rep, force_vlan=vlan)

        results = await asyncio.gather(*(one(v) for v in vlans), return_exceptions=True)
        ok = [r for r in results if isinstance(r, list)]
        if not ok:  # toutes les instances ont échoué : on remonte l'erreur (injoignable, authentification…)
            raise next(r for r in results if isinstance(r, BaseException))
        return [e for r in ok for e in r]

    async def lookup_mac(
        self, target: SnmpTarget, mac: bytes, vlan_hints: list[int], max_rep: int, concurrency: int
    ) -> LiveHit | None:
        """Cisco : la FDB est par VLAN. Les VLAN connus (apprentissage) sont essayés d'abord, sinon tous les VLAN VTP ;
        GET ciblé dans chaque contexte, arrêt dès la première correspondance."""
        async with SnmpClient(target) as client:
            vlans = vlan_hints or await bridge.collect_vtp_vlans(client, max_rep)
            if not vlans:
                return await bridge.lookup_mac(client, mac, [], max_rep)
        sem = asyncio.Semaphore(max(1, min(concurrency, 8)))

        async def one(vlan: int) -> LiveHit | None:
            async with sem, SnmpClient(replace(target, context_name=f"vlan-{vlan}")) as c:
                return await bridge.lookup_mac(c, mac, [], max_rep, force_vlan=vlan)

        tasks = [asyncio.create_task(one(v)) for v in vlans]
        first_error: BaseException | None = None
        answered = 0
        try:
            for fut in asyncio.as_completed(tasks):
                try:
                    hit = await fut
                except Exception as exc:  # noqa: BLE001 - une instance VLAN absente ne doit pas masquer les autres
                    first_error = first_error or exc
                    continue
                answered += 1
                if hit is not None:
                    return hit
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        if answered == 0 and first_error is not None:  # aucune instance n'a répondu : équipement injoignable / auth
            raise first_error
        return None
