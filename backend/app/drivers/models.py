"""Structures de données échangées entre drivers et service de topologie."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class IfInfo:
    if_index: int
    name: str
    descr: str
    alias: str
    if_type: int
    oper_status: int | None
    bridge_port: int | None


@dataclass(frozen=True)
class NeighborInfo:
    protocol: str  # lldp | cdp
    local_if_index: int
    remote_chassis_id: str
    remote_port_id: str
    remote_port_desc: str
    remote_sysname: str
    remote_sysdescr: str
    remote_ip: str | None
    is_network_device: bool


@dataclass
class TopologySnapshot:
    chassis_mac: str | None
    interfaces: list[IfInfo]
    neighbors: list[NeighborInfo]
    trunk_if_indexes: set[int] = field(default_factory=set)
    mac_counts: dict[int, int] = field(default_factory=dict)
    sys_name: str | None = None


@dataclass(frozen=True)
class ArpInfo:
    ip: str
    mac: str
    if_index: int
    vlan: int | None


@dataclass(frozen=True)
class FdbInfo:
    mac: str
    vlan: int | None
    if_index: int


@dataclass(frozen=True)
class LiveHit:
    """Résultat d'une recherche MAC en direct sur un équipement."""

    bridge_port: int
    if_index: int | None
    vlan: int | None
    is_self: bool = False  # statut « self » : la MAC appartient à l'équipement lui-même
