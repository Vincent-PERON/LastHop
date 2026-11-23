"""Garde-fous sur les cibles SNMP : liste blanche de réseaux + refus des adresses dangereuses (anti-SSRF/scan)."""

from __future__ import annotations

import ipaddress
from typing import Any

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address

MAX_DISCOVERY_HOSTS = 1024
MIN_PREFIX_V4 = 8
MIN_PREFIX_V6 = 32


class TargetNotAllowed(Exception):
    """Cible refusée (message générique côté client, détail dans l'audit)."""


def is_forbidden_address(ip: Address) -> bool:
    return (
        ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved
    )  # link-local couvre 169.254.169.254 (métadonnées cloud)


def validate_cidr_list(values: list[str]) -> list[str]:
    """Validateur du paramètre `snmp_allowed_cidrs`."""
    out: list[str] = []
    for v in values:
        try:
            net = ipaddress.ip_network(v, strict=True)
        except ValueError as exc:
            raise ValueError("CIDR invalide") from exc
        min_prefix = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
        if net.prefixlen < min_prefix:
            raise ValueError("réseau trop large")
        if is_forbidden_address(net.network_address):
            raise ValueError("réseau interdit")
        out.append(str(net))
    return out


def _nets(allowed: list[str]) -> list[Network]:
    return [ipaddress.ip_network(a, strict=True) for a in allowed]


def check_address(ip_text: str, allowed: list[str]) -> Address:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise TargetNotAllowed("adresse invalide") from exc
    if is_forbidden_address(ip):
        raise TargetNotAllowed("adresse interdite")
    if not any(ip in n for n in _nets(allowed) if n.version == ip.version):
        raise TargetNotAllowed("hors des réseaux autorisés")
    return ip


def parse_discovery_cidr(cidr: str, allowed: list[str]) -> Network:
    try:
        net = ipaddress.ip_network(cidr, strict=True)
    except ValueError as exc:
        raise TargetNotAllowed("CIDR invalide") from exc
    if is_forbidden_address(net.network_address):
        raise TargetNotAllowed("réseau interdit")
    if net.num_addresses > MAX_DISCOVERY_HOSTS:
        raise TargetNotAllowed("plage trop large")
    if not any(net.version == a.version and net.subnet_of(a) for a in _nets(allowed)):  # type: ignore[arg-type]
        raise TargetNotAllowed("hors des réseaux autorisés")
    return net


def expand_hosts(net: Network) -> list[str]:
    hosts: list[Any] = list(net.hosts()) if net.num_addresses > 2 else list(net)
    return [str(h) for h in hosts if not is_forbidden_address(h)]
