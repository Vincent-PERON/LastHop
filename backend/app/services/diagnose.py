# ruff: noqa: E501  (messages d'aide longs, volontairement lisibles tels quels)
"""Diagnostic SNMP d'un équipement : quelles tables LastHop sait lire, lesquelles manquent, et ce que cela change.

Fonctionne sur un `SnmpClient` (équipement réel, job « diagnose ») comme sur un `WalkClient` (parcours hors ligne, tests et
CLI `diagnose-walk`). Lecture seule. Aucune valeur d'équipement n'est renvoyée brute : seulement des compteurs et de courts
exemples nettoyés (`as_text`)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from app.drivers.registry import detect_driver
from app.snmp import bridge, oids
from app.snmp.client import AUTH_FAILURE, TIMEOUT, SnmpError, SnmpValue, as_text

Client = Any  # SnmpClient (équipement réel) ou WalkClient (parcours hors ligne) : mêmes méthodes get / walk


@dataclass
class Check:
    key: str
    title: str
    status: str  # ok | empty | error
    rows: int = 0
    detail: str = ""
    sample: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    feature: str
    level: str  # ok | partial | missing | na
    message: str
    advice: str = ""


async def _count(client: Client, base: str, limit: int = 200_000) -> tuple[int, list[tuple[str, SnmpValue]]]:
    """Nombre de lignes d'une colonne + 3 premières (index, valeur). Échec fonctionnel : propagé à l'appelant."""
    rows: list[tuple[str, SnmpValue]] = []
    n = 0
    async for oid, val in client.walk(base, max_repetitions=25, max_rows=limit):
        n += 1
        if len(rows) < 3:
            rows.append((oid[len(base) + 1 :], val))
    return n, rows


async def _table(client: Client, key: str, title: str, base: str, *, hint: str = "") -> Check:
    try:
        n, sample = await _count(client, base)
    except SnmpError as exc:
        if exc.code in (TIMEOUT, AUTH_FAILURE):
            raise  # l'équipement ne répond pas / identifiants refusés : le diagnostic entier est sans objet
        return Check(
            key,
            title,
            "error",
            detail=f"Refusé par l'équipement ({exc.code}) : sous-arbre {base} hors de la vue SNMP ?",
        )
    if n == 0:
        return Check(key, title, "empty", detail=hint or f"Aucune donnée sous {base}.")
    return Check(key, title, "ok", rows=n, sample=[f"{i} = {_fmt(v)}" for i, v in sample])


def _fmt(v: SnmpValue) -> str:
    if isinstance(v, bytes):
        return bridge.fmt_mac(v) if len(v) == 6 else as_text(v, 40)
    return as_text(str(v), 40) if v is not None else "—"


async def run_checks(client: Client) -> tuple[list[Check], str]:
    """Retourne (contrôles, nom du pilote détecté)."""
    checks: list[Check] = []
    vals = await client.get(oids.SYS_NAME, oids.SYS_DESCR, oids.SYS_OBJECT_ID)
    sys_oid = as_text(vals.get(oids.SYS_OBJECT_ID), 128)
    driver = detect_driver(sys_oid)
    if not sys_oid:
        checks.append(
            Check(
                "system", "Identité (sysObjectID)", "error", detail="sysObjectID illisible : vue SNMP trop restreinte ?"
            )
        )
    elif driver.name == "generic":
        checks.append(
            Check(
                "system",
                "Identité (sysObjectID)",
                "ok",
                1,
                f"Constructeur non reconnu ({sys_oid}) : pilote générique (tables standard).",
                [sys_oid],
            )
        )
    else:
        checks.append(
            Check(
                "system", "Identité (sysObjectID)", "ok", 1, f"Pilote « {driver.name} » ({driver.vendor}).", [sys_oid]
            )
        )

    checks.append(
        await _table(
            client, "if_type", "Interfaces (IF-MIB ifType)", oids.IF_TYPE, hint="IF-MIB absent de la vue SNMP."
        )
    )
    ifs = await bridge.collect_interfaces(client)
    physical = Check(
        "if_physical",
        "Ports physiques reconnus",
        "ok" if ifs else "empty",
        len(ifs),
        "" if ifs else "Aucune interface de type Ethernet reconnue (types 6, 62, 69, 117, 161).",
        [f"{i.name} (type {i.if_type})" for i in ifs[:3]],
    )
    checks.append(physical)
    checks.append(
        await _table(
            client,
            "if_name",
            "Noms de ports (ifName, ifXTable)",
            oids.IF_NAME,
            hint="ifXTable absente : les noms viendront d'ifDescr.",
        )
    )
    checks.append(
        await _table(client, "if_alias", "Descriptions de ports (ifAlias)", oids.IF_ALIAS, hint="Facultatif.")
    )
    checks.append(
        await _table(
            client,
            "bridge_ports",
            "Ports de bridge → ifIndex (BRIDGE-MIB)",
            oids.DOT1D_BASE_PORT_IFINDEX,
            hint="Absent : LastHop suppose « port de bridge = ifIndex ».",
        )
    )
    checks.append(
        await _table(client, "fdb_qbridge", "Table MAC avec VLAN (Q-BRIDGE dot1qTpFdb)", oids.DOT1Q_TP_FDB_PORT)
    )
    checks.append(await _table(client, "fdb_bridge", "Table MAC sans VLAN (BRIDGE dot1dTpFdb)", oids.DOT1D_TP_FDB_PORT))
    status_oid = oids.DOT1Q_TP_FDB_STATUS if checks[-2].status == "ok" else oids.DOT1D_TP_FDB_STATUS
    checks.append(
        await _table(
            client,
            "fdb_status",
            "Statut des entrées MAC (learned/self…)",
            status_oid,
            hint="Absent : toutes les entrées MAC sont considérées comme apprises (les adresses propres au switch ne sont pas distinguées).",
        )
    )
    checks.append(
        await _table(
            client,
            "vlan_egress",
            "Appartenance aux VLAN (Q-BRIDGE, détection des trunks)",
            oids.DOT1Q_VLAN_STATIC_EGRESS,
        )
    )
    checks.append(
        await _table(client, "lldp_remote", "Voisins LLDP", oids.LLDP_REM + "." + str(oids.LLDP_REM_SYS_NAME))
    )
    checks.append(await _table(client, "cdp", "Voisins CDP", oids.CDP_CACHE + "." + str(oids.CDP_DEVICE_ID)))
    checks.append(await _table(client, "arp_physical", "ARP moderne (ipNetToPhysical)", oids.IP_NET_TO_PHYSICAL_MAC))
    checks.append(await _table(client, "arp_media", "ARP classique (ipNetToMedia)", oids.IP_NET_TO_MEDIA_MAC))
    if driver.name == "cisco_ios":
        checks.append(
            await _table(
                client,
                "vtp",
                "Liste des VLAN (CISCO-VTP-MIB)",
                oids.VTP_VLAN_STATE,
                hint="Sans VTP, la FDB par VLAN Cisco ne peut pas être lue.",
            )
        )
    return checks, driver.name


def verdicts(checks: list[Check], driver_name: str) -> list[Verdict]:
    ok = {c.key: c.status == "ok" for c in checks}
    out: list[Verdict] = []

    def add(feature: str, level: str, message: str, advice: str = "") -> None:
        out.append(Verdict(feature, level, message, advice))

    if ok.get("if_physical"):
        add("Inventaire des ports", "ok", "Les ports physiques sont lus.")
    else:
        add(
            "Inventaire des ports",
            "missing",
            "Aucun port physique reconnu.",
            "Autorisez IF-MIB (1.3.6.1.2.1.2 et 1.3.6.1.2.1.31) dans la vue SNMP ; sinon envoyez un snmpwalk pour ajouter le type d'interface.",
        )

    if ok.get("lldp_remote") or ok.get("cdp"):
        add(
            "Topologie (liaisons entre équipements)",
            "ok",
            "Les voisins sont découverts par " + ("LLDP" if ok.get("lldp_remote") else "CDP") + ".",
        )
    else:
        add(
            "Topologie (liaisons entre équipements)",
            "missing",
            "Aucun voisin LLDP/CDP.",
            "Activez LLDP sur l'équipement (`lldp run` / `lldp enable`) et autorisez 1.0.8802.1.1.2 dans la vue SNMP. Sans cela, les uplinks sont devinés par le nombre de MAC par port.",
        )

    if ok.get("fdb_qbridge") or ok.get("fdb_bridge"):
        parts = []
        level = "ok"
        if not ok.get("fdb_qbridge"):
            parts.append("pas de VLAN dans la table MAC (le VLAN des endpoints sera inconnu)")
            level = "partial"
        if not ok.get("bridge_ports"):
            parts.append("table des ports de bridge absente (hypothèse bridge = ifIndex)")
            level = "partial"
        if not ok.get("fdb_status"):
            parts.append("statut des entrées absent (adresses propres au switch non distinguées)")
            level = "partial"
        add(
            "Apprentissage MAC → port",
            level,
            "Table MAC lue" + (" ; " + " ; ".join(parts) if parts else "."),
            "Vérifiez avec un snmpwalk que les numéros de port de la FDB correspondent bien aux ifIndex."
            if parts
            else "",
        )
    elif driver_name == "cisco_ios" and ok.get("vtp"):
        add(
            "Apprentissage MAC → port",
            "partial",
            "Cisco : la table MAC se lit par VLAN (contexte), pas dans le contexte par défaut.",
        )
    else:
        add(
            "Apprentissage MAC → port",
            "missing",
            "Aucune table MAC lisible.",
            "Autorisez BRIDGE-MIB et Q-BRIDGE (1.3.6.1.2.1.17) dans la vue SNMP. Pour un routeur/pare-feu sans table MAC, c'est normal : ajoutez plutôt les switchs d'accès.",
        )

    if ok.get("arp_physical") or ok.get("arp_media"):
        add(
            "Apprentissage IP ↔ MAC (ARP)",
            "ok",
            "Table ARP lue (" + ("ipNetToPhysical" if ok.get("arp_physical") else "ipNetToMedia") + ").",
        )
    else:
        add(
            "Apprentissage IP ↔ MAC (ARP)",
            "na",
            "Pas de table ARP : normal pour un switch de niveau 2.",
            "Si cet équipement route les VLAN (FortiGate, cœur de réseau), autorisez 1.3.6.1.2.1.4.22 / 1.3.6.1.2.1.4.35 dans la vue SNMP ; sinon l'IP des endpoints restera inconnue.",
        )

    mac_ok = ok.get("fdb_qbridge") or ok.get("fdb_bridge")
    add(
        "Localisation en direct",
        "ok" if mac_ok else "missing",
        "Recherche MAC possible sur cet équipement." if mac_ok else "Recherche MAC impossible sur cet équipement.",
        "" if mac_ok else "Ajoutez les switchs où les postes se branchent.",
    )
    return out


async def diagnose(client: Client) -> dict[str, Any]:
    checks, driver_name = await run_checks(client)
    return {
        "driver": driver_name,
        "checks": [asdict(c) for c in checks],
        "verdicts": [asdict(v) for v in verdicts(checks, driver_name)],
    }


_ICON = {"ok": "✔", "empty": "·", "error": "✘", "partial": "~", "missing": "✘", "na": "–"}


def render_text(result: dict[str, Any]) -> str:
    """Rapport lisible (CLI, tickets) : tables lues puis conséquences et conseils."""
    lines = [f"Pilote détecté : {result['driver']}", "", "Tables SNMP :"]
    for c in result["checks"]:
        lines.append(
            f"  {_ICON[c['status']]} {c['title']} — {c['rows']} ligne(s)" + (f" — {c['detail']}" if c["detail"] else "")
        )
    lines += ["", "Fonctions de LastHop :"]
    for v in result["verdicts"]:
        lines.append(f"  {_ICON[v['level']]} {v['feature']} : {v['message']}")
        if v["advice"]:
            lines.append(f"      → {v['advice']}")
    return "\n".join(lines)
