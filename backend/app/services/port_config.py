# ruff: noqa: E501  (messages d'aide affichés à l'utilisateur, volontairement lisibles tels quels)
"""Modification de la configuration d'un port (VLAN d'accès, PVID/VLAN natif, mode accès/trunk) par SSH.

C'est le SEUL module de LastHop qui envoie des commandes de CONFIGURATION à un équipement (le SNMP reste strictement en
lecture). Garde-fous :
- désactivé tant que le réglage `port_config_enabled` n'est pas activé par le super admin ;
- le VLAN doit exister sur l'équipement (VLAN lus par SNMP), jamais un identifiant libre ;
- aperçu obligatoire : les commandes exactes et l'état actuel sont montrés avant toute application ;
- alerte renforcée (saisie du nom du port) pour un uplink, un trunk, un passage trunk → accès ou un changement de VLAN natif ;
- à l'application, les commandes sont recalculées depuis l'état courant : si le port a changé depuis l'aperçu, refus ;
- on s'arrête à la première erreur de l'équipement (rien n'est enregistré dans ce cas) ;
- chaque aperçu et chaque application sont audités (commandes comprises).
Les syntaxes sont écrites d'après la documentation des constructeurs et NON validées sur du matériel réel."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

MAX_VLANS_IN_TRUNK = 200


class PortConfigError(ValueError):
    """Demande refusée ; le message (français) est affiché tel quel à l'utilisateur."""


@dataclass(frozen=True)
class PortChange:
    mode: str  # access | trunk
    access_vlan: int | None = None
    native_vlan: int | None = None  # trunk : VLAN non étiqueté = PVID
    allowed_vlans: tuple[int, ...] = ()  # trunk : VLAN étiquetés autorisés
    save: bool = True  # enregistrer la configuration (sinon perdue au redémarrage)


@dataclass(frozen=True)
class PortState:
    """État actuel du port lu par SNMP (None = inconnu)."""

    mode: str | None
    pvid: int | None
    tagged: tuple[int, ...] = ()


@dataclass(frozen=True)
class Alert:
    level: str  # danger | warn | info
    text: str


@dataclass
class Plan:
    commands: list[str]
    save_commands: list[str]
    alerts: list[Alert] = field(default_factory=list)

    @property
    def requires_ack(self) -> bool:
        return any(a.level == "danger" for a in self.alerts)

    def digest(self) -> str:
        return hashlib.sha256(json.dumps([self.commands, self.save_commands]).encode()).hexdigest()


# --------------------------------------------------------------------------------------------------- validation
def validate_change(change: PortChange, known_vlans: set[int]) -> None:
    if not known_vlans:
        raise PortConfigError(
            "Les VLAN de cet équipement ne sont pas connus : lancez d'abord une collecte de topologie (SNMP)."
        )

    def check(v: int | None, what: str) -> int:
        if v is None:
            raise PortConfigError(f"{what} obligatoire.")
        if not 1 <= v <= 4094:
            raise PortConfigError(f"{what} : identifiant de VLAN invalide ({v}).")
        if v not in known_vlans:
            raise PortConfigError(
                f"{what} : le VLAN {v} n'existe pas sur cet équipement. Seuls les VLAN connus de l'équipement sont autorisés."
            )
        return v

    if change.mode == "access":
        check(change.access_vlan, "VLAN d'accès")
        if change.native_vlan is not None or change.allowed_vlans:
            raise PortConfigError("Un port d'accès n'a ni VLAN natif ni VLAN autorisés.")
    elif change.mode == "trunk":
        check(change.native_vlan, "VLAN natif (PVID)")
        if len(change.allowed_vlans) > MAX_VLANS_IN_TRUNK:
            raise PortConfigError("Trop de VLAN autorisés.")
        for v in change.allowed_vlans:
            check(v, "VLAN autorisé")
        if change.access_vlan is not None:
            raise PortConfigError("Un trunk n'a pas de VLAN d'accès.")
    else:
        raise PortConfigError("Mode inconnu : « access » ou « trunk » attendu.")


# --------------------------------------------------------------------------------------------------- commandes
@dataclass(frozen=True)
class ConfigProfile:
    enter: tuple[str, ...]
    exit: tuple[str, ...]
    save: tuple[str, ...]


PROFILES = {
    "cisco_ios": ConfigProfile(("configure terminal",), ("end",), ("write memory",)),
    "comware": ConfigProfile(("system-view",), ("return",), ("save force",)),
    "aruba_cx": ConfigProfile(("configure terminal",), ("end",), ("write memory",)),
    "aruba_os": ConfigProfile(("configure",), ("end",), ("write memory",)),
}


def variant(driver: str, sys_object_id: str | None) -> str | None:
    """Syntaxe à utiliser. `aruba_os` regroupe AOS-CX (entreprise 47196) et ArubaOS-Switch/ProCurve : deux syntaxes différentes."""
    if driver == "aruba_os":
        return "aruba_cx" if (sys_object_id or "").startswith("1.3.6.1.4.1.47196.") else "aruba_os"
    return driver if driver in PROFILES else None


def _need_native(native: int | None) -> int:
    if native is None:
        raise PortConfigError("VLAN natif (PVID) obligatoire pour un trunk.")
    return native


def _csv(vlans: list[int] | set[int]) -> str:
    return ",".join(str(v) for v in sorted(vlans))


def build_commands(syntax: str, port: str, current: PortState, change: PortChange) -> list[str]:
    """Commandes de configuration (après l'entrée en mode configuration), spécifiques au constructeur."""
    was_trunk = current.mode in ("trunk", "hybrid")
    native, allowed = change.native_vlan, set(change.allowed_vlans)
    if syntax == "cisco_ios":
        out = [f"interface {port}"]
        if change.mode == "access":
            if was_trunk or current.mode is None:
                out += ["no switchport trunk native vlan", "no switchport trunk allowed vlan"]
            out += ["switchport mode access", f"switchport access vlan {change.access_vlan}"]
        else:
            native = _need_native(native)
            out += [
                "switchport mode trunk",
                f"switchport trunk native vlan {native}",
                f"switchport trunk allowed vlan {_csv(allowed | {native})}",
            ]
        return out
    if syntax == "comware":
        out = [f"interface {port}"]
        if change.mode == "access":
            out += ["port link-type access", f"port access vlan {change.access_vlan}"]
        else:
            native = _need_native(native)
            out += [
                "port link-type trunk",
                "undo port trunk permit vlan all",
                f"port trunk permit vlan {' '.join(str(v) for v in sorted(allowed | {native}))}",
                f"port trunk pvid vlan {native}",
            ]
        return out
    if syntax == "aruba_cx":
        out = [f"interface {port}"]
        if change.mode == "access":
            if was_trunk or current.mode is None:
                out += ["no vlan trunk native", "no vlan trunk allowed"]
            out += [f"vlan access {change.access_vlan}"]
        else:
            native = _need_native(native)
            if was_trunk or current.mode is None:
                out += ["no vlan trunk allowed"]
            out += [f"vlan trunk native {native}", f"vlan trunk allowed {_csv(allowed | {native})}"]
        return out
    if syntax == "aruba_os":
        # ArubaOS-Switch : configuration par VLAN (« vlan N tagged/untagged PORT ») ; sans l'état actuel on ne sait pas
        # quels VLAN étiquetés retirer : refus plutôt que de laisser un port à moitié configuré.
        if current.mode is None:
            raise PortConfigError(
                "État actuel du port inconnu : lancez une collecte de topologie avant de le modifier."
            )
        out = []
        tagged_now = set(current.tagged)
        if change.mode == "access":
            out += [f"no vlan {v} tagged {port}" for v in sorted(tagged_now)]
            out += [f"vlan {change.access_vlan} untagged {port}"]
        else:
            native = _need_native(native)
            wanted = allowed - {native}
            out += [f"no vlan {v} tagged {port}" for v in sorted(tagged_now - wanted - {native})]
            out += [f"vlan {v} tagged {port}" for v in sorted(wanted - tagged_now)]
            out += [f"vlan {native} untagged {port}"]
        return out
    raise PortConfigError("La modification des ports n'est pas prise en charge pour ce type d'équipement.")


# --------------------------------------------------------------------------------------------------- alertes
def assess(
    *,
    port_name: str,
    current: PortState,
    change: PortChange,
    role: str,
    is_trunk: bool,
    neighbor_names: list[str],
    mac_count: int,
    mac_threshold: int,
    device_role: str,
) -> list[Alert]:
    a: list[Alert] = []
    uplink = role == "uplink" or is_trunk or bool(neighbor_names)
    if uplink:
        who = f" vers {', '.join(sorted(set(neighbor_names)))}" if neighbor_names else ""
        a.append(
            Alert(
                "danger",
                f"Le port {port_name} est un port d'UPLINK{who} : il relie cet équipement à d'autres équipements réseau. "
                "Une erreur peut couper l'accès à cet équipement et à tout ce qui se trouve derrière, y compris l'accès de LastHop.",
            )
        )
    if device_role in ("core", "distribution"):
        a.append(
            Alert(
                "danger",
                f"Cet équipement est un équipement de {'cœur' if device_role == 'core' else 'distribution'} : une erreur peut paralyser une grande partie du réseau.",
            )
        )
    if mac_count > mac_threshold and not uplink:
        a.append(
            Alert(
                "danger",
                f"{mac_count} adresses MAC sont apprises sur ce port : il dessert probablement un autre switch ou un point d'accès.",
            )
        )
    if current.mode == "trunk" and change.mode == "access":
        a.append(
            Alert("danger", "Passage d'un TRUNK à un port d'ACCÈS : tous les VLAN étiquetés seront retirés du port.")
        )
    if (
        current.mode in ("trunk", "hybrid")
        and change.mode == "trunk"
        and current.pvid
        and change.native_vlan
        and current.pvid != change.native_vlan
    ):
        a.append(
            Alert(
                "danger",
                f"Changement du VLAN natif (PVID) {current.pvid} → {change.native_vlan} : il doit être identique à l'autre extrémité du lien, sinon le trafic non étiqueté est mal aiguillé.",
            )
        )
    if change.mode == "trunk" and current.tagged:
        removed = sorted(set(current.tagged) - set(change.allowed_vlans) - {change.native_vlan or 0})
        if removed:
            a.append(
                Alert(
                    "danger",
                    f"VLAN retirés du trunk : {', '.join(map(str, removed))}. Le trafic de ces VLAN ne passera plus.",
                )
            )
    if current.mode == "hybrid" and change.mode == "access":
        a.append(
            Alert(
                "warn",
                f"Ce port porte des VLAN étiquetés ({', '.join(map(str, current.tagged))}), par exemple un VLAN voix : ils seront retirés.",
            )
        )
    if change.mode == "access" and mac_count and not uplink:
        a.append(
            Alert(
                "warn",
                f"{mac_count} poste(s) actuellement connecté(s) : ils changeront de VLAN et peuvent perdre leur adresse IP jusqu'au renouvellement du bail.",
            )
        )
    a.append(
        Alert(
            "info",
            "La session SSH de LastHop peut elle-même passer par ce port. Si l'équipement ne répond plus après l'application, la modification n'est pas annulée automatiquement.",
        )
    )
    if not change.save:
        a.append(
            Alert(
                "warn",
                "La configuration ne sera PAS enregistrée : elle sera perdue au prochain redémarrage de l'équipement.",
            )
        )
    return a


def make_plan(
    syntax: str,
    port: str,
    current: PortState,
    change: PortChange,
    *,
    alerts: list[Alert],
) -> Plan:
    profile = PROFILES[syntax]
    cmds = [*profile.enter, *build_commands(syntax, port, current, change), *profile.exit]
    return Plan(commands=cmds, save_commands=list(profile.save) if change.save else [], alerts=alerts)


def same_as_current(current: PortState, change: PortChange) -> bool:
    if change.mode == "access":
        return current.mode == "access" and current.pvid == change.access_vlan
    return (
        current.mode == "trunk"
        and current.pvid == change.native_vlan
        and (not current.tagged or set(current.tagged) == set(change.allowed_vlans) - {change.native_vlan or 0})
        and bool(current.tagged)
    )
