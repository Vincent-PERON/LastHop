# ruff: noqa: E501  (docstrings et expressions régulières lisibles telles quelles)
"""Travail HORS LIGNE sur un parcours SNMP (snmpwalk) : lecture, anonymisation, rejeu des collecteurs.

Cas d'usage : un client envoie la sortie de `snmpwalk` de son équipement ; on l'anonymise (adresses MAC/IP, noms, numéros
de série…), on la range comme jeu de test, et on rejoue les VRAIS collecteurs dessus (`WalkClient`) sans aucun réseau.
Rien ici ne parle SNMP sur le réseau."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass

from app.snmp.client import SnmpValue

Entry = tuple[str, str]  # (type snmprec, valeur snmprec)
Walk = dict[str, Entry]

# types snmprec (snmpsim) : 2 INTEGER, 4 OCTET STRING (texte), 4x OCTET STRING (hex), 6 OID, 64 IpAddress, 65 Counter32,
# 66 Gauge32, 67 TimeTicks, 70 Counter64
_TYPES_NUMERIC = {"2", "65", "66", "67", "70"}


def _oid_key(oid: str) -> tuple[int, ...]:
    return tuple(int(p) for p in oid.split(".") if p.isdigit())


# ------------------------------------------------------------------------------------------------ lecture
_LINE = re.compile(r"^\.?(\d+(?:\.\d+)+)\s*=\s*(.*)$")


def _hex_bytes(text: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", text).lower()


def parse_walk(text: str) -> Walk:
    """Sortie de `snmpwalk -On` (idéalement avec `-Ox` : chaînes en hexadécimal) ou fichier .snmprec (`oid|type|valeur`)."""
    out: Walk = {}
    lines = text.splitlines()
    if any("|" in ln and ln.split("|", 2)[0].replace(".", "").isdigit() for ln in lines[:5]):
        for ln in lines:
            parts = ln.rstrip("\n").split("|", 2)
            if len(parts) == 3 and parts[0].replace(".", "").isdigit():
                out[parts[0].lstrip(".")] = (parts[1], parts[2])
        return out
    pending: str | None = None
    for ln in lines:
        m = _LINE.match(ln)
        if m is None:
            if pending is not None and ln.strip():  # valeur multiligne (sysDescr) : on conserve la 1re ligne seulement
                continue
            continue
        oid, rest = m.group(1), m.group(2).strip()
        pending = oid
        kind, _, value = rest.partition(":")
        kind, value = kind.strip(), value.strip()
        if rest.startswith('"') or not _:  # chaîne sans type explicite
            out[oid] = ("4", rest.strip('"'))
        elif kind == "Hex-STRING":
            out[oid] = ("4x", _hex_bytes(value))
        elif kind == "STRING":
            out[oid] = ("4", value.strip('"'))
        elif kind == "INTEGER":
            num = re.match(r"^(?:[^\d(-]*\()?(-?\d+)", value)
            out[oid] = ("2", num.group(1) if num else "0")
        elif kind in ("Counter32", "Gauge32", "Unsigned32", "Counter64"):
            out[oid] = ({"Counter32": "65", "Counter64": "70"}.get(kind, "66"), re.sub(r"\D", "", value) or "0")
        elif kind == "Timeticks":
            m2 = re.match(r"^\((\d+)\)", value)
            out[oid] = ("67", m2.group(1) if m2 else "0")
        elif kind == "OID":
            out[oid] = ("6", value.lstrip("."))
        elif kind in ("IpAddress", "Network Address"):
            out[oid] = ("4x", _hex_bytes(value)) if ":" in value else ("64", value)
        # types inconnus ou « No Such… » : ignorés
    return out


def to_snmprec(walk: Walk) -> str:
    return "".join(f"{o}|{t}|{v}\n" for o, (t, v) in sorted(walk.items(), key=lambda kv: _oid_key(kv[0])))


def decode(entry: Entry) -> SnmpValue:
    """Même conversion que `SnmpClient` : entier, octets, OID en texte pointé."""
    t, v = entry
    if t in _TYPES_NUMERIC:
        return int(v) if v.lstrip("-").isdigit() else 0
    if t == "4x":
        return bytes.fromhex(v) if re.fullmatch(r"(?:[0-9a-fA-F]{2})*", v) else b""
    if t == "4":
        return v.encode("utf-8", "replace")
    if t == "64":
        return ipaddress.ip_address(v).packed if v.count(".") == 3 else b""
    return v.lstrip(".")  # OID


class WalkClient:
    """Compatible avec `SnmpClient` pour `get` / `walk` ; répond depuis un parcours en mémoire."""

    def __init__(self, walk: Walk) -> None:
        self._rows = sorted(((_oid_key(o), o, e) for o, e in walk.items()), key=lambda r: r[0])
        self._by_oid = {o: e for o, e in walk.items()}

    async def get(self, *oids: str) -> dict[str, SnmpValue]:
        return {o: decode(self._by_oid[o]) if o in self._by_oid else None for o in oids}

    async def walk(
        self, oid: str, max_repetitions: int = 25, max_rows: int = 100_000
    ) -> AsyncIterator[tuple[str, SnmpValue]]:
        prefix = _oid_key(oid)
        n = 0
        for key, o, entry in self._rows:
            if key[: len(prefix)] == prefix and len(key) > len(prefix):
                yield o, decode(entry)
                n += 1
                if n >= max_rows:
                    return


# ------------------------------------------------------------------------------------------- anonymisation
@dataclass
class AnonReport:
    macs: int = 0
    ips: int = 0
    strings: int = 0
    removed: int = 0


_MAC_TEXT = re.compile(r"\b([0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5})\b")
_IP_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# colonnes dont la valeur est une identité à masquer (texte libre) : sysContact/Location, alias, descriptions voisines, série
_SCRUB_STRING_OIDS = (
    ("1.3.6.1.2.1.1.4.0", "contact"),
    ("1.3.6.1.2.1.1.6.0", "location"),
)
_SCRUB_STRING_PREFIXES = (
    ("1.3.6.1.2.1.31.1.1.1.18.", "alias"),  # ifAlias
    ("1.0.8802.1.1.2.1.4.1.1.8.", "portdesc"),  # lldpRemPortDesc
    ("1.0.8802.1.1.2.1.4.1.1.10.", "sysdesc"),  # lldpRemSysDesc
    ("1.3.6.1.2.1.47.1.1.1.1.11.", "serial"),  # entPhysicalSerialNum
    ("1.3.6.1.2.1.47.1.1.1.1.8.", "hwrev"),
    ("1.3.6.1.2.1.47.1.1.1.1.9.", "fwrev"),
    ("1.3.6.1.2.1.47.1.1.1.1.10.", "swrev"),
    ("1.3.6.1.2.1.47.1.1.1.1.15.", "assetid"),
    ("1.3.6.1.4.1.9.9.23.1.2.1.1.5.", "cdpversion"),
)
_NAME_OIDS = ("1.3.6.1.2.1.1.5.0",)  # sysName
_NAME_PREFIXES = (
    "1.0.8802.1.1.2.1.4.1.1.9.",  # lldpRemSysName
    "1.3.6.1.4.1.9.9.23.1.2.1.1.6.",  # cdpCacheDeviceId
    "1.0.8802.1.1.2.1.3.3.0",  # lldpLocSysName
)


class Anonymizer:
    """Remplace de façon COHÉRENTE (même valeur d'origine → même valeur anonyme) les MAC, IP et noms. Le préfixe constructeur
    (OUI) des MAC est conservé : il sert à reconnaître le matériel, il ne désigne pas la machine. Sel aléatoire par
    exécution : l'anonymisation n'est pas réversible, même par force brute sur l'espace des adresses."""

    def __init__(self, salt: bytes | None = None) -> None:
        self.salt = salt or secrets.token_bytes(16)
        self.report = AnonReport()
        self._names: dict[str, str] = {}
        self._macs: dict[bytes, bytes] = {}
        self._ips: dict[str, str] = {}

    def _h(self, kind: str, data: bytes) -> bytes:
        return hmac.new(self.salt, kind.encode() + b"\0" + data, hashlib.sha256).digest()

    def mac(self, raw: bytes) -> bytes:
        if len(raw) != 6:
            return raw
        if raw not in self._macs:
            self._macs[raw] = raw[:3] + self._h("mac", raw)[:3]
            self.report.macs += 1
        return self._macs[raw]

    def ip(self, text: str) -> str:
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return text
        if addr.version != 4 or addr.is_unspecified or addr.is_multicast or str(addr) in ("255.255.255.255",):
            return text
        if text not in self._ips:
            h = self._h("ip", addr.packed)
            self._ips[text] = f"10.{h[0]}.{h[1]}.{max(1, min(254, h[2]))}"
            self.report.ips += 1
        return self._ips[text]

    def name(self, kind: str, value: str) -> str:
        key = f"{kind}:{value}"
        if key not in self._names:
            self._names[key] = f"{kind}-{len(self._names) + 1}"
            self.report.strings += 1
        return self._names[key]

    def _scrub_text(self, text: str) -> str:
        text = _MAC_TEXT.sub(
            lambda m: ":".join(f"{b:02x}" for b in self.mac(bytes.fromhex(re.sub(r"[:\-]", "", m.group(1))))), text
        )
        return _IP_TEXT.sub(lambda m: self.ip(m.group(0)), text)

    def _index_macs(self, oid: str) -> str:
        """Adresses MAC / IP encodées dans l'index d'un OID (FDB, ARP, LLDP) : remplacées de façon cohérente."""
        parts = oid.split(".")
        # dot1dTpFdb* : …17.4.3.1.<col>.<6 octets MAC>
        for base, vlan_in_index in (("1.3.6.1.2.1.17.4.3.1.", False), ("1.3.6.1.2.1.17.7.1.2.2.1.", True)):
            if oid.startswith(base):
                n = len(base.split(".")) - 1  # nombre de composantes du préfixe
                skip = n + 1 + (1 if vlan_in_index else 0)  # + colonne (+ VLAN)
                if len(parts) == skip + 6 and all(p.isdigit() for p in parts[skip:]):
                    new = self.mac(bytes(int(p) for p in parts[skip:]))
                    return ".".join(parts[:skip] + [str(b) for b in new])
        # ipNetToMedia (…4.22.1.<col>.<ifIndex>.<a.b.c.d>)
        if oid.startswith("1.3.6.1.2.1.4.22.1.") and len(parts) == 15:
            ip = self.ip(".".join(parts[11:]))
            return ".".join(parts[:11] + ip.split("."))
        # ipNetToPhysical (…4.35.1.<col>.<ifIndex>.<type=1>.<len=4>.<a.b.c.d>)
        if oid.startswith("1.3.6.1.2.1.4.35.1.") and len(parts) == 17 and parts[11:13] == ["1", "4"]:
            ip = self.ip(".".join(parts[13:]))
            return ".".join(parts[:13] + ip.split("."))
        return oid

    def apply(self, walk: Walk) -> Walk:
        out: Walk = {}
        for oid, (t, v) in walk.items():
            for scrub, label in _SCRUB_STRING_OIDS:
                if oid == scrub:
                    t, v = "4", self.name(label, v)
            if any(oid.startswith(p) for p, _ in _SCRUB_STRING_PREFIXES):
                label = next(lb for p, lb in _SCRUB_STRING_PREFIXES if oid.startswith(p))
                if v:
                    t, v = "4", self.name(label, v)
            elif oid in _NAME_OIDS or any(oid.startswith(p) for p in _NAME_PREFIXES):
                raw = decode((t, v))
                text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                t, v = "4", self.name("device", text)
            elif t == "4x" and len(v) == 12:  # adresse MAC (6 octets) : colonne physique ou identifiant de châssis LLDP
                v = self.mac(bytes.fromhex(v)).hex()
            elif (
                t == "4x"
                and oid.startswith(("1.3.6.1.4.1.9.9.23.1.2.1.1.4.", "1.0.8802.1.1.2.1.4.1.1.5."))
                and len(v) == 8
            ):
                v = "".join(f"{int(x):02x}" for x in self.ip(".".join(str(b) for b in bytes.fromhex(v))).split("."))
            elif t == "64":
                v = self.ip(v)
            elif t == "4":
                v = self._scrub_text(v)
            elif t == "4x":
                try:  # texte codé en hexadécimal (option -Ox de snmpwalk) : mêmes remplacements
                    text = bytes.fromhex(v).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    text = ""
                if text.isprintable() and text:
                    scrubbed = self._scrub_text(text)
                    if scrubbed != text:
                        v = scrubbed.encode().hex()
            out[self._index_macs(oid)] = (t, v)
        return out


def anonymize(walk: Walk, salt: bytes | None = None) -> tuple[Walk, AnonReport]:
    a = Anonymizer(salt)
    out = a.apply(walk)
    return out, a.report
