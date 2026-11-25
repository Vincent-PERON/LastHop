"""Client SNMP asynchrone — LECTURE SEULE.

Seul module important pysnmp. Il n'expose que GET, GETNEXT-walk et GETBULK-walk : aucune opération d'écriture
n'existe dans le code (un test échoue si une primitive d'écriture apparaît dans `app/`).
Les valeurs reçues d'un équipement sont NON FIABLES : toujours passer par `as_text` avant stockage/affichage.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any

from pyasn1.type import univ
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.proto import errind

SnmpValue = int | bytes | str | None

AUTH_PROTOCOLS: dict[str, Any] = {
    "sha1": usmHMACSHAAuthProtocol,  # héritage : exige allow_legacy_algos
    "sha224": usmHMAC128SHA224AuthProtocol,
    "sha256": usmHMAC192SHA256AuthProtocol,
    "sha384": usmHMAC256SHA384AuthProtocol,
    "sha512": usmHMAC384SHA512AuthProtocol,
}
PRIV_PROTOCOLS: dict[str, Any] = {
    "aes128": usmAesCfb128Protocol,
    "aes192": usmAesCfb192Protocol,
    "aes256": usmAesCfb256Protocol,
}
# MD5 et DES ne sont volontairement pas disponibles.

# Codes d'erreur stables, affichables à l'utilisateur (messages explicites au lot e)
TIMEOUT = "DEVICE_UNREACHABLE"
AUTH_FAILURE = "SNMP_AUTH_FAILURE"
SNMP_ERROR = "SNMP_ERROR"


class SnmpError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SnmpCredential:
    version: str  # "v2c" | "v3"
    community: str | None = field(default=None, repr=False)
    username: str | None = None
    auth_proto: str | None = None
    priv_proto: str | None = None
    auth_key: str | None = field(default=None, repr=False)
    priv_key: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class SnmpTarget:
    host: str
    credential: SnmpCredential
    port: int = 161
    timeout_s: float = 3.0
    retries: int = 1
    context_name: str = ""  # v3 : contextName ; "vlan-<id>" = instance VLAN Cisco (en v2c : community@<id>)


_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def as_text(value: SnmpValue, limit: int = 255, multiline: bool = False) -> str:
    """Nettoie une valeur texte venant d'un équipement (non fiable) : décodage tolérant, caractères de contrôle retirés,
    longueur bornée. N'échappe PAS le HTML : l'échappement se fait au rendu (pas de v-html côté front)."""
    if value is None:
        return ""
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    text = text.replace("\r\n", "\n")
    if not multiline:
        text = text.split("\n", 1)[0]
    return _CTRL.sub("", text).strip()[:limit]


def _convert(v: Any) -> SnmpValue:
    if isinstance(v, univ.Null):  # NoSuchObject / NoSuchInstance / EndOfMibView
        return None
    if isinstance(v, univ.Integer):
        return int(v)
    if isinstance(v, univ.OctetString):
        return bytes(v)
    if isinstance(v, ObjectIdentity):  # valeur de type OID : str() donne la forme numérique pointée
        return str(v)
    if isinstance(v, univ.ObjectIdentifier):
        return ".".join(str(n) for n in v.asTuple())
    return str(v.prettyPrint())


def _map_error(indication: Any) -> str:
    if isinstance(indication, errind.RequestTimedOut):
        return TIMEOUT
    if isinstance(
        indication,
        errind.UnknownUserName
        | errind.WrongDigest
        | errind.DecryptionError
        | errind.UnsupportedSecurityLevel
        | errind.UnknownEngineID
        | errind.NotInTimeWindow
        | errind.AuthenticationError,
    ):
        return AUTH_FAILURE
    return SNMP_ERROR


class SnmpClient:
    def __init__(self, target: SnmpTarget) -> None:
        self.t = target
        self._engine: SnmpEngine | None = None
        self._transport: UdpTransportTarget | None = None

    async def __aenter__(self) -> SnmpClient:
        self._engine = SnmpEngine()
        self._transport = await UdpTransportTarget.create(
            (self.t.host, self.t.port), timeout=self.t.timeout_s, retries=self.t.retries
        )
        return self

    async def __aexit__(
        self, et: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None
    ) -> None:
        if self._engine is not None:
            self._engine.close_dispatcher()
        self._engine = self._transport = None

    def _auth(self) -> CommunityData | UsmUserData:
        c = self.t.credential
        if c.version == "v2c":
            community = c.community or ""
            if self.t.context_name.startswith("vlan-"):  # indexation Cisco par VLAN
                community = f"{community}@{self.t.context_name[5:]}"
            return CommunityData(community, mpModel=1)  # noqa: S508 - v2c optionnel, désactivé par défaut (paramètre admin)
        if not (
            c.username
            and c.auth_key
            and c.priv_key
            and c.auth_proto in AUTH_PROTOCOLS
            and c.priv_proto in PRIV_PROTOCOLS
        ):
            raise SnmpError(SNMP_ERROR)  # SNMPv3 : uniquement authPriv, algorithmes de la liste blanche
        return UsmUserData(
            c.username,
            authKey=c.auth_key,
            privKey=c.priv_key,
            authProtocol=AUTH_PROTOCOLS[c.auth_proto],
            privProtocol=PRIV_PROTOCOLS[c.priv_proto],
        )

    def _ctx(self) -> ContextData:
        # en v2c le contexte n'existe pas (la VLAN passe par la community)
        return ContextData(contextName=self.t.context_name if self.t.credential.version == "v3" else "")

    def _ready(self) -> tuple[SnmpEngine, UdpTransportTarget]:
        if self._engine is None or self._transport is None:
            raise RuntimeError("client non ouvert")
        return self._engine, self._transport

    async def get(self, *oids: str) -> dict[str, SnmpValue]:
        engine, transport = self._ready()
        ind, status, _, binds = await get_cmd(
            engine,
            self._auth(),
            transport,
            self._ctx(),
            *[ObjectType(ObjectIdentity(o)) for o in oids],
        )
        if ind:
            raise SnmpError(_map_error(ind))
        if status:
            raise SnmpError(SNMP_ERROR)
        return {b[0].get_oid().prettyPrint(): _convert(b[1]) for b in binds}

    async def walk(
        self, oid: str, max_repetitions: int = 25, max_rows: int = 100_000
    ) -> AsyncIterator[tuple[str, SnmpValue]]:
        """GETBULK sur un sous-arbre ; s'arrête à la fin du sous-arbre ou à `max_rows` (borne anti-DoS mémoire)."""
        engine, transport = self._ready()
        rows = 0
        async for ind, status, _, binds in bulk_walk_cmd(
            engine,
            self._auth(),
            transport,
            self._ctx(),
            0,
            max_repetitions,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if ind:
                raise SnmpError(_map_error(ind))
            if status:
                raise SnmpError(SNMP_ERROR)
            for b in binds:
                yield b[0].get_oid().prettyPrint(), _convert(b[1])
                rows += 1
                if rows >= max_rows:
                    return
