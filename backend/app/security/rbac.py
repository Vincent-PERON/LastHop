"""RBAC : permissions fines, rôles et portées de tokens d'API."""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field

from app.db.models import Role


class Perm(enum.StrEnum):
    inventory_read = "inventory:read"  # liste/fiche des équipements, tableau de bord : super admin uniquement
    topology_read = "topology:read"  # graphe de topologie et liste des sites
    inventory_write = "inventory:write"
    credentials_write = "credentials:write"
    search = "search"
    realtime = "realtime"
    export = "export"
    audit_read = "audit:read"
    settings_write = "settings:write"
    users_read = "users:read"
    backups_read = "backups:read"  # contenu des configurations : très sensible, administrateurs seulement
    backups_run = "backups:run"
    ports_configure = (
        "ports:configure"  # MODIFIER la configuration d'un port (VLAN, PVID, mode) : super admin uniquement
    )
    auth_manage = "auth:manage"  # fournisseurs d'identité (OIDC, LDAP) : super admin uniquement
    tokens_manage = "tokens:manage"  # création / liste / révocation des tokens d'API : super admin uniquement


_VIEWER = frozenset({Perm.search, Perm.topology_read})  # recherche IP/MAC + topologie, rien d'autre
_OPERATOR = _VIEWER | {Perm.realtime, Perm.export}
ROLE_PERMS: dict[Role, frozenset[Perm]] = {
    Role.viewer: _VIEWER,
    Role.operator: frozenset(_OPERATOR),
    Role.admin: frozenset(Perm),
}

# Portées autorisées pour un token d'API : jamais d'écriture ni d'administration.
TOKEN_SCOPES: dict[str, frozenset[Perm]] = {
    "read": frozenset({Perm.inventory_read}),
    "topology": frozenset({Perm.topology_read}),
    "search": frozenset({Perm.search}),
    "realtime": frozenset({Perm.realtime}),
    "export": frozenset({Perm.export}),
}


def token_permissions(scopes: list[str], role: Role) -> frozenset[Perm]:
    """Un token ne peut jamais dépasser les droits actuels de son propriétaire (rétrogradation immédiate)."""
    granted: set[Perm] = set()
    for s in scopes:
        granted |= TOKEN_SCOPES.get(s, frozenset())
    return frozenset(granted) & ROLE_PERMS[role]


@dataclass(frozen=True)
class Principal:
    kind: str  # "user" | "token"
    user_id: uuid.UUID
    label: str
    role: Role
    permissions: frozenset[Perm]
    session_hash: str | None = None
    csrf: str | None = None
    token_id: uuid.UUID | None = None
    scopes: list[str] = field(default_factory=list)
    auth_source: str = "token"  # local | oidc | ldap | token
    must_change_password: bool = False
    totp_enabled: bool = False

    @property
    def actor_type(self) -> str:
        return self.kind

    @property
    def actor_id(self) -> str:
        return str(self.token_id if self.kind == "token" and self.token_id else self.user_id)
