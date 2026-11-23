"""Fournisseurs d'identité : validation de la configuration, stockage chiffré des secrets, résolution des rôles.

Règle centrale : un compte fédéré (OIDC/LDAP) n'est JAMAIS super admin. Les groupes ne peuvent attribuer que
`operator` ou `viewer` ; le rôle `admin` n'existe que pour le compte local (et la base l'impose par contrainte)."""

from __future__ import annotations

import ipaddress
import re
import uuid
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import AuthProvider, Role
from app.security.crypto import KeyRing
from app.security.targets import is_forbidden_address

PRESETS_OIDC = ("generic", "keycloak", "entra", "google")
PRESETS_LDAP = ("ldap", "ad")
FEDERATED_ROLES = (Role.operator, Role.viewer)  # du plus au moins privilégié
_HOST = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_ENTRA_ISSUER = re.compile(r"^https://login\.microsoftonline\.com/[0-9a-fA-F-]{36}/v2\.0$")
GOOGLE_ISSUER = "https://accounts.google.com"


class ProviderConfigError(ValueError):
    """Configuration invalide ; message affichable (jamais de secret)."""


def check_host(host: str, env: str) -> None:
    """Anti-SSRF : refuse boucle locale, link-local (métadonnées cloud), multicast, non spécifiée. Les réseaux privés
    restent autorisés (un Keycloak ou un annuaire interne est normal). En dev (tests, labo) la boucle locale passe."""
    h = host.strip("[]").lower()
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        if h == "localhost" and env == "prod":
            raise ProviderConfigError("hôte interdit") from None
        if not _HOST.match(h):
            raise ProviderConfigError("nom d'hôte invalide") from None
        return
    if is_forbidden_address(ip) and not (ip.is_loopback and env != "prod"):
        raise ProviderConfigError("adresse interdite")


def _split_url(url: str, schemes: tuple[str, ...]) -> tuple[str, str, int | None]:
    from urllib.parse import urlsplit

    p = urlsplit(url)
    if p.scheme not in schemes or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise ProviderConfigError("URL invalide")
    try:
        port = p.port
    except ValueError:
        raise ProviderConfigError("port invalide") from None
    return p.scheme, p.hostname, port


class OidcConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issuer: Annotated[str, Field(min_length=8, max_length=512)]
    client_id: Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[\w.:@\-]+$")]
    scopes: Annotated[str, Field(max_length=200, pattern=r"^[\w.:\-\/ ]+$")] = "openid profile email"
    groups_claim: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[\w.:\-]+$")] = "groups"
    allowed_domains: Annotated[list[str], Field(max_length=50)] = []
    require_email_verified: bool = False
    required_acr: Annotated[str | None, Field(max_length=64)] = None

    @field_validator("allowed_domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        out = [d.strip().lower() for d in v]
        if any(not _HOST.match(d) for d in out):
            raise ValueError("domaine invalide")
        return sorted(set(out))

    @field_validator("scopes")
    @classmethod
    def _scopes(cls, v: str) -> str:
        if "openid" not in v.split():
            raise ValueError("le scope openid est obligatoire")
        return " ".join(v.split())


class LdapConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: Annotated[str, Field(min_length=8, max_length=300)]
    starttls: bool = False
    insecure: bool = False  # reconnaissance explicite : mots de passe en clair sur le réseau (laboratoire uniquement)
    ca_pem: Annotated[str | None, Field(max_length=40000)] = None
    bind_dn: Annotated[str | None, Field(max_length=512)] = None  # compte de service (lecture seule)
    bind_dn_template: Annotated[str | None, Field(max_length=512)] = None  # ex. "{username}@corp.local" (bind direct)
    user_base: Annotated[str, Field(min_length=1, max_length=512)]
    user_filter: Annotated[str, Field(min_length=3, max_length=512)] = "(uid={username})"
    uid_attr: Annotated[str, Field(max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9-]*$")] = ""  # vide = DN
    display_attr: Annotated[str, Field(max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9-]*$")] = "cn"
    mail_attr: Annotated[str, Field(max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9-]*$")] = "mail"
    group_attr: Annotated[str, Field(max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9-]*$")] = "memberOf"
    group_base: Annotated[str | None, Field(max_length=512)] = None
    group_filter: Annotated[str, Field(max_length=512)] = "(member={user_dn})"

    @field_validator("uid_attr", mode="before")
    @classmethod
    def _uid_none(cls, v: Any) -> Any:
        return "" if v is None else v

    @field_validator("user_filter")
    @classmethod
    def _filter(cls, v: str) -> str:
        if v.count("{username}") != 1 or not (v.startswith("(") and v.endswith(")")):
            raise ValueError("le filtre doit être entre parenthèses et contenir {username} une seule fois")
        return v

    @field_validator("group_filter")
    @classmethod
    def _gfilter(cls, v: str) -> str:
        if v.count("{user_dn}") != 1:
            raise ValueError("le filtre de groupes doit contenir {user_dn} une seule fois")
        return v

    @field_validator("bind_dn_template")
    @classmethod
    def _tmpl(cls, v: str | None) -> str | None:
        if v is not None and v.count("{username}") != 1:
            raise ValueError("le modèle doit contenir {username} une seule fois")
        return v or None

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        if not v:
            return None
        if "BEGIN CERTIFICATE" not in v or "PRIVATE KEY" in v:
            raise ValueError("PEM de certificat attendu (jamais une clé privée)")
        return v.strip() + "\n"


def validate_config(kind: str, preset: str, config: dict[str, Any], *, env: str) -> dict[str, Any]:
    """Valide et normalise la configuration non secrète ; lève ProviderConfigError (ou ValueError pydantic)."""
    if kind == "oidc":
        if preset not in PRESETS_OIDC:
            raise ProviderConfigError("préréglage inconnu")
        c = OidcConfig.model_validate(config)
        scheme, host, _ = _split_url(c.issuer, ("https",) if env == "prod" else ("https", "http"))
        check_host(host, env)
        c.issuer = c.issuer.rstrip("/")
        if preset == "google":
            # Google ne fournit pas les groupes : l'accès est limité par le domaine Workspace (claim hd), jamais ouvert
            # à tout compte Google.
            if c.issuer != GOOGLE_ISSUER:
                raise ProviderConfigError("l'émetteur Google est fixe")
            if not c.allowed_domains:
                raise ProviderConfigError("indiquez au moins un domaine Google Workspace autorisé")
            c.require_email_verified = True
        if preset == "entra" and not _ENTRA_ISSUER.match(c.issuer) and env == "prod":
            raise ProviderConfigError("émetteur Entra ID attendu : https://login.microsoftonline.com/<tenant-id>/v2.0")
        return c.model_dump()
    if kind == "ldap":
        if preset not in PRESETS_LDAP:
            raise ProviderConfigError("préréglage inconnu")
        lc = LdapConfig.model_validate(config)
        scheme, host, _ = _split_url(lc.url, ("ldap", "ldaps"))
        check_host(host, env)
        if scheme == "ldaps" and lc.starttls:
            raise ProviderConfigError("StartTLS est inutile avec ldaps://")
        if scheme == "ldap" and not lc.starttls and not lc.insecure:
            raise ProviderConfigError(
                "LDAP non chiffré : activez StartTLS, utilisez ldaps://, ou cochez « connexion non chiffrée »"
            )
        if lc.insecure and (scheme == "ldaps" or lc.starttls):
            lc.insecure = False  # la reconnaissance n'a de sens que pour une connexion réellement en clair
        return lc.model_dump()
    raise ProviderConfigError("type inconnu")


def validate_role_map(role_map: dict[str, str]) -> dict[str, str]:
    if len(role_map) > 100:
        raise ProviderConfigError("trop de correspondances de groupes")
    out: dict[str, str] = {}
    for group, role in role_map.items():
        if not (1 <= len(group) <= 512):
            raise ProviderConfigError("nom de groupe invalide")
        if role not in (r.value for r in FEDERATED_ROLES):
            raise ProviderConfigError("un groupe externe ne peut donner que « operator » ou « viewer »")
        out[group] = role
    return out


def resolve_role(role_map: dict[str, str], default_role: str | None, groups: list[str]) -> Role | None:
    """Rôle le plus élevé parmi les groupes mappés (comparaison insensible à la casse), sinon le rôle par défaut du
    fournisseur, sinon refus. Jamais `admin`."""
    wanted = {g.lower(): r for g, r in role_map.items()}
    got = {Role(wanted[g.lower()]) for g in groups if g.lower() in wanted}
    for role in FEDERATED_ROLES:
        if role in got:
            return role
    return Role(default_role) if default_role in ("viewer", "operator") else None


# --- secrets chiffrés (AES-GCM, AAD liée à la ligne)
def _aad(provider_id: uuid.UUID) -> str:
    return f"auth_providers:{provider_id}"


def seal_secret(keyring: KeyRing, provider_id: uuid.UUID, secret: str) -> tuple[bytes, str]:
    return keyring.encrypt(secret.encode(), _aad(provider_id)), keyring.active_kid


def open_secret(keyring: KeyRing, row: AuthProvider) -> str | None:
    if row.secret_blob is None:
        return None
    return keyring.decrypt(row.secret_blob, _aad(row.id)).decode()


ProviderKind = Literal["oidc", "ldap"]
