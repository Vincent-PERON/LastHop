"""Authentification LDAP directe (Active Directory, OpenLDAP, FreeIPA…) en lecture seule.

Deux modes :
- recherche : compte de service en lecture seule → DN de l'utilisateur → bind avec SON mot de passe ;
- bind direct par modèle (`{username}@corp.local`, `uid={username},ou=people,…`).

Garde-fous : mot de passe vide refusé (un bind simple à mot de passe vide est un bind ANONYME réussi sur la plupart
des annuaires), nom d'utilisateur à jeu de caractères restreint, valeurs échappées dans les filtres, TLS ≥ 1.2 avec
vérification du certificat et du nom (autorité fournie ou système), connexions en lecture seule, délais bornés.
Les appels sont bloquants (ldap3) : à exécuter via asyncio.to_thread."""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ldap3 import SUBTREE, Connection, Server, Tls  # type: ignore[import-untyped]
from ldap3.core.exceptions import LDAPException  # type: ignore[import-untyped]
from ldap3.utils.conv import escape_filter_chars  # type: ignore[import-untyped]

from app.services.auth_providers import LdapConfig

USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")
MAX_PASSWORD = 512
TIMEOUT_S = 8


class LdapError(Exception):
    """`code` : unreachable | service_bind | not_found | ambiguous | bad_credentials | invalid_input."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class LdapIdentity:
    dn: str
    uid: str
    display_name: str | None = None
    email: str | None = None
    groups: list[str] = field(default_factory=list)  # DN complets ET noms courts (CN), pour la correspondance de rôles


def _server(cfg: LdapConfig) -> Server:
    p = urlsplit(cfg.url)
    use_ssl = p.scheme == "ldaps"
    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLS_CLIENT,
        ca_certs_data=cfg.ca_pem or None,
        valid_names=[p.hostname] if p.hostname else None,
        ssl_options=[ssl.OP_NO_SSLv2, ssl.OP_NO_SSLv3, ssl.OP_NO_TLSv1, ssl.OP_NO_TLSv1_1],
    )
    return Server(
        p.hostname or "",
        port=p.port or (636 if use_ssl else 389),
        use_ssl=use_ssl,
        tls=tls if (use_ssl or cfg.starttls) else None,
        connect_timeout=TIMEOUT_S,
        get_info="NO_INFO",
    )


def _connect(cfg: LdapConfig, user: str | None, password: str | None) -> Connection:
    """Ouvre, applique StartTLS si demandé, puis lie. Lève LdapError('unreachable') ou ('bad_credentials')."""
    conn = Connection(
        _server(cfg),
        user=user,
        password=password,
        auto_bind=False,
        receive_timeout=TIMEOUT_S,
        raise_exceptions=False,
        read_only=True,  # ldap3 refuse toute opération d'écriture sur cette connexion
    )
    try:
        conn.open(read_server_info=False)  # lève une exception si l'annuaire est injoignable / TLS refusé
        if conn.closed:
            raise LdapError("unreachable")
        if cfg.starttls and not conn.start_tls(read_server_info=False):
            raise LdapError("unreachable")
        if user is None:
            return conn  # lien anonyme (recherche sans compte de service)
        if not conn.bind(read_server_info=False):
            raise LdapError("bad_credentials")
        return conn
    except LDAPException as exc:
        raise LdapError("unreachable") from exc


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list | tuple) else [value]
    return [i.decode("utf-8", "replace") if isinstance(i, bytes) else str(i) for i in items if i not in (None, "")]


def _short_name(dn: str) -> str | None:
    """Valeur du premier RDN `cn=` ou `ou=` (AD/OpenLDAP : cn ; GLAuth, certains annuaires : ou)."""
    m = re.match(r"^\s*(?:cn|ou)=((?:[^,\\]|\\.)+)", dn, re.IGNORECASE)
    return m.group(1).replace("\\,", ",") if m else None


def _search_user(conn: Connection, cfg: LdapConfig, username: str) -> tuple[str, dict[str, Any]]:
    flt = cfg.user_filter.replace("{username}", escape_filter_chars(username))
    attrs = [a for a in {cfg.uid_attr, cfg.display_attr, cfg.mail_attr, cfg.group_attr} if a]
    if not conn.search(cfg.user_base, flt, search_scope=SUBTREE, attributes=attrs, size_limit=2):
        entries: list[dict[str, Any]] = []
    else:
        entries = [e for e in (conn.response or []) if e.get("type") == "searchResEntry"]
    if not entries:
        raise LdapError("not_found")
    if len(entries) > 1:
        raise LdapError("ambiguous")
    return str(entries[0]["dn"]), dict(entries[0].get("attributes") or {})


def _group_names(conn: Connection, cfg: LdapConfig, dn: str, attrs: dict[str, Any]) -> list[str]:
    groups = _as_list(attrs.get(cfg.group_attr))
    if cfg.group_base:
        flt = cfg.group_filter.replace("{user_dn}", escape_filter_chars(dn))
        if conn.search(cfg.group_base, flt, search_scope=SUBTREE, attributes=["cn"], size_limit=500):
            groups += [str(e["dn"]) for e in (conn.response or []) if e.get("type") == "searchResEntry"]
    out: list[str] = []
    for g in groups:
        out.append(g)
        cn = _short_name(g)
        if cn:
            out.append(cn)
    return sorted(set(out))


def authenticate(cfg: LdapConfig, bind_password: str | None, username: str, password: str) -> LdapIdentity:
    if not USERNAME_RE.match(username) or not password or len(password) > MAX_PASSWORD:
        raise LdapError("invalid_input")
    opened: list[Connection] = []
    try:
        if cfg.bind_dn_template:  # bind direct : le mot de passe de l'utilisateur sert aussi à lire ses attributs
            user_conn = _connect(cfg, cfg.bind_dn_template.replace("{username}", username), password)
            opened.append(user_conn)
            dn, attrs = _search_user(user_conn, cfg, username)
            reader = user_conn
        else:
            try:
                svc = _connect(cfg, cfg.bind_dn, bind_password if cfg.bind_dn else None)
            except LdapError as exc:
                raise LdapError("service_bind" if exc.code == "bad_credentials" else exc.code) from None
            opened.append(svc)
            dn, attrs = _search_user(svc, cfg, username)
            user_conn = _connect(
                cfg, dn, password
            )  # preuve de possession du mot de passe : bind avec l'identité trouvée
            opened.append(user_conn)
            reader = svc
        uid = (_as_list(attrs.get(cfg.uid_attr)) or [dn])[0] if cfg.uid_attr else dn
        names, mails = _as_list(attrs.get(cfg.display_attr)), _as_list(attrs.get(cfg.mail_attr))
        display = names[0] if names else None
        mail = mails[0] if mails else None
        return LdapIdentity(
            dn=dn,
            uid=uid[:255],
            display_name=display[:255] if display else None,
            email=mail[:320] if mail else None,
            groups=_group_names(reader, cfg, dn, attrs),
        )
    finally:
        for c in opened:
            try:
                c.unbind()
            except LDAPException:  # pragma: no cover - fermeture best effort
                pass


def check_connection(cfg: LdapConfig, bind_password: str | None) -> str:
    """Contrôle de configuration (admin) : joignabilité, TLS, compte de service. Retourne un message lisible."""
    conn = _connect(cfg, cfg.bind_dn, bind_password if cfg.bind_dn else None)
    try:
        mode = "ldaps" if cfg.url.startswith("ldaps") else ("StartTLS" if cfg.starttls else "non chiffré")
        who = "compte de service authentifié" if cfg.bind_dn else "lien anonyme"
        return f"Connexion réussie ({mode}, {who})."
    finally:
        conn.unbind()
