"""LDAP direct contre un annuaire réel (GLAuth) : ldap:// , ldaps:// avec autorité de test, filtres, rôles, refus."""

import httpx
import pytest
from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import make_provider

BIND_DN = "cn=svc-lasthop,ou=lasthop-svc,dc=lab,dc=local"
SVC_PW = "Svc-Test-Password-1"
ROLES = {"lasthop-operators": "operator", "lasthop-viewers": "viewer"}
BASE = {
    "url": "ldap://ldap.lasthop.test:3893",
    "starttls": False,
    "insecure": True,  # annuaire de test en clair : reconnaissance explicite
    "ca_pem": None,
    "bind_dn": BIND_DN,
    "bind_dn_template": None,
    "user_base": "dc=lab,dc=local",
    "user_filter": "(uid={username})",
    "uid_attr": "uid",
    "display_attr": "givenName",
    "mail_attr": "mail",
    "group_attr": "memberOf",
    "group_base": None,
    "group_filter": "(member={user_dn})",
}
ORIGIN = "https://lasthop.test"


def _ca() -> str:
    return open("/ldap-certs/ca.crt").read()


async def ldap_provider(cfg: dict | None = None, **kw) -> str:  # type: ignore[no-untyped-def]
    return await make_provider(
        "annuaire",
        kind="ldap",
        preset="ldap",
        config={**BASE, **(cfg or {})},
        secret=kw.pop("secret", SVC_PW),
        role_map=kw.pop("role_map", ROLES),
        **kw,
    )


async def ldap_login(client: httpx.AsyncClient, pid: str, user: str, password: str) -> httpx.Response:
    return await client.post(
        f"/api/v1/auth/ldap/{pid}/login", json={"username": user, "password": password}, headers={"Origin": ORIGIN}
    )


async def test_operator_and_viewer_login_with_mapped_roles(client: httpx.AsyncClient) -> None:
    pid = await ldap_provider()
    r = await ldap_login(client, pid, "alice", "Alice-Test-Password-1")
    assert r.status_code == 200 and r.json()["role"] == "operator", r.text
    me = (await client.get("/api/v1/auth/me")).json()
    assert me["auth_source"] == "ldap" and me["label"] == "alice@lab.local" and "realtime" in me["permissions"]
    assert (await client.get("/api/v1/settings")).status_code == 403  # jamais d'administration
    client.cookies.clear()
    r = await ldap_login(client, pid, "bob", "Bob-Test-Password-1")
    assert r.json()["role"] == "viewer"
    async for s in dbsession.get_session():
        n = (
            await s.execute(text("SELECT count(*) FROM users WHERE issuer LIKE 'ldap:%' AND role = 'admin'"))
        ).scalar_one()
        assert n == 0


async def test_unmapped_and_admin_group_members_never_become_admin(client: httpx.AsyncClient) -> None:
    pid = await ldap_provider()
    assert (await ldap_login(client, pid, "carol", "Carol-Test-Password-1")).status_code == 403  # aucun groupe mappé
    # dave est dans lasthop-admins (non mappé) ET lasthop-viewers : lecteur, pas super admin
    r = await ldap_login(client, pid, "dave", "Dave-Test-Password-1")
    assert r.status_code == 200 and r.json()["role"] == "viewer"
    assert "auth:manage" not in (await client.get("/api/v1/auth/me")).json()["permissions"]


async def test_wrong_password_unknown_user_and_filter_injection_are_refused(client: httpx.AsyncClient) -> None:
    pid = await ldap_provider()
    attempts = [
        ("alice", "mauvais-mot-de-passe"),
        ("inconnu", "Alice-Test-Password-1"),
        ("*", "x"),  # joker
        ("alice)(uid=*", "x"),  # injection de filtre
        ("*)(|(uid=*", "x"),
        ("alice\x00", "x"),
        ("a" * 200, "x"),
    ]
    codes = {(await ldap_login(client, pid, u, p)).status_code for u, p in attempts}
    assert codes <= {401, 422}
    assert "set-cookie" not in (await ldap_login(client, pid, "alice", "faux")).headers
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def test_empty_password_is_never_an_anonymous_bind() -> None:
    from app.security import ldap_auth
    from app.services.auth_providers import LdapConfig

    cfg = LdapConfig.model_validate(BASE)
    for pw in ("", None):
        with pytest.raises(ldap_auth.LdapError) as e:
            ldap_auth.authenticate(cfg, SVC_PW, "alice", pw)  # type: ignore[arg-type]
        assert e.value.code == "invalid_input"


async def test_failures_are_rate_limited_per_user(client: httpx.AsyncClient) -> None:
    pid = await ldap_provider()
    codes = [(await ldap_login(client, pid, "bob", f"faux-{i}")).status_code for i in range(12)]
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]
    # le même compte reste bloqué même avec le bon mot de passe pendant la fenêtre (protège l'annuaire du verrouillage)
    assert (await ldap_login(client, pid, "bob", "Bob-Test-Password-1")).status_code == 429


async def test_service_account_failure_is_audited_without_detail(client: httpx.AsyncClient) -> None:
    pid = await ldap_provider(secret="mauvais-mot-de-passe-service")
    r = await ldap_login(client, pid, "alice", "Alice-Test-Password-1")
    assert r.status_code == 401 and "service" not in r.text.lower()
    async for s in dbsession.get_session():
        reasons = (
            await s.execute(
                text("SELECT details->>'reason' FROM audit_log WHERE action='auth.login' ORDER BY id DESC LIMIT 1")
            )
        ).scalar_one()
        assert reasons == "ldap_service_bind"


async def test_unreachable_directory_is_refused_quickly_and_generically(client: httpx.AsyncClient) -> None:
    import time

    pid = await ldap_provider({"url": "ldap://ldap.lasthop.test:3999"})
    t0 = time.monotonic()
    r = await ldap_login(client, pid, "alice", "Alice-Test-Password-1")
    assert r.status_code == 401 and time.monotonic() - t0 < 12


async def test_ldaps_with_private_ca_works_and_server_name_is_verified(client: httpx.AsyncClient) -> None:
    tls = {"url": "ldaps://ldap.lasthop.test:3894", "insecure": False, "ca_pem": _ca()}
    pid = await ldap_provider(tls)
    assert (await ldap_login(client, pid, "alice", "Alice-Test-Password-1")).status_code == 200
    client.cookies.clear()
    # sans l'autorité de test, le certificat n'est pas approuvé : refus
    async for s in dbsession.get_session():
        await s.execute(text("DELETE FROM auth_providers"))
        await s.commit()
    pid2 = await ldap_provider({**tls, "ca_pem": None})
    assert (await ldap_login(client, pid2, "alice", "Alice-Test-Password-1")).status_code == 401
    # même autorité, mais l'hôte joint (« ldap ») ne figure pas dans le certificat : refus du nom
    async for s in dbsession.get_session():
        await s.execute(text("DELETE FROM auth_providers"))
        await s.commit()
    pid3 = await ldap_provider({**tls, "url": "ldaps://ldap:3894"})
    assert (await ldap_login(client, pid3, "alice", "Alice-Test-Password-1")).status_code == 401


async def test_plain_ldap_on_the_ldaps_port_and_starttls_failures_do_not_leak_passwords(
    client: httpx.AsyncClient,
) -> None:
    pid = await ldap_provider({"url": "ldap://ldap.lasthop.test:3894"})  # port TLS en clair : échec de protocole
    assert (await ldap_login(client, pid, "alice", "Alice-Test-Password-1")).status_code == 401


async def test_provider_test_endpoint_for_ldap(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    pid = await ldap_provider({"url": "ldaps://ldap.lasthop.test:3894", "insecure": False, "ca_pem": _ca()})
    r = (await c.post(f"/api/v1/auth-providers/{pid}/test")).json()
    assert r["ok"] is True and "ldaps" in r["message"] and SVC_PW not in str(r)
    await c.put(f"/api/v1/auth-providers/{pid}", json={"secret": "mauvais"})
    r = (await c.post(f"/api/v1/auth-providers/{pid}/test")).json()
    assert r["ok"] is False and "Compte de service refusé" in r["message"]


async def test_ldap_config_cannot_be_saved_in_cleartext_without_acknowledgement(
    client: httpx.AsyncClient, as_role
) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    body = {"kind": "ldap", "preset": "ldap", "name": "Annuaire", "secret": SVC_PW, "role_map": ROLES}
    cfg = {k: v for k, v in BASE.items() if k not in ("ca_pem", "bind_dn_template", "group_base")}
    assert (
        await c.post("/api/v1/auth-providers", json={**body, "config": {**cfg, "insecure": False}})
    ).status_code == 422
    ok = await c.post("/api/v1/auth-providers", json={**body, "config": {**cfg, "insecure": True}})
    assert ok.status_code == 201 and ok.json()["config"]["insecure"] is True
    async for s in dbsession.get_session():  # la connexion non chiffrée est tracée dans l'audit
        d = (
            await s.execute(
                text(
                    "SELECT details->>'insecure' FROM audit_log WHERE action='auth_provider.create' ORDER BY id DESC LIMIT 1"
                )
            )
        ).scalar_one()
        assert d == "true"
