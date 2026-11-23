"""Gestion des fournisseurs d'identité (super admin) et connexions Keycloak / Entra ID / Google Workspace."""

import uuid

import httpx
import pytest
from sqlalchemy import text

from app.db import session as dbsession
from app.security.crypto import CryptoError
from tests.conftest import CLIENT_ID, ISSUER, FakeIdP, _keyring, login, make_provider

SECRET = "super-client-secret-à-ne-jamais-voir"
KC = {"issuer": ISSUER, "client_id": CLIENT_ID, "groups_claim": "groups"}
BODY = {
    "kind": "oidc",
    "preset": "keycloak",
    "name": "Keycloak labo",
    "config": KC,
    "secret": "test-client-secret",
    "role_map": {"lasthop-operators": "operator", "lasthop-viewers": "viewer"},
}


async def test_only_super_admin_can_manage_providers(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    assert (await client.get("/api/v1/auth-providers")).status_code == 401
    pid = await make_provider("existant")
    for group in ("lasthop-viewers", "lasthop-operators"):
        c = await as_role(group)
        assert (await c.get("/api/v1/auth-providers")).status_code == 403
        assert (await c.post("/api/v1/auth-providers", json=BODY)).status_code == 403
        assert (await c.put(f"/api/v1/auth-providers/{pid}", json={"enabled": False})).status_code == 403
        assert (await c.delete(f"/api/v1/auth-providers/{pid}")).status_code == 403
        assert (await c.post(f"/api/v1/auth-providers/{pid}/test")).status_code == 403


async def test_secret_is_encrypted_bound_to_row_and_never_returned(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    r = await c.post("/api/v1/auth-providers", json={**BODY, "secret": SECRET, "enabled": True})
    assert r.status_code == 201, r.text
    view = r.json()
    assert (
        view["has_secret"] is True and SECRET not in r.text and "secret" not in {k for k in view if k != "has_secret"}
    )
    assert view["redirect_uri"] == "https://lasthop.test/api/v1/auth/oidc/callback"
    assert SECRET not in (await c.get("/api/v1/auth-providers")).text
    async for s in dbsession.get_session():
        row = (await s.execute(text("SELECT id, secret_blob FROM auth_providers"))).one()
        blob = bytes(row[1])
        assert SECRET.encode() not in blob  # chiffré
        ring = _keyring()
        assert ring.decrypt(blob, f"auth_providers:{row[0]}").decode() == SECRET
        with pytest.raises(CryptoError):  # un blob copié vers une autre ligne ne se déchiffre pas
            ring.decrypt(blob, f"auth_providers:{uuid.uuid4()}")
        audit = (
            (await s.execute(text("SELECT details::text FROM audit_log WHERE action LIKE 'auth_provider.%'")))
            .scalars()
            .all()
        )
        assert audit and all(SECRET not in a for a in audit)


async def test_validation_and_activation_rules(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    url = "/api/v1/auth-providers"
    bad_bodies = [
        {**BODY, "role_map": {"lasthop-admins": "admin"}},  # un groupe externe ne donne jamais admin
        {**BODY, "config": {**KC, "issuer": "https://169.254.169.254/x"}},
        {**BODY, "config": {**KC, "unknown": 1}},
        {**BODY, "kind": "saml"},
        {**BODY, "enabled": True, "secret": None},  # activer sans client_secret
        {**BODY, "enabled": True, "role_map": {}},  # activer sans correspondance : personne ne pourrait se connecter
        {
            **BODY,
            "preset": "google",
            "config": {"issuer": "https://accounts.google.com", "client_id": "x"},
        },  # sans domaine
        {**BODY, "name": "<script>"},
    ]
    for b in bad_bodies:
        assert (await c.post(url, json=b)).status_code == 422, b
    assert (await c.post(url, json=BODY)).status_code == 201
    assert (await c.post(url, json=BODY)).status_code == 409  # nom unique


async def test_update_keeps_secret_when_omitted_and_delete(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    pid = (await c.post("/api/v1/auth-providers", json=BODY)).json()["id"]
    r = await c.put(f"/api/v1/auth-providers/{pid}", json={"enabled": True, "name": "Renommé"})
    assert r.status_code == 200 and r.json()["has_secret"] is True and r.json()["enabled"] is True
    r = await c.put(f"/api/v1/auth-providers/{pid}", json={"clear_secret": True})
    assert r.status_code == 422  # un fournisseur actif ne peut pas perdre son secret
    assert (await c.put(f"/api/v1/auth-providers/{pid}", json={"enabled": False, "clear_secret": True})).json()[
        "has_secret"
    ] is False
    assert (await c.put(f"/api/v1/auth-providers/{pid}", json={"role_map": {"g": "admin"}})).status_code == 422
    assert (await c.delete(f"/api/v1/auth-providers/{pid}")).status_code == 204
    assert (await c.delete(f"/api/v1/auth-providers/{pid}")).status_code == 404
    assert (await c.get("/api/v1/auth-providers")).json() == []


async def test_provider_test_endpoint_and_end_to_end_login(client: httpx.AsyncClient, idp: FakeIdP, as_role) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    pid = (await c.post("/api/v1/auth-providers", json={**BODY, "enabled": True})).json()["id"]
    t = (await c.post(f"/api/v1/auth-providers/{pid}/test")).json()
    assert t["ok"] is True and "Découverte OIDC réussie" in t["message"]
    # configuration pointant vers un IdP qui ne répond pas : message générique, pas de détail technique
    bad = (
        await c.put(f"/api/v1/auth-providers/{pid}", json={"config": {**KC, "issuer": "https://absent.test/realms/x"}})
    ).json()
    assert bad["config"]["issuer"].endswith("/realms/x")
    t2 = (await c.post(f"/api/v1/auth-providers/{pid}/test")).json()
    assert t2["ok"] is False and "Traceback" not in t2["message"] and "absent.test" not in t2["message"]
    await c.put(f"/api/v1/auth-providers/{pid}", json={"config": KC})
    # visible sur la page de connexion, puis connexion réelle avec ce fournisseur
    c.cookies.clear()
    public = (await client.get("/api/v1/auth/providers")).json()
    assert public["providers"] == [{"id": pid, "name": "Keycloak labo", "kind": "oidc", "preset": "keycloak"}]
    r = await login(client, idp, ["lasthop-operators"], provider=pid)
    assert r.status_code == 302 and (await client.get("/api/v1/auth/me")).json()["role"] == "operator"


async def test_provider_change_takes_effect_immediately(client: httpx.AsyncClient, idp: FakeIdP, as_role) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    pid = (await c.post("/api/v1/auth-providers", json={**BODY, "enabled": True})).json()["id"]
    await c.put(f"/api/v1/auth-providers/{pid}", json={"role_map": {"lasthop-viewers": "viewer"}})  # opérateurs retirés
    c.cookies.clear()
    assert (await login(client, idp, ["lasthop-operators"], provider=pid)).status_code == 403
    assert (await login(client, idp, ["lasthop-viewers"], provider=pid)).status_code == 302
    c2 = await as_role("lasthop-admins")
    await c2.put(f"/api/v1/auth-providers/{pid}", json={"enabled": False})
    c2.cookies.clear()
    assert (await client.get(f"/api/v1/auth/oidc/{pid}/login")).status_code == 404


async def test_entra_without_groups_uses_default_role_and_role_is_recomputed(
    client: httpx.AsyncClient, idp: FakeIdP
) -> None:
    pid = await make_provider(
        "Entra",
        preset="entra",
        config={**KC, "allowed_domains": [], "require_email_verified": False, "scopes": "openid profile email"},
        role_map={"guid-operateurs": "operator"},
        default_role="viewer",
    )
    assert (await login(client, idp, ["guid-operateurs"], provider=pid, sub="u-1")).status_code == 302
    assert (await client.get("/api/v1/auth/me")).json()["role"] == "operator"
    client.cookies.clear()
    # dépassement de groupes Entra (claim groups absent) : rôle par défaut, et le rôle est recalculé à chaque connexion
    assert (await login(client, idp, None, provider=pid, sub="u-1")).status_code == 302
    assert (await client.get("/api/v1/auth/me")).json()["role"] == "viewer"


GOOGLE = {
    "issuer": ISSUER,
    "client_id": CLIENT_ID,
    "allowed_domains": ["corp.example"],
    "require_email_verified": True,
    "scopes": "openid profile email",
    "groups_claim": "groups",
}


async def test_google_workspace_is_restricted_to_the_workspace_domain(client: httpx.AsyncClient, idp: FakeIdP) -> None:
    pid = await make_provider("Google", preset="google", config=GOOGLE, role_map={}, default_role="viewer")
    ok = {"hd": "corp.example", "email": "x@corp.example", "email_verified": True}
    assert (await login(client, idp, None, provider=pid, **ok)).status_code == 302
    client.cookies.clear()
    for over in (
        {**ok, "hd": "other.example"},  # autre domaine Workspace
        {**ok, "hd": None},  # compte Google personnel (pas de hd) avec une adresse @corp.example usurpée
        {**ok, "email_verified": False},
        {**ok, "email_verified": "true"},  # chaîne et non booléen
    ):
        r = await login(client, idp, None, provider=pid, **over)
        assert r.status_code == 401 and "set-cookie" not in r.headers, over
