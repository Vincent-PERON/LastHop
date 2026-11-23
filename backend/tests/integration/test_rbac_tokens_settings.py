import httpx
from sqlalchemy import text

from app.db import session as dbsession


async def test_rbac_matrix(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    assert (await client.get("/api/v1/audit")).status_code == 401  # non authentifié
    await as_role("lasthop-viewers")
    assert (await client.get("/api/v1/audit")).status_code == 403
    assert (await client.get("/api/v1/settings")).status_code == 403
    assert (await client.put("/api/v1/settings/retention_days", json={"value": 30})).status_code == 403
    async for s in dbsession.get_session():  # le refus est audité
        n = (
            await s.execute(text("SELECT count(*) FROM audit_log WHERE action='authz.denied' AND outcome='denied'"))
        ).scalar_one()
        assert n >= 3


async def test_admin_audit_and_verify(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    await as_role("lasthop-admins")
    r = await client.get("/api/v1/audit", params={"action": "auth.login", "limit": 5})
    assert r.status_code == 200 and r.json() and r.json()[0]["action"] == "auth.login"
    assert (await client.get("/api/v1/audit", params={"action": "x'; DROP TABLE users;--"})).status_code == 422
    v = (await client.get("/api/v1/audit/verify")).json()
    assert v == {"intact": True, "first_broken_id": None}


async def test_settings_validation_and_audit(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    await as_role("lasthop-admins")
    assert (await client.get("/api/v1/settings")).json()["snmp_v2c_enabled"] is False  # v2c off par défaut
    assert (await client.put("/api/v1/settings/snmp_v2c_enabled", json={"value": True})).status_code == 200
    assert (await client.get("/api/v1/settings")).json()["snmp_v2c_enabled"] is True
    for key, bad in (("retention_days", 0), ("retention_days", "90"), ("snmp_v2c_enabled", "yes"), ("unknown", 1)):
        assert (await client.put(f"/api/v1/settings/{key}", json={"value": bad})).status_code in (404, 422)


async def test_api_token_lifecycle_and_limits(client: httpx.AsyncClient, as_role, app) -> None:  # type: ignore[no-untyped-def]
    for group in ("lasthop-viewers", "lasthop-operators"):  # la gestion des tokens est réservée au super admin
        await as_role(group)
        assert (await client.post("/api/v1/tokens", json={"name": "t", "scopes": ["search"]})).status_code == 403
        assert (await client.get("/api/v1/tokens")).status_code == 403
    await as_role("lasthop-admins")
    assert (await client.post("/api/v1/tokens", json={"name": "t", "scopes": ["admin"]})).status_code == 422
    assert (
        await client.post("/api/v1/tokens", json={"name": "t", "scopes": ["read"], "expires_in_days": 9999})
    ).status_code == 422
    assert (await client.post("/api/v1/tokens", json={"name": "t", "scopes": ["read"], "extra": 1})).status_code == 422
    r = await client.post("/api/v1/tokens", json={"name": "ci", "scopes": ["read", "search"]})
    assert r.status_code == 201
    body = r.json()
    plain = body["token"]
    assert plain.startswith("lasthop_")
    assert "token" not in (await client.get("/api/v1/tokens")).json()[0]  # jamais re-affiché

    async for s in dbsession.get_session():  # le secret n'est stocké qu'en hash
        h = (await s.execute(text("SELECT token_hash FROM api_tokens WHERE id=:i"), {"i": body["id"]})).scalar_one()
        assert plain.split(".")[1].encode() not in bytes(h)

    transport = httpx.ASGITransport(app=app, client=("10.250.250.7", 1))
    async with httpx.AsyncClient(transport=transport, base_url="https://lasthop.test") as bearer:
        auth = {"Authorization": f"Bearer {plain}"}
        me = await bearer.get("/api/v1/auth/me", headers=auth)
        assert (
            me.status_code == 200
            and me.json()["permissions"] == ["inventory:read", "search"]
            and me.json()["csrf_token"] is None
        )
        assert (await bearer.get("/api/v1/audit", headers=auth)).status_code == 403
        assert (
            await bearer.post("/api/v1/tokens", headers=auth, json={"name": "x", "scopes": ["read"]})
        ).status_code == 403
        assert (await bearer.get("/api/v1/auth/me", headers={"Authorization": plain[:-1] + "A"})).status_code == 401

        assert (await client.delete(f"/api/v1/tokens/{body['id']}")).status_code == 204  # révocation
        assert (await bearer.get("/api/v1/auth/me", headers=auth)).status_code == 401


async def test_token_cannot_exceed_owner_after_demotion_and_other_users_cannot_revoke(
    client, idp, as_role, app
) -> None:  # type: ignore[no-untyped-def]
    from tests.conftest import login

    await as_role("lasthop-admins")
    tok = (await client.post("/api/v1/tokens", json={"name": "rt", "scopes": ["read", "realtime"]})).json()
    # rétrogradation de l'utilisateur côté IdP : le rôle est recalculé au prochain login
    client.cookies.clear()
    r = await login(client, idp, ["lasthop-viewers"], sub=(await _only_sub()))
    assert r.status_code == 302
    transport = httpx.ASGITransport(app=app, client=("10.250.250.8", 1))
    async with httpx.AsyncClient(transport=transport, base_url="https://lasthop.test") as b:
        me = await b.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok['token']}"})
        assert me.json()["permissions"] == []  # les portées read/realtime n'existent plus pour un viewer
    # un autre utilisateur non super admin n'a aucun accès à la gestion des tokens
    client.cookies.clear()
    await login(client, idp, ["lasthop-viewers"])
    me2 = (await client.get("/api/v1/auth/me")).json()
    client.headers.update({"Origin": "https://lasthop.test", "X-CSRF-Token": me2["csrf_token"]})
    assert (await client.delete(f"/api/v1/tokens/{tok['id']}")).status_code == 403
    assert (await client.get("/api/v1/tokens")).status_code == 403


async def _only_sub() -> str:
    async for s in dbsession.get_session():
        return str((await s.execute(text("SELECT sub FROM users ORDER BY created_at LIMIT 1"))).scalar_one())
    raise AssertionError


async def test_viewer_and_operator_limited_to_search_and_topology(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    """Hors super admin : recherche IP/MAC et topologie uniquement (le temps réel et l'export restent à l'opérateur)."""
    forbidden = [
        ("get", "/api/v1/devices"),
        ("get", "/api/v1/credentials"),
        ("get", "/api/v1/ssh-credentials"),
        ("get", "/api/v1/backups/runs"),
        ("get", "/api/v1/settings"),
        ("get", "/api/v1/audit"),
        ("get", "/api/v1/tokens"),
        ("post", "/api/v1/discovery"),
    ]
    for group in ("lasthop-viewers", "lasthop-operators"):
        await as_role(group)
        for method, url in forbidden:
            r = await (client.get(url) if method == "get" else client.post(url, json={}))
            assert r.status_code == 403, (group, url, r.status_code)
        assert (await client.get("/api/v1/endpoints")).status_code == 200
        assert (await client.get("/api/v1/topology/graph")).status_code == 200
        assert (await client.get("/api/v1/sites")).status_code == 200
    await as_role("lasthop-viewers")
    assert (await client.get("/api/v1/endpoints/export.csv")).status_code == 403
    assert (await client.post("/api/v1/realtime", json={"query": "10.0.0.1"})).status_code == 403
