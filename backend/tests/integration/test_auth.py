"""Connexion OIDC (code + PKCE) : sécurité du flux, sessions, CSRF. Les comptes fédérés ne sont jamais super admin."""

from urllib.parse import parse_qs, urlparse

import httpx
from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import ORIGIN, FakeIdP, login, oidc_provider_id


async def _audit_count(action: str, outcome: str | None = None) -> int:
    async for s in dbsession.get_session():
        q = "SELECT count(*) FROM audit_log WHERE action=:a AND (CAST(:o AS text) IS NULL OR outcome=:o)"
        return int((await s.execute(text(q), {"a": action, "o": outcome})).scalar_one())
    raise AssertionError


async def test_login_redirect_uses_pkce_state_nonce_and_binds_cookie(client: httpx.AsyncClient) -> None:
    pid = await oidc_provider_id()
    r = await client.get(f"/api/v1/auth/oidc/{pid}/login", params={"next": "//evil.example"})
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"] and q["state"] and q["nonce"] and q["code_challenge"]
    assert q["redirect_uri"] == [ORIGIN + "/api/v1/auth/oidc/callback"]
    sc = r.headers["set-cookie"].lower()
    assert "__host-lasthop_login" in sc and "secure" in sc and "httponly" in sc and "samesite=lax" in sc


async def test_full_login_flow_session_cookie_flags_and_open_redirect_blocked(
    client: httpx.AsyncClient, idp: FakeIdP
) -> None:
    before = await _audit_count("auth.login", "success")
    r = await login(client, idp, ["lasthop-viewers"])
    assert r.status_code == 302 and r.headers["location"] == ORIGIN + "/devices"
    sc = ";".join(r.headers.get_list("set-cookie")).lower()
    assert (
        "__host-lasthop_session=" in sc
        and "httponly" in sc
        and "secure" in sc
        and "path=/" in sc
        and "domain" not in sc
    )
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["role"] == "viewer" and me.json()["csrf_token"]
    assert me.json()["auth_source"] == "oidc" and me.json()["must_change_password"] is False
    assert await _audit_count("auth.login", "success") == before + 1

    pid = await oidc_provider_id()
    r2 = await client.get(f"/api/v1/auth/oidc/{pid}/login", params={"next": "//evil.example/x"})
    q = parse_qs(urlparse(r2.headers["location"]).query)
    idp.next_claims = idp.claims(q["nonce"][0], groups=["lasthop-viewers"])
    cb = await client.get("/api/v1/auth/oidc/callback", params={"code": "abc", "state": q["state"][0]})
    assert cb.headers["location"] == ORIGIN + "/"  # next malveillant ignoré


async def test_no_mapped_group_is_denied_and_audited(client: httpx.AsyncClient, idp: FakeIdP) -> None:
    before = await _audit_count("auth.login", "failure")
    for groups in (["random-group"], [], None):
        r = await login(client, idp, groups)
        assert r.status_code == 403 and "set-cookie" not in r.headers
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    assert await _audit_count("auth.login", "failure") == before + 3


async def test_federated_account_can_never_be_super_admin(client: httpx.AsyncClient, idp: FakeIdP) -> None:
    """Même un groupe « admin » de l'IdP n'ouvre que ce que le fournisseur mappe (operator/viewer) ; la base refuse aussi."""
    r = await login(client, idp, ["lasthop-admins"])
    assert r.status_code == 403  # aucun mappage vers admin : refus par défaut
    async for s in dbsession.get_session():
        from sqlalchemy.exc import IntegrityError

        try:
            await s.execute(
                text(
                    "INSERT INTO users(id, issuer, sub, role) VALUES (gen_random_uuid(), 'https://idp.test/realms/lasthop',"
                    " 'x', 'admin')"
                )
            )
            await s.commit()
            raise AssertionError("la contrainte devait refuser un admin fédéré")
        except IntegrityError:
            await s.rollback()


async def test_invalid_idp_tokens_rejected(client: httpx.AsyncClient, idp: FakeIdP) -> None:
    pid = await oidc_provider_id()

    async def attempt(**over: object) -> int:
        r = await client.get(f"/api/v1/auth/oidc/{pid}/login")
        q = parse_qs(urlparse(r.headers["location"]).query)
        claims = idp.claims(over.pop("nonce", q["nonce"][0]), groups=["lasthop-viewers"], **over)  # type: ignore[arg-type]
        idp.next_claims = claims
        r2 = await client.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": q["state"][0]})
        return r2.status_code

    assert await attempt(nonce="wrong") == 401
    assert await attempt(exp=1) == 401
    assert await attempt(aud="other-client") == 401
    assert await attempt(iss="https://evil.example/realms/x") == 401
    idp.sign_with = idp.other_key  # signature par une autre clé (même kid)
    try:
        assert await attempt() == 401
    finally:
        idp.sign_with = idp.key
    assert await attempt() == 302  # contrôle positif


async def test_state_is_single_use_and_cookie_bound(client: httpx.AsyncClient, idp: FakeIdP) -> None:
    pid = await oidc_provider_id()
    r = await client.get(f"/api/v1/auth/oidc/{pid}/login")
    q = parse_qs(urlparse(r.headers["location"]).query)
    idp.next_claims = idp.claims(q["nonce"][0], groups=["lasthop-viewers"])
    ok = await client.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": q["state"][0]})
    assert ok.status_code == 302
    client.cookies.set("__Host-lasthop_login", q["state"][0], domain="lasthop.test", path="/")
    replay = await client.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": q["state"][0]})
    assert replay.status_code == 401  # état déjà consommé
    # login-CSRF : état valide mais cookie d'un autre navigateur
    client.cookies.clear()
    r = await client.get(f"/api/v1/auth/oidc/{pid}/login")
    q = parse_qs(urlparse(r.headers["location"]).query)
    client.cookies.clear()
    assert (
        await client.get("/api/v1/auth/oidc/callback", params={"code": "c", "state": q["state"][0]})
    ).status_code == 401


async def test_disabled_or_unknown_provider_is_not_found(client: httpx.AsyncClient) -> None:
    import uuid

    assert (await client.get(f"/api/v1/auth/oidc/{uuid.uuid4()}/login")).status_code == 404
    assert (await client.get("/api/v1/auth/oidc/not-a-uuid/login")).status_code == 404
    async for s in dbsession.get_session():
        pid = await oidc_provider_id()
        await s.execute(text("UPDATE auth_providers SET enabled = false"))
        await s.commit()
    assert (await client.get(f"/api/v1/auth/oidc/{pid}/login")).status_code == 404
    public = (await client.get("/api/v1/auth/providers")).json()
    assert public["local"] is True and public["providers"] == []


async def test_csrf_and_origin_enforced_on_cookie_auth(client: httpx.AsyncClient, idp: FakeIdP, as_role) -> None:  # type: ignore[no-untyped-def]
    await as_role("lasthop-admins")
    good = dict(client.headers)
    for hdrs in ({"x-csrf-token": "bad"}, {"origin": "https://evil.example"}):
        r = await client.put("/api/v1/settings/snmp_v2c_enabled", json={"value": True}, headers={**good, **hdrs})
        assert r.status_code == 403
    del client.headers["origin"]
    assert (await client.put("/api/v1/settings/snmp_v2c_enabled", json={"value": True})).status_code == 403


async def test_logout_invalidates_session(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    await as_role("lasthop-viewers")
    assert (await client.post("/api/v1/auth/logout")).status_code == 200
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def test_login_rate_limited(client: httpx.AsyncClient) -> None:
    pid = await oidc_provider_id()
    codes = [(await client.get(f"/api/v1/auth/oidc/{pid}/login")).status_code for _ in range(22)]
    assert codes[:20] == [302] * 20 and codes[-1] == 429
