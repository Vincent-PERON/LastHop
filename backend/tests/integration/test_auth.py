from urllib.parse import parse_qs, urlparse

import httpx
from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import ISSUER, ORIGIN, FakeIdP, login


async def _audit_count(action: str, outcome: str | None = None) -> int:
    async for s in dbsession.get_session():
        q = "SELECT count(*) FROM audit_log WHERE action=:a AND (CAST(:o AS text) IS NULL OR outcome=:o)"
        return int((await s.execute(text(q), {"a": action, "o": outcome})).scalar_one())
    raise AssertionError


async def test_login_redirect_uses_pkce_state_nonce_and_binds_cookie(client: httpx.AsyncClient) -> None:
    r = await client.get("/api/v1/auth/login", params={"next": "//evil.example"})
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"] and q["state"] and q["nonce"] and q["code_challenge"]
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
    assert await _audit_count("auth.login", "success") == before + 1

    r2 = await client.get("/api/v1/auth/login", params={"next": "//evil.example/x"})
    q = parse_qs(urlparse(r2.headers["location"]).query)
    idp.next_claims = idp.claims(q["nonce"][0], groups=["lasthop-viewers"])
    cb = await client.get("/api/v1/auth/callback", params={"code": "abc", "state": q["state"][0]})
    assert cb.headers["location"] == ORIGIN + "/"  # next malveillant ignoré


async def test_no_mapped_group_is_denied_and_audited(client: httpx.AsyncClient, idp: FakeIdP) -> None:
    before = await _audit_count("auth.login", "failure")
    for groups in (["random-group"], [], None):
        r = await login(client, idp, groups)
        assert r.status_code == 403 and "set-cookie" not in r.headers
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    assert await _audit_count("auth.login", "failure") == before + 3


async def test_invalid_idp_tokens_rejected(client: httpx.AsyncClient, idp: FakeIdP) -> None:
    async def attempt(**over: object) -> int:
        r = await client.get("/api/v1/auth/login")
        q = parse_qs(urlparse(r.headers["location"]).query)
        claims = idp.claims(over.pop("nonce", q["nonce"][0]), groups=["lasthop-admins"], **over)  # type: ignore[arg-type]
        idp.next_claims = claims
        return (await client.get("/api/v1/auth/callback", params={"code": "c", "state": q["state"][0]})).status_code

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
    r = await client.get("/api/v1/auth/login")
    q = parse_qs(urlparse(r.headers["location"]).query)
    idp.next_claims = idp.claims(q["nonce"][0], groups=["lasthop-admins"])
    ok = await client.get("/api/v1/auth/callback", params={"code": "c", "state": q["state"][0]})
    assert ok.status_code == 302
    client.cookies.set("__Host-lasthop_login", q["state"][0], domain="lasthop.test", path="/")
    replay = await client.get("/api/v1/auth/callback", params={"code": "c", "state": q["state"][0]})
    assert replay.status_code == 401  # état déjà consommé
    # login-CSRF : état valide mais cookie d'un autre navigateur
    client.cookies.clear()
    r = await client.get("/api/v1/auth/login")
    q = parse_qs(urlparse(r.headers["location"]).query)
    client.cookies.clear()
    assert (await client.get("/api/v1/auth/callback", params={"code": "c", "state": q["state"][0]})).status_code == 401


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
    codes = [(await client.get("/api/v1/auth/login")).status_code for _ in range(22)]
    assert codes[:20] == [302] * 20 and codes[-1] == 429


_ = ISSUER
