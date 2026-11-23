"""Compte super admin local : connexion, verrouillage progressif, changement de mot de passe imposé, secours CLI."""

import httpx
import pytest
from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, ORIGIN, local_login, make_local_user

NEW_PW = "Nouveau-Secret-Fort-2026"


async def _audit(action: str, outcome: str) -> int:
    async for s in dbsession.get_session():
        q = "SELECT count(*) FROM audit_log WHERE action=:a AND outcome=:o"
        return int((await s.execute(text(q), {"a": action, "o": outcome})).scalar_one())
    raise AssertionError


async def test_local_admin_login_gives_super_admin_session(client: httpx.AsyncClient) -> None:
    ok_before = await _audit("auth.login", "success")
    r = await local_login(client)
    assert r.status_code == 200 and r.json() == {"status": "ok", "must_change_password": False}
    sc = r.headers["set-cookie"].lower()
    assert "__host-lasthop_session=" in sc and "httponly" in sc and "secure" in sc and "domain" not in sc
    me = (await client.get("/api/v1/auth/me")).json()
    assert me["role"] == "admin" and me["auth_source"] == "local" and "auth:manage" in me["permissions"]
    assert await _audit("auth.login", "success") == ok_before + 1


async def test_bad_credentials_are_generic_and_audited(client: httpx.AsyncClient) -> None:
    before = await _audit("auth.login", "failure")
    r1 = await local_login(client, ADMIN_USER, "mauvais-mot-de-passe")
    r2 = await local_login(client, "inconnu", "mauvais-mot-de-passe")
    assert r1.status_code == r2.status_code == 401 and r1.json() == r2.json()  # pas d'énumération de comptes
    assert "set-cookie" not in r1.headers
    assert await _audit("auth.login", "failure") == before + 2


async def test_hostile_usernames_are_rejected_before_reaching_database_or_audit(client: httpx.AsyncClient) -> None:
    for name in ("adm\x00in", "a\nb\r\nfake-entry", "é" * 50, "x" * 65, "a b", "a'; DROP TABLE users;--"):
        r = await local_login(client, name, "x" * 12)
        assert r.status_code == 422, name  # jamais 500 ; refusé dès la validation
    # même une saisie de caractères de contrôle qui atteindrait l'audit est neutralisée
    from app.security.audit import clean_label

    assert (
        clean_label("a\x00b\nc") == "a?b?c" and clean_label(None) is None and len(clean_label("é" * 999) or "") == 320
    )


async def test_login_post_requires_app_origin(client: httpx.AsyncClient) -> None:
    body = {"username": ADMIN_USER, "password": ADMIN_PASSWORD}
    assert (await client.post("/api/v1/auth/local/login", json=body)).status_code == 403  # sans Origin
    r = await client.post("/api/v1/auth/local/login", json=body, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert (
        await client.post("/api/v1/auth/local/login", json={**body, "x": 1}, headers={"Origin": ORIGIN})
    ).status_code == 422


async def test_progressive_lockout_then_correct_password_still_refused(client: httpx.AsyncClient) -> None:
    await make_local_user("lockme", "Passphrase-Correcte-123")
    for _ in range(5):
        assert (await local_login(client, "lockme", "faux-faux-faux")).status_code == 401
    # verrouillé : même le bon mot de passe est refusé, avec la même réponse générique
    r = await local_login(client, "lockme", "Passphrase-Correcte-123")
    assert r.status_code == 401 and "set-cookie" not in r.headers
    async for s in dbsession.get_session():
        row = (
            await s.execute(text("SELECT failed_login_count, locked_until > now() FROM users WHERE sub='lockme'"))
        ).one()
        assert row[0] == 5 and row[1] is True
        await s.execute(text("UPDATE users SET locked_until = now() - interval '1 minute' WHERE sub='lockme'"))
        await s.commit()
    assert (await local_login(client, "lockme", "Passphrase-Correcte-123")).status_code == 200  # verrou expiré
    async for s in dbsession.get_session():
        assert (await s.execute(text("SELECT failed_login_count FROM users WHERE sub='lockme'"))).scalar_one() == 0


async def test_ip_rate_limit_on_local_login(client: httpx.AsyncClient) -> None:
    codes = [(await local_login(client, "inconnu", "x" * 12)).status_code for _ in range(22)]
    assert codes[:20] == [401] * 20 and codes[-1] == 429


async def test_forced_password_change_blocks_everything_else(client: httpx.AsyncClient) -> None:
    await make_local_user("fresh", "Initial-Passphrase-77", must_change=True)
    r = await local_login(client, "fresh", "Initial-Passphrase-77")
    assert r.json()["must_change_password"] is True
    me = (await client.get("/api/v1/auth/me")).json()
    assert me["must_change_password"] is True
    h = {"Origin": ORIGIN, "X-CSRF-Token": me["csrf_token"]}
    blocked = await client.get("/api/v1/settings")
    assert blocked.status_code == 403 and blocked.headers.get("x-error-code") == "PASSWORD_CHANGE_REQUIRED"
    ch = await client.post(
        "/api/v1/auth/password", json={"current_password": "Initial-Passphrase-77", "new_password": NEW_PW}, headers=h
    )
    assert ch.status_code == 200
    me2 = (await client.get("/api/v1/auth/me")).json()
    assert me2["must_change_password"] is False and me2["csrf_token"] != me["csrf_token"]  # nouvelle session
    assert (await client.get("/api/v1/settings")).status_code == 200


async def test_password_change_validates_policy_and_invalidates_other_sessions(client: httpx.AsyncClient, app) -> None:  # type: ignore[no-untyped-def]
    await make_local_user("rotator", "Initial-Passphrase-77")
    await local_login(client, "rotator", "Initial-Passphrase-77")
    me = (await client.get("/api/v1/auth/me")).json()
    h = {"Origin": ORIGIN, "X-CSRF-Token": me["csrf_token"]}
    old_cookies = dict(client.cookies)

    async def change(cur: str, new: str) -> httpx.Response:
        return await client.post(
            "/api/v1/auth/password", json={"current_password": cur, "new_password": new}, headers=h
        )

    assert (await change("faux", NEW_PW)).status_code == 403  # mot de passe actuel incorrect
    for weak in ("court", "rotator-rotator-1", "a" * 20, " " + NEW_PW, "Initial-Passphrase-77"):
        assert (await change("Initial-Passphrase-77", weak)).status_code == 422, weak
    assert (await change("Initial-Passphrase-77", NEW_PW)).status_code == 200

    # une session ouverte avant le changement (autre navigateur) n'est plus valide
    transport = httpx.ASGITransport(app=app, client=("10.9.9.9", 1))
    async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as other:
        for k, v in old_cookies.items():
            other.cookies.set(k, v, domain="lasthop.test", path="/")
        assert (await other.get("/api/v1/auth/me")).status_code == 401
    assert (await local_login(client, "rotator", "Initial-Passphrase-77")).status_code == 401
    assert (await local_login(client, "rotator", NEW_PW)).status_code == 200


async def test_federated_user_cannot_change_password_here(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    await as_role("lasthop-viewers")
    r = await client.post("/api/v1/auth/password", json={"current_password": "x" * 12, "new_password": NEW_PW})
    assert r.status_code == 400


async def test_bootstrap_creates_account_once_and_refuses_weak_password(app) -> None:  # type: ignore[no-untyped-def]
    from app.config import Settings
    from app.services.local_admin import ensure_local_admin

    base = {"env": "dev", "frontend_origin": ORIGIN}
    async for s in dbsession.get_session():
        await s.execute(text("UPDATE users SET sub = 'moved' WHERE issuer='local' AND sub='admin'"))
        await s.commit()
    try:
        async for s in dbsession.get_session():  # d'autres comptes locaux existent : rien n'est créé
            assert await ensure_local_admin(Settings(**base, local_admin_password="Bootstrap-Passphrase-1")) is False
            await s.execute(text("DELETE FROM users WHERE issuer='local' AND sub='moved'"))
            await s.commit()
        assert await ensure_local_admin(Settings(**base, local_admin_password="faible")) is False  # politique
        assert await ensure_local_admin(Settings(**base)) is False  # pas de mot de passe fourni
        assert await ensure_local_admin(
            Settings(**base, local_admin_password="Bootstrap-Passphrase-1", local_admin_must_change=True)
        )
        async for s in dbsession.get_session():
            row = (
                await s.execute(
                    text(
                        "SELECT must_change_password, password_hash LIKE '$argon2id$%' FROM users WHERE issuer='local'"
                    )
                )
            ).one()
            assert row[0] is True and row[1] is True  # argon2id, jamais en clair
    finally:
        async for s in dbsession.get_session():  # restaure le compte de référence des autres tests
            from app.security.passwords import hash_password

            await s.execute(text("DELETE FROM users WHERE issuer='local' AND sub='admin'"))
            await s.execute(
                text(
                    "INSERT INTO users(id, issuer, sub, role, display_name, password_hash) VALUES"
                    " (gen_random_uuid(), 'local', 'admin', 'admin', 'Super admin local', :h)"
                ),
                {"h": await hash_password(ADMIN_PASSWORD)},
            )
            await s.commit()


async def test_cli_reset_unlocks_forces_change_and_kills_sessions(client: httpx.AsyncClient) -> None:
    from app.services.local_admin import reset_local_password

    await make_local_user("rescue", "Initial-Passphrase-77")
    await local_login(client, "rescue", "Initial-Passphrase-77")
    assert (await client.get("/api/v1/auth/me")).status_code == 200
    assert await reset_local_password("rescue", "Secours-Passphrase-88") is True
    assert (await client.get("/api/v1/auth/me")).status_code == 401  # sessions invalidées
    r = await local_login(client, "rescue", "Secours-Passphrase-88")
    assert r.json()["must_change_password"] is True
    assert await reset_local_password("nobody", "Secours-Passphrase-88") is False
    with pytest.raises(ValueError):
        await reset_local_password("rescue", "court")


async def test_password_hash_is_argon2id_and_never_exposed(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    await as_role("lasthop-admins")
    async for s in dbsession.get_session():
        h = (await s.execute(text("SELECT password_hash FROM users WHERE sub = 'admin'"))).scalar_one()
        assert h.startswith("$argon2id$") and ADMIN_PASSWORD not in h
    for url in ("/api/v1/auth/me", "/api/v1/audit", "/api/v1/auth-providers"):
        assert "argon2" not in (await client.get(url)).text and ADMIN_PASSWORD not in (await client.get(url)).text
