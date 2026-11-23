"""TOTP optionnel du compte local : activation, connexion en 2 étapes, anti-rejeu, verrouillage, codes de secours."""

import asyncio

import httpx
from sqlalchemy import text

from app.db import session as dbsession
from app.security import totp
from tests.conftest import ORIGIN, _keyring, local_login, make_local_user

PW = "Totp-User-Passphrase-1"
HEADERS = {"Origin": ORIGIN}


async def _session_for(client: httpx.AsyncClient, user: str = "totpuser") -> dict[str, str]:
    await make_local_user(user, PW)
    assert (await local_login(client, user, PW)).status_code == 200
    me = (await client.get("/api/v1/auth/me")).json()
    return {"Origin": ORIGIN, "X-CSRF-Token": me["csrf_token"]}


async def _enroll(client: httpx.AsyncClient, h: dict[str, str]) -> tuple[str, list[str]]:
    r = await client.post("/api/v1/auth/totp/setup", json={"password": PW}, headers=h)
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    e = await client.post(
        "/api/v1/auth/totp/enable", json={"code": totp.code_at(secret, totp.current_step())}, headers=h
    )
    assert e.status_code == 200, e.text
    return secret, e.json()["recovery_codes"]


async def _password_step(client: httpx.AsyncClient, user: str = "totpuser") -> httpx.Response:
    client.cookies.clear()
    return await client.post("/api/v1/auth/local/login", json={"username": user, "password": PW}, headers=HEADERS)


async def _second_step(client: httpx.AsyncClient, challenge: str, code: str) -> httpx.Response:
    return await client.post("/api/v1/auth/local/totp", json={"challenge": challenge, "code": code}, headers=HEADERS)


async def _audit(action: str, outcome: str = "success") -> int:
    async for s in dbsession.get_session():
        q = "SELECT count(*) FROM audit_log WHERE action=:a AND outcome=:o"
        return int((await s.execute(text(q), {"a": action, "o": outcome})).scalar_one())
    raise AssertionError


async def test_setup_requires_password_returns_qr_and_stores_secret_encrypted(client: httpx.AsyncClient) -> None:
    h = await _session_for(client)
    assert (await client.post("/api/v1/auth/totp/setup", json={"password": "faux"}, headers=h)).status_code == 403
    r = await client.post("/api/v1/auth/totp/setup", json={"password": PW}, headers=h)
    body = r.json()
    assert (
        r.status_code == 200
        and body["uri"].startswith("otpauth://totp/LastHop")
        and body["qr"].startswith("data:image/svg+xml")
    )
    async for s in dbsession.get_session():
        row = (await s.execute(text("SELECT id, totp_enabled, totp_secret_blob FROM users WHERE sub='totpuser'"))).one()
        assert row[1] is False  # inactif tant qu'un code n'a pas été confirmé
        assert body["secret"].encode() not in bytes(row[2])  # chiffré
        assert _keyring().decrypt(bytes(row[2]), f"users_totp:{row[0]}").decode() == body["secret"]
    # tant que ce n'est pas confirmé, la connexion reste à un seul facteur
    assert (await _password_step(client)).json()["status"] == "ok"
    assert "secret" not in (await client.get("/api/v1/auth/me")).text


async def test_enable_needs_a_valid_code_then_login_is_two_step(client: httpx.AsyncClient) -> None:
    h = await _session_for(client)
    r = await client.post("/api/v1/auth/totp/setup", json={"password": PW}, headers=h)
    secret = r.json()["secret"]
    bad = await client.post("/api/v1/auth/totp/enable", json={"code": "000000"}, headers=h)
    assert bad.status_code == 422 and (await client.get("/api/v1/auth/me")).json()["totp_enabled"] is False
    ok = await client.post(
        "/api/v1/auth/totp/enable", json={"code": totp.code_at(secret, totp.current_step())}, headers=h
    )
    codes = ok.json()["recovery_codes"]
    assert ok.status_code == 200 and len(codes) == 10 and all(len(c) == 11 and c[5] == "-" for c in codes)
    assert (await client.get("/api/v1/auth/me")).json()["totp_enabled"] is True
    assert (await client.post("/api/v1/auth/totp/setup", json={"password": PW}, headers=h)).status_code == 409

    step1 = await _password_step(client)
    assert step1.json()["status"] == "totp_required" and "set-cookie" not in step1.headers
    assert (await client.get("/api/v1/auth/me")).status_code == 401  # aucune session après le seul mot de passe
    ch = step1.json()["challenge"]
    step = totp.current_step()
    done = await _second_step(client, ch, totp.code_at(secret, step + 1))  # (le pas courant a servi à l'activation)
    assert done.status_code == 200 and (await client.get("/api/v1/auth/me")).json()["totp_enabled"] is True
    assert "set-cookie" in done.headers
    assert (await _second_step(client, ch, totp.code_at(secret, step + 1))).status_code == 401  # défi à usage unique


async def test_code_cannot_be_replayed_and_older_codes_are_refused(client: httpx.AsyncClient) -> None:
    h = await _session_for(client)
    secret, _ = await _enroll(client, h)
    step = totp.current_step()
    c1 = (await _password_step(client)).json()["challenge"]
    assert (await _second_step(client, c1, totp.code_at(secret, step + 1))).status_code == 200
    c2 = (await _password_step(client)).json()["challenge"]
    assert (
        await _second_step(client, c2, totp.code_at(secret, step + 1))
    ).status_code == 401  # même code : rejeu refusé
    c3 = (await _password_step(client)).json()["challenge"]
    assert (await _second_step(client, c3, totp.code_at(secret, step))).status_code == 401  # pas antérieur : refusé


async def test_concurrent_use_of_the_same_code_succeeds_only_once(client: httpx.AsyncClient) -> None:
    from sqlalchemy import select

    from app.db.models import User

    h = await _session_for(client)
    secret, _ = await _enroll(client, h)
    code = totp.code_at(secret, totp.current_step() + 1)

    async def attempt() -> str | None:
        from app.services.totp_service import verify_second_factor

        async for s in dbsession.get_session():
            user = (await s.execute(select(User).where(User.sub == "totpuser"))).scalar_one()
            kind = await verify_second_factor(s, _keyring(), user, code)
            await s.commit()
            return kind
        return None

    results = await asyncio.gather(*(attempt() for _ in range(6)))
    assert results.count("totp") == 1 and results.count(None) == 5


async def test_wrong_codes_feed_the_progressive_lockout(client: httpx.AsyncClient) -> None:
    h = await _session_for(client)
    await _enroll(client, h)
    for _ in range(5):
        ch = (await _password_step(client)).json()["challenge"]
        assert (await _second_step(client, ch, "000000")).status_code == 401
    r = await _password_step(client)  # compte verrouillé : même le bon mot de passe est refusé
    assert r.status_code == 401 and "challenge" not in r.text
    async for s in dbsession.get_session():
        assert (
            await s.execute(text("SELECT locked_until > now() FROM users WHERE sub='totpuser'"))
        ).scalar_one() is True


async def test_a_challenge_allows_only_five_attempts(client: httpx.AsyncClient) -> None:
    h = await _session_for(client)
    secret, _ = await _enroll(client, h)
    ch = (await _password_step(client)).json()["challenge"]
    for _ in range(5):
        assert (await _second_step(client, ch, "000000")).status_code == 401
    good = totp.code_at(secret, totp.current_step() + 1)
    assert (await _second_step(client, ch, good)).status_code == 401  # défi épuisé : même un bon code ne passe plus


async def test_second_step_checks_origin_and_input_format(client: httpx.AsyncClient) -> None:
    body = {"challenge": "x" * 30, "code": "123456"}
    assert (await client.post("/api/v1/auth/local/totp", json=body)).status_code == 403
    assert (await client.post("/api/v1/auth/local/totp", json=body, headers=HEADERS)).status_code == 401  # défi inconnu
    for bad in ({"challenge": "court", "code": "123456"}, {"challenge": "x" * 30, "code": "é!"}, {**body, "extra": 1}):
        assert (await client.post("/api/v1/auth/local/totp", json=bad, headers=HEADERS)).status_code == 422


async def test_recovery_codes_work_once_in_any_format(client: httpx.AsyncClient) -> None:
    h = await _session_for(client)
    _, codes = await _enroll(client, h)
    c = (await _password_step(client)).json()["challenge"]
    assert (await _second_step(client, c, codes[0].lower().replace("-", " "))).status_code == 200
    c = (await _password_step(client)).json()["challenge"]
    assert (await _second_step(client, c, codes[0])).status_code == 401  # déjà utilisé
    c = (await _password_step(client)).json()["challenge"]
    assert (await _second_step(client, c, codes[1])).status_code == 200  # un autre code fonctionne
    async for s in dbsession.get_session():
        assert (
            await s.execute(text("SELECT jsonb_array_length(totp_recovery) FROM users WHERE sub='totpuser'"))
        ).scalar_one() == 8
        stored = (await s.execute(text("SELECT totp_recovery::text FROM users WHERE sub='totpuser'"))).scalar_one()
        assert codes[2].replace("-", "") not in stored  # hachés, jamais en clair
    assert await _audit("auth.totp_recovery_used") == 2


async def test_disable_and_regenerate_require_password_and_code(client: httpx.AsyncClient) -> None:
    h = await _session_for(client)
    secret, codes = await _enroll(client, h)
    code = totp.code_at(secret, totp.current_step() + 1)
    url = "/api/v1/auth/totp/"
    assert (await client.post(url + "disable", json={"password": "faux", "code": code}, headers=h)).status_code == 403
    assert (await client.post(url + "disable", json={"password": PW, "code": "000000"}, headers=h)).status_code == 403
    assert (await client.get("/api/v1/auth/me")).json()["totp_enabled"] is True
    # régénération : les anciens codes sont invalidés
    new = await client.post(url + "recovery-codes", json={"password": PW, "code": codes[5]}, headers=h)
    assert new.status_code == 200 and set(new.json()["recovery_codes"]).isdisjoint(codes)
    c = (await _password_step(client)).json()["challenge"]
    assert (await _second_step(client, c, codes[0])).status_code == 401
    # désactivation (avec un code de secours valide), puis connexion à un seul facteur
    c = (await _password_step(client)).json()["challenge"]
    await _second_step(client, c, new.json()["recovery_codes"][0])
    h = {"Origin": ORIGIN, "X-CSRF-Token": (await client.get("/api/v1/auth/me")).json()["csrf_token"]}
    off = await client.post(url + "disable", json={"password": PW, "code": new.json()["recovery_codes"][1]}, headers=h)
    assert off.status_code == 200
    assert (await _password_step(client)).json()["status"] == "ok"
    async for s in dbsession.get_session():
        row = (
            await s.execute(
                text(
                    "SELECT totp_secret_blob, totp_enabled, jsonb_array_length(totp_recovery) FROM users WHERE sub='totpuser'"
                )
            )
        ).one()
        assert row[0] is None and row[1] is False and row[2] == 0


async def test_totp_is_for_the_local_account_only(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-viewers")
    assert (await c.post("/api/v1/auth/totp/setup", json={"password": "x"})).status_code == 400
    assert (await client.get("/api/v1/auth/me")).json()["totp_enabled"] is False


async def test_password_change_keeps_totp_and_cli_rescue_disables_it(client: httpx.AsyncClient) -> None:
    h = await _session_for(client)
    secret, _ = await _enroll(client, h)
    ch = await client.post(
        "/api/v1/auth/password", json={"current_password": PW, "new_password": "Autre-Phrase-De-Passe-77"}, headers=h
    )
    assert ch.status_code == 200
    r = await client.post(
        "/api/v1/auth/local/login",
        json={"username": "totpuser", "password": "Autre-Phrase-De-Passe-77"},
        headers=HEADERS,
    )
    assert r.json()["status"] == "totp_required"  # le second facteur survit au changement de mot de passe
    from app.services.totp_service import disable_totp

    async for s in dbsession.get_session():
        assert await disable_totp(s, "totpuser") is True
        assert await disable_totp(s, "inconnu") is False
        await s.commit()
    r = await client.post(
        "/api/v1/auth/local/login",
        json={"username": "totpuser", "password": "Autre-Phrase-De-Passe-77"},
        headers=HEADERS,
    )
    assert r.json()["status"] == "ok"
    _ = secret
