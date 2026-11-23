from __future__ import annotations

import os
import secrets
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import pytest_asyncio
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.config import Settings
from app.db import session as dbsession
from app.main import create_app

ISSUER = "https://idp.test/realms/lasthop"
ORIGIN = "https://lasthop.test"
CLIENT_ID = "lasthop"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "Adm1n-Test-Passphrase-42"  # compte super admin local des tests (jetable)
OIDC_PROVIDER_NAME = "test-oidc"


class FakeIdP:
    """IdP OIDC simulé : découverte, JWKS, endpoint de token (id_token signé RS256)."""

    def __init__(self) -> None:
        self.key = RSAKey.generate_key(2048, parameters={"kid": "k1", "use": "sig"})
        self.other_key = RSAKey.generate_key(2048, parameters={"kid": "k1", "use": "sig"})  # kid identique, autre clé
        self.next_claims: dict[str, Any] = {}
        self.sign_with = self.key
        self.alg = "RS256"
        self.token_status = 200

    def make_token(self, claims: dict[str, Any]) -> str:
        return jwt.encode({"alg": self.alg, "kid": "k1"}, claims, self.sign_with)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": ISSUER + "/auth",
                    "token_endpoint": ISSUER + "/token",
                    "jwks_uri": ISSUER + "/certs",
                },
            )
        if path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [self.key.as_dict(private=False)]})
        if path.endswith("/token"):
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_grant"})
            body = parse_qs(request.content.decode())
            assert body["code_verifier"] and body["client_secret"] == ["test-client-secret"]
            return httpx.Response(200, json={"id_token": self.make_token(self.next_claims)})
        return httpx.Response(404)

    def claims(self, nonce: str, *, groups: list[str] | None, sub: str | None = None, **over: Any) -> dict[str, Any]:
        now = int(time.time())
        c: dict[str, Any] = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": sub or str(uuid.uuid4()),
            "exp": now + 300,
            "iat": now,
            "nonce": nonce,
            "email": "alice@example.org",
            "name": "Alice",
            "groups": groups,
        }
        c.update(over)
        return c


@pytest.fixture(scope="session")
def idp() -> FakeIdP:
    return FakeIdP()


@pytest.fixture(scope="session")
def settings() -> Settings:
    return Settings(
        env="dev",
        frontend_origin=ORIGIN,
        local_admin_username=ADMIN_USER,
        local_admin_password=ADMIN_PASSWORD,
        local_admin_must_change=False,
        max_body_bytes=4096,
    )


@pytest_asyncio.fixture(scope="session")
async def app(settings: Settings, idp: FakeIdP) -> AsyncIterator[Any]:
    application = create_app(settings, oidc_transport=httpx.MockTransport(idp.handler))
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture(scope="session")
async def owner_engine() -> AsyncIterator[AsyncEngine]:
    from urllib.parse import quote

    pw = open(os.environ["LASTHOP_DB_OWNER_PASSWORD_FILE"]).read().strip()
    e = create_async_engine(f"postgresql+asyncpg://lasthop_owner:{quote(pw)}@{os.environ['LASTHOP_DB_HOST']}/lasthop")
    yield e
    await e.dispose()


@pytest_asyncio.fixture
async def client(app: Any) -> AsyncIterator[httpx.AsyncClient]:
    """Client HTTPS avec une IP source unique par test (isole les compteurs de rate-limit)."""
    ip = f"10.{secrets.randbelow(250)}.{secrets.randbelow(250)}.{secrets.randbelow(250) + 1}"
    transport = httpx.ASGITransport(app=app, client=(ip, 5000))
    async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as c:
        yield c
    # nettoyage : compteurs de limitation (le compte local de référence, lui, persiste d'un test à l'autre)
    async for k in app.state.redis.scan_iter(match="rl:*"):
        await app.state.redis.delete(k)
    # nettoyage : les utilisateurs et leurs tokens créés par le test
    async for s in dbsession.get_session():
        for table in (
            "endpoint_history",
            "endpoints",
            "oui",
            "jobs",
            "config_backups",
            "backup_runs",
            "devices",
            "snmp_credentials",
            "ssh_credentials",
            "sites",
        ):
            await s.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - noms constants
        await s.execute(text("DELETE FROM api_tokens"))
        await s.execute(text("DELETE FROM auth_providers"))
        await s.execute(
            text("DELETE FROM users WHERE issuer = :i OR issuer LIKE 'ldap:%' OR (issuer = 'local' AND sub <> :a)"),
            {"i": ISSUER, "a": ADMIN_USER},
        )
        await s.execute(  # le compte local de référence est conservé : seuls ses compteurs sont remis à zéro
            text(
                "UPDATE users SET failed_login_count = 0, locked_until = NULL, is_active = true WHERE issuer = 'local'"
            )
        )
        await s.execute(text("DELETE FROM app_settings"))
        await s.commit()


def _keyring():  # type: ignore[no-untyped-def]
    from app.security.crypto import keyring_from_settings

    s = Settings(env="dev", frontend_origin=ORIGIN)
    return keyring_from_settings(s.master_keys, s.master_key_active)


async def make_provider(  # type: ignore[no-untyped-def]
    name: str = OIDC_PROVIDER_NAME,
    *,
    kind: str = "oidc",
    preset: str = "generic",
    config: dict[str, Any] | None = None,
    secret: str | None = "test-client-secret",  # noqa: S107
    role_map: dict[str, str] | None = None,
    default_role: str | None = None,
    enabled: bool = True,
) -> str:
    """Insère un fournisseur d'identité de test (secret chiffré comme en production) et retourne son identifiant."""
    import json

    from app.services.auth_providers import seal_secret

    pid = uuid.uuid4()
    cfg = (
        config
        if config is not None
        else {
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "scopes": "openid profile email",
            "groups_claim": "groups",
            "allowed_domains": [],
            "require_email_verified": False,
            "required_acr": None,
        }
    )
    blob, kid = seal_secret(_keyring(), pid, secret) if secret else (None, None)
    roles = role_map if role_map is not None else {"lasthop-operators": "operator", "lasthop-viewers": "viewer"}
    async for s in dbsession.get_session():
        await s.execute(
            text(
                "INSERT INTO auth_providers(id, kind, preset, name, enabled, config, secret_blob, key_id, role_map,"
                " default_role) VALUES (:i, :k, :p, :n, :e, CAST(:c AS jsonb), :b, :kid, CAST(:r AS jsonb), :d)"
            ),
            {
                "i": pid,
                "k": kind,
                "p": preset,
                "n": name,
                "e": enabled,
                "c": json.dumps(cfg),
                "b": blob,
                "kid": kid,
                "r": json.dumps(roles),
                "d": default_role,
            },
        )
        await s.commit()
    return str(pid)


async def oidc_provider_id(name: str = OIDC_PROVIDER_NAME) -> str:
    """Identifiant du fournisseur OIDC de test (créé à la demande)."""
    async for s in dbsession.get_session():
        row = (await s.execute(text("SELECT id FROM auth_providers WHERE name = :n"), {"n": name})).scalar_one_or_none()
        if row is not None:
            return str(row)
    return await make_provider(name)


async def login(
    client: httpx.AsyncClient, idp: FakeIdP, groups: list[str] | None, provider: str | None = None, **over: Any
) -> httpx.Response:
    pid = provider or await oidc_provider_id()
    r = await client.get(f"/api/v1/auth/oidc/{pid}/login", params={"next": "/devices"})
    assert r.status_code == 302, r.text
    q = parse_qs(urlparse(r.headers["location"]).query)
    idp.next_claims = idp.claims(q["nonce"][0], groups=groups, **over)
    return await client.get("/api/v1/auth/oidc/callback", params={"code": "abc", "state": q["state"][0]})


async def local_login(
    client: httpx.AsyncClient, username: str = ADMIN_USER, password: str = ADMIN_PASSWORD
) -> httpx.Response:
    return await client.post(
        "/api/v1/auth/local/login",
        json={"username": username, "password": password},
        headers={"Origin": ORIGIN},
    )


async def make_local_user(username: str, password: str, *, role: str = "admin", must_change: bool = False) -> None:
    from app.security.passwords import hash_password

    h = await hash_password(password)
    async for s in dbsession.get_session():
        await s.execute(
            text(
                "INSERT INTO users(id, issuer, sub, role, display_name, password_hash, must_change_password)"
                " VALUES (gen_random_uuid(), 'local', :u, CAST(:r AS user_role), :u, :h, :m)"
            ),
            {"u": username, "r": role, "h": h, "m": must_change},
        )
        await s.commit()


@pytest.fixture
def as_role(client: httpx.AsyncClient, idp: FakeIdP):  # type: ignore[no-untyped-def]
    """Ouvre une session du rôle voulu : « lasthop-admins » = compte super admin LOCAL ; sinon connexion OIDC avec ce groupe
    (un compte fédéré ne peut jamais être super admin)."""

    async def _do(group: str) -> httpx.AsyncClient:
        client.cookies.clear()
        if group == "lasthop-admins":
            r = await local_login(client)
            assert r.status_code == 200, r.text
        else:
            r = await login(client, idp, [group])
            assert r.status_code == 302, r.text
        me = (await client.get("/api/v1/auth/me")).json()
        client.headers["Origin"] = ORIGIN
        client.headers["X-CSRF-Token"] = me["csrf_token"]
        return client

    return _do


SNMPSIM_PORT = 1161
V3 = {"v3_username": "lasthop-test", "auth_key": "test-auth-key-1234", "priv_key": "test-priv-key-1234"}


@pytest.fixture(scope="session")
def sim_ip() -> str:
    import socket

    return socket.gethostbyname("snmpsim")


@pytest_asyncio.fixture
async def lab(client: httpx.AsyncClient, sim_ip: str):  # type: ignore[no-untyped-def]
    """Autorise le réseau du simulateur et active v2c (écriture directe en base, comme le ferait un admin)."""
    import ipaddress
    import json

    net = str(ipaddress.ip_network(f"{sim_ip}/24", strict=False))
    async for s in dbsession.get_session():
        for k, v in (("snmp_allowed_cidrs", [net]), ("snmp_v2c_enabled", True)):
            await s.execute(
                text("INSERT INTO app_settings(key, value) VALUES (:k, CAST(:v AS jsonb))"),
                {"k": k, "v": json.dumps(v)},
            )
        await s.commit()
    return {"ip": sim_ip, "net": net}


@pytest.fixture
def inline_jobs(app: Any):  # type: ignore[no-untyped-def]
    """Exécute les jobs immédiatement dans le processus de test (au lieu de passer par Celery)."""
    from app.security.crypto import keyring_from_settings
    from app.services.probe import process_job

    original = app.state.dispatch_job

    async def run(job_id: uuid.UUID, queue: str | None = None) -> None:
        s = app.state.settings
        async for db in dbsession.get_session():
            await process_job(db, keyring_from_settings(s.master_keys, s.master_key_active), job_id, app.state.redis)

    app.state.dispatch_job = run
    yield
    app.state.dispatch_job = original


async def create_three(c, sim_ip, *, v3_cisco: bool = False):  # type: ignore[no-untyped-def]
    """3 équipements de laboratoire (aruba L2, comware L2+L3, cisco L2+L3). `mgmt_ip` étant unique, les lignes reçoivent des
    adresses distinctes ; `run_on_sim` les redirige vers le simulateur le temps d'une collecte."""
    import ipaddress

    base = ipaddress.ip_address(sim_ip)
    specs = (
        ("aruba", "lab-aruba", "access", False),
        ("comware", "lab-comware", "distribution", True),
        ("cisco", "lab-cisco", "core", True),
    )
    ids = {}
    for n, (name, comm, role, l3) in enumerate(specs):
        if name == "cisco" and v3_cisco:
            body = {"name": f"cred-{name}", "version": "v3", **V3}
        else:
            body = {"name": f"cred-{name}", "version": "v2c", "community": comm}
        cid = (await c.post("/api/v1/credentials", json=body)).json()["id"]
        dev = {
            "name": name,
            "mgmt_ip": str(base + 20 + n),
            "role": role,
            "credential_id": cid,
            "snmp_port": SNMPSIM_PORT,
            "timeout_ms": 1500,
            "retries": 0,
            "is_l3": l3,
            "is_l2": True,
        }
        if name == "cisco" and v3_cisco:
            dev["snmp_context"] = "lab-cisco"
        r = await c.post("/api/v1/devices", json=dev)
        assert r.status_code == 201, r.text
        ids[name] = r.json()["id"]
    return ids


async def run_on_sim(c, sim_ip, ids, name, kind, wait):  # type: ignore[no-untyped-def]
    """Lance le job `kind` (topology|learn) sur l'équipement `name` en le dirigeant vers le simulateur."""
    import ipaddress

    names = list(ids)
    async for s in dbsession.get_session():
        await s.execute(
            text("UPDATE devices SET mgmt_ip = CAST(:ip AS inet) WHERE id = CAST(:i AS uuid)"),
            {"ip": sim_ip, "i": ids[name]},
        )
        await s.commit()
    try:
        j = await wait(c, (await c.post(f"/api/v1/devices/{ids[name]}/{kind}")).json()["job_id"])
    finally:
        async for s in dbsession.get_session():
            await s.execute(
                text("UPDATE devices SET mgmt_ip = CAST(:ip AS inet) WHERE id = CAST(:i AS uuid)"),
                {"ip": str(ipaddress.ip_address(sim_ip) + 20 + names.index(name)), "i": ids[name]},
            )
            await s.commit()
    return j


async def wait_job(c, job_id, timeout=40.0):  # type: ignore[no-untyped-def]
    import asyncio

    for _ in range(int(timeout / 0.25)):
        j = (await c.get(f"/api/v1/jobs/{job_id}")).json()
        if j["status"] in ("done", "failed"):
            return j
        await asyncio.sleep(0.25)
    raise AssertionError("job non terminé")


@pytest.fixture(scope="session")
def sim_ips() -> list[str]:
    """3 adresses distinctes du même simulateur (aliases réseau sim-a/b/c) : aruba, comware, cisco."""
    import socket

    return [socket.gethostbyname(h) for h in ("sim-a", "sim-b", "sim-c")]


@pytest_asyncio.fixture
async def lab3(client: httpx.AsyncClient, sim_ips: list[str]):  # type: ignore[no-untyped-def]
    import ipaddress
    import json

    nets = sorted({str(ipaddress.ip_network(f"{ip}/24", strict=False)) for ip in sim_ips})
    async for s in dbsession.get_session():
        for k, v in (("snmp_allowed_cidrs", nets), ("snmp_v2c_enabled", True)):
            await s.execute(
                text("INSERT INTO app_settings(key, value) VALUES (:k, CAST(:v AS jsonb))"),
                {"k": k, "v": json.dumps(v)},
            )
        await s.commit()
    return sim_ips


async def create_lab3(c, ips, *, l3=("comware", "cisco")):  # type: ignore[no-untyped-def]
    """aruba/comware/cisco sur 3 IP différentes : permet les recherches simultanées du temps réel."""
    ids = {}
    for ip, (name, comm, role) in zip(
        ips,
        (("aruba", "lab-aruba", "access"), ("comware", "lab-comware", "distribution"), ("cisco", "lab-cisco", "core")),
        strict=True,
    ):
        cid = (
            await c.post("/api/v1/credentials", json={"name": f"cred-{name}", "version": "v2c", "community": comm})
        ).json()["id"]
        r = await c.post(
            "/api/v1/devices",
            json={
                "name": name,
                "mgmt_ip": ip,
                "role": role,
                "credential_id": cid,
                "snmp_port": SNMPSIM_PORT,
                "timeout_ms": 1500,
                "retries": 0,
                "is_l3": name in l3,
                "is_l2": True,
            },
        )
        assert r.status_code == 201, r.text
        ids[name] = r.json()["id"]
    return ids
