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
        oidc_issuer=ISSUER,
        oidc_client_id=CLIENT_ID,
        oidc_client_secret="test-client-secret",
        oidc_redirect_uri=ORIGIN + "/api/v1/auth/callback",
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
    # nettoyage : les utilisateurs (et leurs tokens, en cascade) créés par le test
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
        await s.execute(text("DELETE FROM users WHERE issuer = :i"), {"i": ISSUER})
        await s.execute(text("DELETE FROM app_settings"))
        await s.commit()


async def login(client: httpx.AsyncClient, idp: FakeIdP, groups: list[str] | None, **over: Any) -> httpx.Response:
    r = await client.get("/api/v1/auth/login", params={"next": "/devices"})
    assert r.status_code == 302, r.text
    q = parse_qs(urlparse(r.headers["location"]).query)
    idp.next_claims = idp.claims(q["nonce"][0], groups=groups, **over)
    return await client.get("/api/v1/auth/callback", params={"code": "abc", "state": q["state"][0]})


@pytest.fixture
def as_role(client: httpx.AsyncClient, idp: FakeIdP):  # type: ignore[no-untyped-def]
    async def _do(group: str) -> httpx.AsyncClient:
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
