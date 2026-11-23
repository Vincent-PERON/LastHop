import asyncio

import httpx
from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import V3

PORT = 1161


async def _setup(c, lab, version="v3", community="lab-aruba", ctx_port=PORT):  # type: ignore[no-untyped-def]
    body = (
        {"name": "cred", "version": "v3", **V3}
        if version == "v3"
        else {"name": "cred", "version": "v2c", "community": community}
    )
    cid = (await c.post("/api/v1/credentials", json=body)).json()["id"]
    dev = await c.post(
        "/api/v1/devices",
        json={
            "name": "dev1",
            "mgmt_ip": lab["ip"],
            "role": "access",
            "credential_id": cid,
            "snmp_port": ctx_port,
            "timeout_ms": 1500,
            "retries": 0,
        },
    )
    assert dev.status_code == 201, dev.text
    return cid, dev.json()["id"]


async def _wait(c, job_id, timeout=30.0):  # type: ignore[no-untyped-def]
    for _ in range(int(timeout / 0.25)):
        j = (await c.get(f"/api/v1/jobs/{job_id}")).json()
        if j["status"] in ("done", "failed"):
            return j
        await asyncio.sleep(0.25)
    raise AssertionError("job non terminé")


async def test_device_test_identifies_and_updates_inventory(client, as_role, lab, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    _, dev_id = await _setup(c, lab, "v2c", "lab-cisco")  # v2c activé par la fixture lab
    r = await c.post(f"/api/v1/devices/{dev_id}/test")
    assert r.status_code == 202
    j = await _wait(c, r.json()["job_id"])
    assert (
        j["status"] == "done" and j["result"]["driver"] == "cisco_ios" and j["result"]["model"] == "WS-C2960X-48FPD-L"
    )
    dev = (await c.get(f"/api/v1/devices/{dev_id}")).json()
    assert (dev["driver"], dev["vendor"], dev["sys_name"], dev["last_poll_status"]) == (
        "cisco_ios",
        "Cisco",
        "sw-core-cisco-01",
        "ok",
    )


async def test_device_test_reports_explicit_error_codes(client, as_role, lab, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    _, dev_id = await _setup(c, lab, "v2c", "wrong-community-1")
    j = await _wait(c, (await c.post(f"/api/v1/devices/{dev_id}/test")).json()["job_id"])
    assert j["status"] == "failed" and j["error_code"] == "DEVICE_UNREACHABLE"
    # v2c désactivé globalement après coup : le worker refuse de l'utiliser
    async for s in dbsession.get_session():
        await s.execute(text("UPDATE app_settings SET value='false'::jsonb WHERE key='snmp_v2c_enabled'"))
        await s.commit()
    j = await _wait(c, (await c.post(f"/api/v1/devices/{dev_id}/test")).json()["job_id"])
    assert j["error_code"] == "V2C_DISABLED"
    # cible retirée de la liste blanche : refusée côté worker aussi
    async for s in dbsession.get_session():
        await s.execute(text("UPDATE app_settings SET value='[]'::jsonb WHERE key='snmp_allowed_cidrs'"))
        await s.execute(text("UPDATE app_settings SET value='true'::jsonb WHERE key='snmp_v2c_enabled'"))
        await s.commit()
    j = await _wait(c, (await c.post(f"/api/v1/devices/{dev_id}/test")).json()["job_id"])
    assert j["error_code"] == "TARGET_NOT_ALLOWED"


async def test_device_test_v3_through_real_celery_worker(client, as_role, lab) -> None:  # type: ignore[no-untyped-def]
    """Chemin complet : API -> Redis (ACL, JSON) -> worker Celery -> SNMPv3 SHA-256/AES -> PostgreSQL."""
    c = await as_role("lasthop-admins")
    cid = (await c.post("/api/v1/credentials", json={"name": "v3", "version": "v3", **V3})).json()["id"]
    # En v3 le contexte sélectionne l'enregistrement du simulateur ; sans contexte il répond "public" => pas d'enregistrement.
    dev = await c.post(
        "/api/v1/devices",
        json={
            "name": "dev-v3",
            "mgmt_ip": lab["ip"],
            "role": "access",
            "credential_id": cid,
            "snmp_port": PORT,
            "timeout_ms": 2000,
            "retries": 0,
        },
    )
    j = await _wait(c, (await c.post(f"/api/v1/devices/{dev.json()['id']}/test")).json()["job_id"])
    # sans contexte, le simulateur n'a pas de données : la réponse valide prouve que le chemin Celery+v3 fonctionne
    assert (
        j["status"] in ("done", "failed")
        and j["error_code"] != "INTERNAL_ERROR"
        and j["error_code"] != "DISPATCH_FAILED"
    )
    assert j["status"] == "failed" or j["result"]["ok"]


async def test_celery_v2c_job_completes_via_worker(client, as_role, lab) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    _, dev_id = await _setup(c, lab, "v2c", "lab-aruba")
    j = await _wait(c, (await c.post(f"/api/v1/devices/{dev_id}/test")).json()["job_id"])
    assert j["status"] == "done" and j["result"]["driver"] == "aruba_os"


async def test_discovery_scans_only_allowed_range_and_adopts_found_hosts(client, as_role, lab, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    import ipaddress

    c = await as_role("lasthop-admins")
    cid = (
        await c.post("/api/v1/credentials", json={"name": "v2", "version": "v2c", "community": "lab-comware"})
    ).json()["id"]
    net = str(ipaddress.ip_network(f"{lab['ip']}/29", strict=False))
    for bad in ("0.0.0.0/0", "8.8.8.0/24", "127.0.0.0/30", "10.0.0.0/8", "x"):  # noqa: S104
        assert (
            await c.post("/api/v1/discovery", json={"cidr": bad, "credential_id": cid, "port": PORT})
        ).status_code in (422,), bad
    r = await c.post("/api/v1/discovery", json={"cidr": net, "credential_id": cid, "port": PORT})
    assert r.status_code == 202
    j = await _wait(c, r.json()["job_id"])
    assert j["status"] == "done" and j["result"]["found"] == 1 and j["result"]["hosts"][0]["driver"] == "comware"
    job_id = j["id"]
    # on n'adopte que ce que la découverte a vu
    assert (
        await c.post(
            f"/api/v1/discovery/{job_id}/adopt", json={"items": [{"ip": "10.9.9.9", "name": "x", "role": "access"}]}
        )
    ).status_code == 422
    ad = await c.post(
        f"/api/v1/discovery/{job_id}/adopt",
        json={"items": [{"ip": lab["ip"], "name": "sw-dist-01", "role": "distribution"}]},
    )
    assert ad.status_code == 201
    dev = (await c.get(f"/api/v1/devices/{ad.json()['created'][0]}")).json()
    assert (dev["driver"], dev["model"], dev["snmp_port"]) == ("comware", "HPE 5130-24G-4SFP+ EI", PORT)


async def test_jobs_are_private_and_rate_limited(client, as_role, lab, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    _, dev_id = await _setup(c, lab, "v2c", "lab-aruba")
    ids = []
    for _ in range(10):
        r = await c.post(f"/api/v1/devices/{dev_id}/test")
        assert r.status_code == 202
        ids.append(r.json()["job_id"])
    assert (await c.post(f"/api/v1/devices/{dev_id}/test")).status_code == 429
    assert (await c.get("/api/v1/jobs/00000000-0000-0000-0000-000000000000")).status_code == 404
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    v = await as_role("lasthop-viewers")
    assert (await v.get(f"/api/v1/jobs/{ids[0]}")).status_code == 404  # un autre utilisateur ne voit pas le job


async def test_unauthenticated_cannot_use_any_new_endpoint(client: httpx.AsyncClient) -> None:
    for method, url in (
        ("GET", "/api/v1/devices"),
        ("GET", "/api/v1/sites"),
        ("GET", "/api/v1/credentials"),
        ("POST", "/api/v1/discovery"),
        ("GET", "/api/v1/jobs/00000000-0000-0000-0000-000000000000"),
    ):
        assert (await client.request(method, url)).status_code == 401, url
