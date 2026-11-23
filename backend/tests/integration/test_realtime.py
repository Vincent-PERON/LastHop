"""Real-Time Location de bout en bout (snmpsim : 3 équipements simultanés sur 3 IP) + flux SSE."""

import asyncio
import json

import httpx
import pytest
from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import create_lab3, wait_job

MAC_ACCESS_ARUBA = "02:bb:00:00:00:01"  # aruba port 4 (accès) ; vu en transit sur comware GE1/0/1 et cisco Gi1/0/2


async def _prepare(c, ips, **kw):  # type: ignore[no-untyped-def]
    ids = await create_lab3(c, ips, **kw)
    for name in ("aruba", "comware", "cisco"):  # topologie : ports, rôles et voisins nécessaires à la chaîne d'uplinks
        j = await wait_job(c, (await c.post(f"/api/v1/devices/{ids[name]}/topology")).json()["job_id"])
        assert j["status"] == "done", (name, j)
    return ids


def _parse(body: str) -> list[dict]:
    out, cur = [], {}
    for line in body.split("\n"):
        if line.startswith(":"):
            continue
        if not line:
            if cur:
                out.append(cur)
                cur = {}
            continue
        k, _, v = line.partition(": ")
        cur[k] = v
    return [{"id": e.get("id"), "type": e["event"], "data": json.loads(e["data"])} for e in out]


async def _search(c, query, **extra):  # type: ignore[no-untyped-def]
    r = await c.post("/api/v1/realtime", json={"query": query, **extra})
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]
    ev = await c.get(f"/api/v1/realtime/{job_id}/events")
    assert ev.status_code == 200 and ev.headers["content-type"].startswith("text/event-stream"), ev.text
    return job_id, _parse(ev.text)


def _final(events):  # type: ignore[no-untyped-def]
    ends = [e for e in events if e["type"] in ("located", "failed")]
    assert len(ends) == 1 and events[-1]["type"] == "done"
    return ends[0]


async def test_locate_mac_follows_uplink_chain_to_access_port(client, as_role, lab3, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-operators")
    admin = c  # opérateur : droits realtime ; la préparation de l'inventaire exige un admin
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    a = await as_role("lasthop-admins")
    await _prepare(a, lab3)
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    c = await as_role("lasthop-operators")
    _ = admin
    for fmt in (MAC_ACCESS_ARUBA, "02bb.0000.0001", "02-BB-00-00-00-01", "02BB00000001"):
        job_id, events = await _search(c, fmt)
        end = _final(events)
        assert end["type"] == "located", end
        r = end["data"]
        assert r["mac"] == MAC_ACCESS_ARUBA
        assert (r["location"]["device"], r["location"]["port"], r["location"]["is_device_mac"]) == ("aruba", "4", False)
        assert [(h["depth"], h["device"]) for h in r["chain"]] == [(2, "cisco"), (1, "comware")]  # du cœur vers l'accès
    types = [e["type"] for e in events]
    assert types[:2] == ["started", "fdb_querying"] and types.count("device_queried") == 3
    assert types[-4:] == ["hop", "hop", "hop", "located"] or types[-5:-1] == ["hop", "hop", "hop", "located"]
    hops = [e["data"] for e in events if e["type"] == "hop"]
    assert [h["device"] for h in hops] == ["cisco", "comware", "aruba"] and hops[-1]["role"] == "access"
    res = (await c.get(f"/api/v1/realtime/{job_id}")).json()
    assert res["status"] == "done" and res["result"]["location"]["port"] == "4"


async def test_locate_ip_through_gateway_arp(client, as_role, lab3, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    a = await as_role("lasthop-admins")
    await _prepare(a, lab3)
    cases = {
        "10.50.0.30": ("02:cc:00:00:00:00", "comware", "GE1/0/3", 1, "comware"),  # ARP via ipNetToPhysical
        "10.60.0.5": ("02:dd:00:00:00:01", "cisco", "Gi1/0/3", 20, "cisco"),  # ARP via repli ipNetToMedia
    }
    for ip, (mac, dev, port, vlan, gw) in cases.items():
        _, events = await _search(a, ip)
        end = _final(events)
        assert end["type"] == "located", end
        r = end["data"]
        assert (r["mac"], r["ip"], r["arp_gateway"]) == (mac, ip, gw)
        assert (r["location"]["device"], r["location"]["port"], r["location"]["vlan"]) == (dev, port, vlan)
        assert "arp_resolving" in [e["type"] for e in events] and "arp_resolved" in [e["type"] for e in events]


async def test_enrichment_from_learning_database(client, as_role, lab3, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    from app.services.oui import import_entries, parse_oui_csv

    a = await as_role("lasthop-admins")
    ids = await _prepare(a, lab3)
    for name in ("aruba", "comware"):  # endpoints + IP connues, historique, VLAN
        assert (await wait_job(a, (await a.post(f"/api/v1/devices/{ids[name]}/learn")).json()["job_id"]))[
            "status"
        ] == "done"
    async for s in dbsession.get_session():
        await import_entries(
            s,
            parse_oui_csv("Registry,Assignment,Organization Name,Organization Address\nMA-L,02BB00,Bravo Devices,x\n"),
        )
    _, events = await _search(a, MAC_ACCESS_ARUBA)
    r = _final(events)["data"]
    assert r["vendor"] == "Bravo Devices" and r["known_ips"] == ["10.50.0.11"] and r["ip"] == "10.50.0.11"
    assert r["first_seen"] and r["last_seen"] and r["history"][-1]["change"] == "appeared"


async def test_explicit_failure_reasons(client, as_role, lab3, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    a = await as_role("lasthop-admins")
    ids = await _prepare(a, lab3)

    async def failure(query: str) -> dict:
        _, events = await _search(a, query)
        end = _final(events)
        assert end["type"] == "failed"
        return end["data"]

    r = await failure("10.99.9.9")  # IP absente de l'ARP
    assert r["error_code"] == "IP_NOT_IN_ARP" and "comware" in r["message"]
    r = await failure("02:99:99:99:99:99")  # MAC absente de toutes les FDB
    assert r["error_code"] == "MAC_AGED_OUT" and len(r["partial"]["queried"]) == 3
    # un switch ne répond plus : on ne peut plus conclure « MAC expirée »
    bad = (
        await a.post("/api/v1/credentials", json={"name": "bad", "version": "v2c", "community": "bad-community-9"})
    ).json()["id"]
    assert (await a.put(f"/api/v1/devices/{ids['aruba']}", json={"credential_id": bad})).status_code == 200
    r = await failure("02:99:99:99:99:99")
    assert r["error_code"] == "DEVICE_UNREACHABLE" and "aruba" in r["message"]
    r = await failure(MAC_ACCESS_ARUBA)  # vu seulement en transit ; la suite de la chaîne (aruba) est muette
    assert r["error_code"] == "DEVICE_UNREACHABLE" and "aruba" in r["message"]
    # l'équipement d'accès est retiré de l'inventaire : la chaîne s'arrête sur un équipement non géré
    assert (await a.delete(f"/api/v1/devices/{ids['aruba']}")).status_code == 204
    r = await failure(MAC_ACCESS_ARUBA)
    assert r["error_code"] == "ACCESS_NOT_MANAGED" and "sw-access-aruba-01" in r["message"]


async def test_gateway_not_managed(client, as_role, lab3, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    a = await as_role("lasthop-admins")
    await create_lab3(a, lab3, l3=())
    _, events = await _search(a, "10.50.0.30")
    end = _final(events)
    assert end["type"] == "failed" and end["data"]["error_code"] == "GATEWAY_NOT_MANAGED"


async def test_global_timeout_returns_partial_progress(client, as_role, lab3, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    import ipaddress

    a = await as_role("lasthop-admins")
    await _prepare(a, lab3)
    assert (await a.put("/api/v1/settings/realtime_timeout_s", json={"value": 5})).status_code == 200
    cid = (
        await a.post("/api/v1/credentials", json={"name": "slow", "version": "v2c", "community": "slow-community-1"})
    ).json()["id"]
    ghost = str(ipaddress.ip_address(lab3[0]) + 100)  # adresse sans agent : chaque requête attend son timeout
    assert (
        await a.post(
            "/api/v1/devices",
            json={
                "name": "ghost",
                "mgmt_ip": ghost,
                "role": "access",
                "credential_id": cid,
                "snmp_port": 1161,
                "timeout_ms": 30000,
                "retries": 5,
            },
        )
    ).status_code == 201
    _, events = await _search(a, "02:99:99:99:99:99")
    end = _final(events)
    assert end["type"] == "failed" and end["data"]["error_code"] == "TIMEOUT"
    assert {"aruba", "comware", "cisco"} <= set(end["data"]["partial"]["queried"]) and "ghost" not in end["data"][
        "partial"
    ]["queried"]


async def test_sse_via_real_celery_worker_replay_and_ownership(client, as_role, lab3, app) -> None:  # type: ignore[no-untyped-def]
    a = await as_role("lasthop-admins")
    await _prepare(a, lab3)
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    op = await as_role("lasthop-operators")
    r = await op.post(
        "/api/v1/realtime", json={"query": MAC_ACCESS_ARUBA}
    )  # chemin réel : API -> file « realtime » -> worker -> Redis Stream
    assert r.status_code == 202 and r.json()["events_url"].endswith("/events")
    job_id = r.json()["job_id"]
    ev = await op.get(f"/api/v1/realtime/{job_id}/events")
    events = _parse(ev.text)
    assert _final(events)["type"] == "located" and events[0]["type"] == "started"
    # reprise : Last-Event-ID ne renvoie que la suite
    cut = events[2]["id"]
    again = _parse((await op.get(f"/api/v1/realtime/{job_id}/events", headers={"Last-Event-ID": cut})).text)
    assert [e["type"] for e in again] == [e["type"] for e in events[3:]]
    # Last-Event-ID malformé : ignoré (pas d'injection dans la commande Redis)
    bad = await op.get(f"/api/v1/realtime/{job_id}/events", headers={"Last-Event-ID": "0-0 STREAMS x"})
    assert bad.status_code == 200 and len(_parse(bad.text)) == len(events)
    # un autre opérateur ne peut ni suivre ni lire ce job ; un admin le peut
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    other = await as_role("lasthop-operators")
    assert (await other.get(f"/api/v1/realtime/{job_id}/events")).status_code == 404
    assert (await other.get(f"/api/v1/realtime/{job_id}")).status_code == 404
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    adm = await as_role("lasthop-admins")
    assert (await adm.get(f"/api/v1/realtime/{job_id}")).status_code == 200


async def test_access_control_validation_and_limits(client, as_role, lab3, inline_jobs, app) -> None:  # type: ignore[no-untyped-def]
    assert (await client.post("/api/v1/realtime", json={"query": MAC_ACCESS_ARUBA})).status_code == 401
    v = await as_role("lasthop-viewers")
    assert (
        await v.post("/api/v1/realtime", json={"query": MAC_ACCESS_ARUBA})
    ).status_code == 403  # viewer : pas de temps réel
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    op = await as_role("lasthop-operators")
    for bad in (
        {"query": "not-an-address"},
        {"query": "1.2.3.4; DROP"},
        {"query": MAC_ACCESS_ARUBA, "x": 1},
        {"query": ""},
        {},
    ):
        assert (await op.post("/api/v1/realtime", json=bad)).status_code == 422, bad
    assert (
        await op.post(
            "/api/v1/realtime", json={"query": MAC_ACCESS_ARUBA, "site_id": "00000000-0000-0000-0000-000000000000"}
        )
    ).status_code == 422
    # plafond de concurrence : 2 recherches déjà en cours pour cet utilisateur
    uid = (await op.get("/api/v1/auth/me")).json()["user_id"]
    async for s in dbsession.get_session():
        for _ in range(2):
            await s.execute(
                text(
                    "INSERT INTO jobs(id, kind, status, requested_by, params) VALUES (gen_random_uuid(), 'realtime', 'running', CAST(:u AS uuid), '{}')"
                ),
                {"u": uid},
            )
        await s.commit()
    assert (await op.post("/api/v1/realtime", json={"query": MAC_ACCESS_ARUBA})).status_code == 429
    # limitation de débit : 6 par minute et par utilisateur (les 422 ci-dessus en ont déjà consommé 6 => 429 aussi)
    assert (await op.post("/api/v1/realtime", json={"query": "10.0.0.1"})).status_code == 429


async def test_realtime_is_audited_and_token_scope_works(client, as_role, lab3, inline_jobs, app) -> None:  # type: ignore[no-untyped-def]
    a = await as_role("lasthop-admins")
    await _prepare(a, lab3)
    tok = (await a.post("/api/v1/tokens", json={"name": "rt", "scopes": ["realtime"]})).json()["token"]
    tok_search = (await a.post("/api/v1/tokens", json={"name": "s", "scopes": ["search"]})).json()["token"]
    t = httpx.ASGITransport(app=app, client=("10.252.1.1", 1))
    async with httpx.AsyncClient(transport=t, base_url="https://lasthop.test") as b:
        assert (
            await b.post(
                "/api/v1/realtime", json={"query": MAC_ACCESS_ARUBA}, headers={"Authorization": f"Bearer {tok_search}"}
            )
        ).status_code == 403
        r = await b.post(
            "/api/v1/realtime", json={"query": MAC_ACCESS_ARUBA}, headers={"Authorization": f"Bearer {tok}"}
        )
        assert r.status_code == 202
        ev = await b.get(f"/api/v1/realtime/{r.json()['job_id']}/events", headers={"Authorization": f"Bearer {tok}"})
        assert _final(_parse(ev.text))["type"] == "located"
    async for s in dbsession.get_session():
        rows = (
            await s.execute(
                text(
                    "SELECT action, details->>'query', outcome FROM audit_log WHERE action IN ('realtime.search','realtime.result') ORDER BY id DESC LIMIT 2"
                )
            )
        ).all()
    assert {r[0] for r in rows} == {"realtime.search", "realtime.result"} and {r[1] for r in rows} == {MAC_ACCESS_ARUBA}


async def test_targeted_get_with_vlan_hint_and_walk_fallback_agree(lab3) -> None:  # type: ignore[no-untyped-def]
    from app.snmp.bridge import lookup_mac
    from app.snmp.client import SnmpClient, SnmpCredential, SnmpTarget

    mac = bytes.fromhex("02cc00000000")  # Comware : seulement en Q-BRIDGE (VLAN 1), port 3
    t = SnmpTarget(
        host=lab3[1],
        port=1161,
        credential=SnmpCredential(version="v2c", community="lab-comware"),
        timeout_s=2,
        retries=0,
    )
    async with SnmpClient(t) as c:
        hinted = await lookup_mac(c, mac, [1])  # GET ciblé dot1qTpFdbPort.<vlan>.<mac>
        walked = await lookup_mac(c, mac, [])  # BRIDGE-MIB vide -> parcours Q-BRIDGE avec arrêt à la correspondance
        wrong_hint = await lookup_mac(c, mac, [99])
        absent = await lookup_mac(c, bytes.fromhex("02ee99999999"), [1])
    assert hinted is not None and hinted == walked == wrong_hint and (hinted.vlan, hinted.bridge_port) == (1, 3)
    assert absent is None


_ = (asyncio, pytest)
