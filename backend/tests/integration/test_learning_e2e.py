"""Learning de bout en bout contre snmpsim : ARP (ipNetToPhysical / ipNetToMedia), FDB (Q-BRIDGE / BRIDGE-MIB / VLAN Cisco)."""

import httpx
from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import create_three, run_on_sim, wait_job

# (mac, ip) -> (équipement, port, vlan) attendus après collecte des 3 équipements
EXPECTED = {
    ("02:bb:00:00:00:01", "10.50.0.11"): ("aruba", "4", None),
    ("02:bb:00:00:00:02", "10.50.0.12"): ("aruba", "4", None),
    ("02:ee:00:00:00:01", "10.50.0.21"): ("aruba", "2", None),
    ("02:cc:00:00:00:00", "10.50.0.30"): ("comware", "GE1/0/3", 1),
    ("02:cc:00:00:00:01", "10.50.0.31"): ("comware", "GE1/0/3", 1),
    ("02:cc:00:00:00:02", "10.50.0.32"): ("comware", "GE1/0/3", 1),
    ("02:cc:00:00:00:03", "10.50.0.33"): ("comware", "GE1/0/3", 1),
    ("02:cc:00:00:00:04", None): ("comware", "GE1/0/3", 1),
    ("02:dd:00:00:00:01", "10.50.0.40"): ("cisco", "Gi1/0/3", 20),  # IP vue par le routeur Comware
    ("02:dd:00:00:00:01", "10.60.0.5"): ("cisco", "Gi1/0/3", 20),  # IP vue par Cisco (repli ipNetToMedia)
    ("02:dd:00:00:00:02", None): ("cisco", "Gi1/0/4", 10),
}


async def _learn_all(c, sim_ip, ids, order=("aruba", "comware", "cisco")):  # type: ignore[no-untyped-def]
    for name in order:
        j = await run_on_sim(c, sim_ip, ids, name, "learn", wait_job)
        assert j["status"] == "done", (name, j)


async def _endpoints(c):  # type: ignore[no-untyped-def]
    r = (await c.get("/api/v1/endpoints", params={"limit": 200})).json()
    return {(e["mac"], e["ip"]): e for e in r["items"]}


async def test_learning_three_vendors_end_to_end(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    await _learn_all(c, sim_ip, ids)
    eps = await _endpoints(c)
    got = {k: (e["device"], e["port"], e["vlan"]) for k, e in eps.items()}
    assert got == EXPECTED
    # exclus : 25 MAC du port 3 d'Aruba (> seuil => uplink), MAC de passage sur les uplinks, entrées self/invalid, ARP incomplet/invalid/diffusion
    assert not any(m.startswith(("02:aa", "02:ff", "ff:")) for m, _ in eps)
    # les équipements portent le statut de leur dernière collecte
    dev = (await c.get(f"/api/v1/devices/{ids['cisco']}")).json()
    assert dev["last_learning_status"] == "ok" and dev["last_learning_at"]


async def test_cisco_per_vlan_contexts_with_snmpv3(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    """v3 : contextName vlan-10 / vlan-20 (instances de bridge distinctes, ports numérotés différemment par VLAN)."""
    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip, v3_cisco=True)
    j = await run_on_sim(c, sim_ip, ids, "cisco", "learn", wait_job)
    assert j["status"] == "done", j
    got = {k: (e["device"], e["port"], e["vlan"]) for k, e in (await _endpoints(c)).items()}
    assert got == {
        ("02:dd:00:00:00:01", "10.60.0.5"): ("cisco", "Gi1/0/3", 20),
        ("02:dd:00:00:00:02", None): ("cisco", "Gi1/0/4", 10),
    }


async def test_failed_collection_leaves_endpoints_untouched(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    await _learn_all(c, sim_ip, ids, order=("aruba",))
    before = await _endpoints(c)
    assert before
    bad = (
        await c.post("/api/v1/credentials", json={"name": "bad", "version": "v2c", "community": "bad-community-9"})
    ).json()["id"]
    assert (await c.put(f"/api/v1/devices/{ids['aruba']}", json={"credential_id": bad})).status_code == 200
    j = await run_on_sim(c, sim_ip, ids, "aruba", "learn", wait_job)
    assert (j["status"], j["error_code"]) == ("failed", "DEVICE_UNREACHABLE")
    assert await _endpoints(c) == before  # aucun endpoint n'a « disparu »
    assert (await c.get(f"/api/v1/devices/{ids['aruba']}")).json()["last_learning_status"] == "DEVICE_UNREACHABLE"


async def test_history_endpoint_and_device_deletion(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    await _learn_all(c, sim_ip, ids, order=("aruba",))
    ep = (await _endpoints(c))[("02:bb:00:00:00:01", None)]
    h = (await c.get(f"/api/v1/endpoints/{ep['id']}/history")).json()
    assert [x["change"] for x in h] == ["appeared"] and h[0]["new"]["port"] == "4"
    assert (await c.get("/api/v1/endpoints/00000000-0000-0000-0000-000000000000/history")).status_code == 404
    assert (await c.delete(f"/api/v1/devices/{ids['aruba']}")).status_code == 204
    after = (await c.get("/api/v1/endpoints", params={"active": "true"})).json()
    assert after["total"] == 0  # les endpoints d'un équipement supprimé deviennent inactifs
    assert (await c.get("/api/v1/endpoints", params={"active": "false"})).json()["total"] == 3


async def test_endpoint_search_filters(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    await _learn_all(c, sim_ip, ids)

    async def q(**p: object) -> set[tuple[str, str | None]]:
        r = await c.get("/api/v1/endpoints", params={k: str(v) for k, v in p.items()})
        assert r.status_code == 200, (p, r.text)
        return {(e["mac"], e["ip"]) for e in r.json()["items"]}

    full = ("02:bb:00:00:00:01", "10.50.0.11")
    for fmt in ("02:bb:00:00:00:01", "02bb.0000.0001", "02-BB-00-00-00-01", "02bb00000001"):
        assert await q(mac=fmt) == {full}
    assert len(await q(mac="02cc")) == 5  # partielle
    assert len(await q(ip="10.50.0.0/24")) == 8 and await q(ip="10.50.0.11") == {full}
    assert len(await q(vlan=1)) == 5 and len(await q(vlan=20)) == 2
    assert len(await q(device_id=ids["aruba"])) == 3
    for bad in (
        {"mac": "zz"},
        {"mac": "%"},
        {"ip": "nope"},
        {"vlan": 5000},
        {"limit": 1000},
        {"mac": "a'; DROP TABLE users;--"},
    ):
        assert (await c.get("/api/v1/endpoints", params={k: str(v) for k, v in bad.items()})).status_code == 422, bad
    page = (await c.get("/api/v1/endpoints", params={"limit": 4, "offset": 8})).json()
    assert page["total"] == 11 and len(page["items"]) == 3


async def test_vendor_and_hostname_enrichment(client, as_role, lab, sim_ip, inline_jobs, app) -> None:  # type: ignore[no-untyped-def]
    from app.services.dns import resolve_pending
    from app.services.oui import import_entries, parse_oui_csv

    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    await _learn_all(c, sim_ip, ids, order=("aruba", "comware"))  # le routeur Comware fournit les IP
    csv_text = "Registry,Assignment,Organization Name,Organization Address\nMA-L,02BB00,Bravo Devices <b>Inc</b>,x\n"
    async for s in dbsession.get_session():
        await import_entries(s, parse_oui_csv(csv_text))

        async def fake(ip: str) -> str | None:
            return {"10.50.0.11": "PC-Compta.Corp.Local.", "10.50.0.12": "bad host!"}.get(ip)

        assert await resolve_pending(s, resolver=fake) == 7  # seuls les endpoints ayant une IP (7 sur 8 : un sans ARP)
        assert await resolve_pending(s, resolver=fake) == 0  # pas de re-résolution avant 24 h
    eps = await _endpoints(c)
    e = eps[("02:bb:00:00:00:01", "10.50.0.11")]
    assert e["vendor"] == "Bravo Devices <b>Inc</b>"  # brut : échappé au rendu côté front
    assert e["hostname"] == "pc-compta.corp.local"
    assert eps[("02:bb:00:00:00:02", "10.50.0.12")]["hostname"] is None  # nom invalide rejeté
    r = await c.get("/api/v1/endpoints", params={"hostname": "COMPTA"})
    assert [x["ip"] for x in r.json()["items"]] == ["10.50.0.11"]
    assert (await c.get("/api/v1/endpoints", params={"hostname": "%"})).json()["total"] == 0  # pas de joker


async def test_rbac_and_token_scopes_on_endpoints(client, as_role, lab, sim_ip, inline_jobs, app) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    await _learn_all(c, sim_ip, ids, order=("aruba",))
    tok_read = (await c.post("/api/v1/tokens", json={"name": "r", "scopes": ["read"]})).json()["token"]  # super admin
    tok_search = (await c.post("/api/v1/tokens", json={"name": "s", "scopes": ["search"]})).json()["token"]
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    v = await as_role("lasthop-viewers")
    assert (await v.get("/api/v1/endpoints")).status_code == 200  # viewer : recherche autorisée
    assert (await v.post(f"/api/v1/devices/{ids['aruba']}/learn")).status_code == 403
    assert (await v.post("/api/v1/oui/update")).status_code == 403
    assert (await v.post("/api/v1/tokens", json={"name": "x", "scopes": ["search"]})).status_code == 403
    t = httpx.ASGITransport(app=app, client=("10.251.1.1", 1))
    async with httpx.AsyncClient(transport=t, base_url="https://lasthop.test") as b:
        assert (await b.get("/api/v1/endpoints", headers={"Authorization": f"Bearer {tok_read}"})).status_code == 403
        assert (await b.get("/api/v1/endpoints", headers={"Authorization": f"Bearer {tok_search}"})).status_code == 200
    client.cookies.clear()
    assert (await client.get("/api/v1/endpoints")).status_code == 401


async def test_retention_purges_old_data_and_audits_it(client, as_role, lab) -> None:  # type: ignore[no-untyped-def]
    from app.services.retention import purge

    c = await as_role("lasthop-admins")
    assert (await c.put("/api/v1/settings/retention_days", json={"value": 30})).status_code == 200
    async for s in dbsession.get_session():
        await s.execute(
            text("""
            INSERT INTO endpoints(id, mac, ip, first_seen, last_seen, active) VALUES
              ('00000000-0000-0000-0000-0000000000a1', '02:99:00:00:00:01', NULL, now() - interval '200 days', now() - interval '100 days', false),
              ('00000000-0000-0000-0000-0000000000a2', '02:99:00:00:00:02', NULL, now() - interval '5 days', now() - interval '1 day', true)""")
        )
        await s.execute(
            text("""
            INSERT INTO endpoint_history(endpoint_id, ts, change) VALUES
              ('00000000-0000-0000-0000-0000000000a1', now() - interval '100 days', 'appeared'),
              ('00000000-0000-0000-0000-0000000000a2', now() - interval '60 days', 'appeared'),
              ('00000000-0000-0000-0000-0000000000a2', now() - interval '1 day', 'moved')""")
        )
        await s.commit()
        totals = await purge(s)
        left = (await s.execute(text("SELECT mac::text FROM endpoints"))).scalars().all()
        hist = (await s.execute(text("SELECT change FROM endpoint_history"))).scalars().all()
        audit = (
            await s.execute(
                text(
                    "SELECT details->>'endpoints' FROM audit_log WHERE action='retention.purge' ORDER BY id DESC LIMIT 1"
                )
            )
        ).scalar_one()
    assert left == ["02:99:00:00:00:02"] and hist == ["moved"]
    assert totals["endpoints"] == 1 and audit == "1"
    async for s in dbsession.get_session():  # l'audit lui-même n'est jamais purgé
        assert (await s.execute(text("SELECT count(*) FROM audit_log WHERE action='auth.login'"))).scalar_one() >= 1


async def test_scheduler_creates_learning_jobs_per_device_interval(client, as_role, lab, sim_ip) -> None:  # type: ignore[no-untyped-def]
    from app.services.scheduler import create_due_learning_jobs

    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    assert (await c.put(f"/api/v1/devices/{ids['cisco']}", json={"poll_interval_s": 3600})).status_code == 200
    async for s in dbsession.get_session():
        assert len(await create_due_learning_jobs(s)) == 3
        assert await create_due_learning_jobs(s) == []  # déjà en file
        await s.execute(text("UPDATE jobs SET status='done'"))
        await s.execute(
            text("UPDATE devices SET last_learning_at = now() - interval '20 minutes'")
        )  # intervalle 15 min sauf Cisco (1 h)
        await s.commit()
        assert len(await create_due_learning_jobs(s)) == 2


async def test_learning_through_real_celery_worker(client, as_role, lab, sim_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    j = await run_on_sim(
        c, sim_ip, ids, "comware", "learn", wait_job
    )  # chemin réel : API -> Redis -> worker -> SNMP -> PG
    assert j["status"] == "done" and j["result"]["driver"] == "comware" and j["result"]["arp"] == 8
    assert j["result"]["fdb"] == 5


async def test_global_search_port_filter_and_csv_export(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    await _learn_all(c, sim_ip, ids)

    async def q(**p: object) -> set[tuple[str, str | None]]:
        r = await c.get("/api/v1/endpoints", params={k: str(v) for k, v in p.items()})
        assert r.status_code == 200, (p, r.text)
        return {(e["mac"], e["ip"]) for e in r.json()["items"]}

    assert len(await q(port="Gi1/0/")) == 3 and len(await q(port="ge1/0/3")) == 5  # sous-chaîne, insensible à la casse
    assert len(await q(q="10.50.0.0/24")) == 8 and len(await q(q="02cc")) == 5  # IP/CIDR et MAC partielle
    assert len(await q(q="comware")) == 5 and len(await q(q="Gi1/0/4")) == 1  # équipement, port
    assert len(await q(q="20")) >= 2  # VLAN 20
    assert await q(q="%") == set() and await q(q="a'; DROP TABLE users;--") == set()  # aucun joker / injection

    r = await c.get("/api/v1/endpoints/export.csv", params={"q": "02cc"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert 'attachment; filename="endpoints-' in r.headers["content-disposition"]
    lines = r.text.lstrip("﻿").strip().split("\r\n")
    assert lines[0] == "mac,ip,hostname,vendor,vlan,switch,port,first_seen,last_seen,active" and len(lines) == 6
    async for s in dbsession.get_session():  # l'export est audité (qui, quels filtres, combien de lignes)
        d = (
            await s.execute(
                text(
                    "SELECT details->>'rows', details->'filters'->>'q' FROM audit_log WHERE action='endpoints.export' ORDER BY id DESC LIMIT 1"
                )
            )
        ).one()
    assert tuple(d) == ("5", "02cc")
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    v = await as_role("lasthop-viewers")
    assert (await v.get("/api/v1/endpoints/export.csv")).status_code == 403  # viewer : pas d'export


def test_csv_cells_cannot_inject_formulas() -> None:
    from app.api.endpoints import csv_safe

    for evil in ("=1+1", "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", "\tx", "\rx"):
        assert csv_safe(evil).startswith("'")
    assert csv_safe("pc-compta") == "pc-compta" and csv_safe(None) == "" and csv_safe(20) == "20"


async def test_exact_port_filter_by_interface_id(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    await _learn_all(c, sim_ip, ids)
    ports = (await c.get(f"/api/v1/devices/{ids['comware']}/interfaces")).json()
    p3 = next(p for p in ports if p["name"] == "GE1/0/3")
    r = (await c.get("/api/v1/endpoints", params={"interface_id": p3["id"]})).json()
    assert r["total"] == 5 and {e["port"] for e in r["items"]} == {"GE1/0/3"}
    assert (await c.get("/api/v1/endpoints", params={"interface_id": "00000000-0000-0000-0000-000000000000"})).json()[
        "total"
    ] == 0
    assert (await c.get("/api/v1/endpoints", params={"interface_id": "not-a-uuid"})).status_code == 422
