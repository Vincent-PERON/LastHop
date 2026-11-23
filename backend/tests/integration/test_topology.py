"""Topologie L2 contre snmpsim : Aruba (accès) <-LLDP-> Comware (distribution) <-LLDP/CDP-> Cisco (cœur)."""

import asyncio
import ipaddress

from sqlalchemy import text

from app.db import session as dbsession

PORT = 1161


async def _wait(c, job_id, timeout=40.0):  # type: ignore[no-untyped-def]
    for _ in range(int(timeout / 0.25)):
        j = (await c.get(f"/api/v1/jobs/{job_id}")).json()
        if j["status"] in ("done", "failed"):
            return j
        await asyncio.sleep(0.25)
    raise AssertionError("job non terminé")


async def _create_three(c, sim_ip):  # type: ignore[no-untyped-def]
    """mgmt_ip est unique : on insère les 3 lignes avec 3 adresses du /24 autorisé ; le port 1161 de l'IP réelle sert de cible
    via une mise à jour directe de mgmt_ip pour chaque équipement avant la collecte (simulateur unique)."""
    out = {}
    base = ipaddress.ip_address(sim_ip)
    for n, (name, comm, role) in enumerate(
        (("aruba", "lab-aruba", "access"), ("comware", "lab-comware", "distribution"), ("cisco", "lab-cisco", "core"))
    ):
        cid = (
            await c.post("/api/v1/credentials", json={"name": f"v2-{name}", "version": "v2c", "community": comm})
        ).json()["id"]
        # adresses distinctes dans le /24 autorisé ; la cible réelle (sim_ip) est substituée au moment de la collecte
        ip = str(base + 10 + n) if base + 10 + n != base else str(base + 20 + n)
        r = await c.post(
            "/api/v1/devices",
            json={
                "name": name,
                "mgmt_ip": ip,
                "role": role,
                "credential_id": cid,
                "snmp_port": PORT,
                "timeout_ms": 1500,
                "retries": 0,
            },
        )
        assert r.status_code == 201, r.text
        out[name] = r.json()["id"]
    return out


async def _collect(c, sim_ip, ids, order=("aruba", "comware", "cisco")):  # type: ignore[no-untyped-def]
    for name in order:
        async for (
            s
        ) in dbsession.get_session():  # le simulateur n'écoute que sur sim_ip : on dirige l'équipement vers lui
            await s.execute(
                text("UPDATE devices SET mgmt_ip = CAST(:ip AS inet) WHERE id = CAST(:i AS uuid)"),
                {"ip": sim_ip, "i": ids[name]},
            )
            await s.commit()
        j = await _wait(c, (await c.post(f"/api/v1/devices/{ids[name]}/topology")).json()["job_id"])
        assert j["status"] == "done", j
        async for s in dbsession.get_session():  # restaure une IP distincte (contrainte d'unicité) après collecte
            base = ipaddress.ip_address(sim_ip)
            await s.execute(
                text("UPDATE devices SET mgmt_ip = CAST(:ip AS inet) WHERE id = CAST(:i AS uuid)"),
                {"ip": str(base + 10 + ("aruba", "comware", "cisco").index(name) + 100), "i": ids[name]},
            )
            await s.commit()


async def test_full_topology_roles_links_and_graph(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await _create_three(c, sim_ip)
    await _collect(c, sim_ip, ids)

    ports = {
        name: {p["name"]: p for p in (await c.get(f"/api/v1/devices/{i}/interfaces")).json()} for name, i in ids.items()
    }

    # --- Aruba : 4 ports physiques ; port 1 = uplink (voisin LLDP géré + trunk 2 VLAN tagués) ; 2 = téléphone => accès ;
    #             3 = 25 MAC (> seuil 20) => uplink ; 4 = accès (statuts self/invalid ignorés)
    a = ports["aruba"]
    assert set(a) == {"1", "2", "3", "4"}
    assert (a["1"]["role"], a["1"]["role_reason"]) == ("uplink", "lldp_neighbor") and a["1"]["is_trunk"]
    assert a["1"]["neighbors"][0]["matched_device_name"] == "comware"
    assert (a["2"]["role"], a["2"]["is_trunk"]) == ("access", False)  # VLAN voix tagué = 1 seul => pas trunk
    assert a["2"]["neighbors"][0]["sysname"] == "phone-1001" and not a["2"]["neighbors"][0]["is_network_device"]
    assert (a["3"]["role"], a["3"]["role_reason"], a["3"]["mac_count"]) == ("uplink", "mac_count", 25)
    assert (a["4"]["role"], a["4"]["mac_count"]) == ("access", 2)
    assert a["1"]["alias"] == "<script>alert(1)</script>poste-compta"  # brut : échappé au rendu côté front

    # --- Comware : interface Vlan filtrée ; port 1 et 2 voisins ; port 3 = 5 MAC (Q-BRIDGE) => accès ; port 4 = trunk
    k = ports["comware"]
    assert set(k) == {f"GE1/0/{i}" for i in range(1, 5)}
    assert k["GE1/0/1"]["neighbors"][0]["matched_device_name"] == "aruba"  # id de port "1" -> interface "1" d'Aruba
    assert k["GE1/0/2"]["neighbors"][0]["matched_device_name"] == "cisco"
    assert (k["GE1/0/3"]["role"], k["GE1/0/3"]["mac_count"]) == ("access", 5)
    assert (k["GE1/0/4"]["role"], k["GE1/0/4"]["role_reason"]) == ("uplink", "trunk")

    # --- Cisco : CDP + trunk VTP ; correspondance "GigabitEthernet1/0/2" <-> "Gi1/0/2" malgré les abréviations
    s = ports["cisco"]
    assert s["Gi1/0/2"]["neighbors"][0]["protocol"] == "cdp"
    assert (s["Gi1/0/2"]["role"], s["Gi1/0/2"]["role_reason"]) == ("uplink", "cdp_neighbor")
    assert (s["Gi1/0/1"]["role"], s["Gi1/0/1"]["role_reason"]) == ("uplink", "trunk")
    assert s["Gi1/0/3"]["role"] == "access"

    # --- Graphe : 2 liaisons (aruba-comware vue des 2 côtés = 1 seule arête ; comware-cisco LLDP+CDP = 1 seule arête)
    g = (await c.get("/api/v1/topology/graph")).json()
    assert {n["name"] for n in g["nodes"]} == {"aruba", "comware", "cisco"}
    pairs = {frozenset((e["source"], e["target"])) for e in g["edges"]}
    assert pairs == {frozenset((ids["aruba"], ids["comware"])), frozenset((ids["comware"], ids["cisco"]))}
    assert len(g["edges"]) == 2
    e = next(e for e in g["edges"] if {e["source"], e["target"]} == {ids["comware"], ids["cisco"]})
    assert set(e["protocols"]) == {"lldp", "cdp"}  # vue en LLDP côté Comware et en CDP côté Cisco = une seule arête

    # --- Un viewer voit le graphe mais n'a aucun droit d'écriture
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    v = await as_role("lasthop-viewers")
    assert (await v.get("/api/v1/topology/graph")).status_code == 200
    assert (await v.post(f"/api/v1/devices/{ids['aruba']}/topology")).status_code == 403
    assert (await v.put(f"/api/v1/interfaces/{a['1']['id']}/role", json={"role": "access"})).status_code == 403


async def test_manual_override_survives_recollection_and_is_audited(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await _create_three(c, sim_ip)
    await _collect(c, sim_ip, ids, order=("aruba",))
    ports = {p["name"]: p for p in (await c.get(f"/api/v1/devices/{ids['aruba']}/interfaces")).json()}
    p3 = ports["3"]["id"]
    assert ports["3"]["role"] == "uplink"
    assert (await c.put(f"/api/v1/interfaces/{p3}/role", json={"role": "access"})).json()["role"] == "access"
    assert (await c.put(f"/api/v1/interfaces/{p3}/role", json={"role": "root"})).status_code == 422
    await _collect(c, sim_ip, ids, order=("aruba",))  # recollecte : la surcharge doit rester
    after = {p["name"]: p for p in (await c.get(f"/api/v1/devices/{ids['aruba']}/interfaces")).json()}
    assert (after["3"]["role"], after["3"]["role_detected"], after["3"]["role_override"]) == (
        "access",
        "uplink",
        "access",
    )
    assert (await c.put(f"/api/v1/interfaces/{p3}/role", json={"role": None})).json()["role"] == "uplink"  # retour auto
    async for s in dbsession.get_session():
        n = (
            await s.execute(text("SELECT count(*) FROM audit_log WHERE action='interface.role_override'"))
        ).scalar_one()
    assert n >= 2


async def test_threshold_setting_changes_detection(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await _create_three(c, sim_ip)
    assert (await c.put("/api/v1/settings/uplink_mac_threshold", json={"value": 30})).status_code == 200
    await _collect(c, sim_ip, ids, order=("aruba",))
    ports = {p["name"]: p for p in (await c.get(f"/api/v1/devices/{ids['aruba']}/interfaces")).json()}
    assert ports["3"]["role"] == "access"  # 25 MAC <= 30
    assert (
        await c.put("/api/v1/settings/uplink_mac_threshold", json={"value": 1})
    ).status_code == 422  # borne basse = 2


async def test_unresolved_remote_is_kept_and_later_resolved(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    """Comware collecté AVANT Aruba/Cisco : ses voisins ne sont pas encore appariés ; ils le deviennent à la collecte suivante."""
    c = await as_role("lasthop-admins")
    ids = await _create_three(c, sim_ip)
    await _collect(c, sim_ip, ids, order=("comware",))
    k = {p["name"]: p for p in (await c.get(f"/api/v1/devices/{ids['comware']}/interfaces")).json()}
    assert k["GE1/0/1"]["neighbors"][0]["matched_device_id"] is None
    assert k["GE1/0/1"]["role"] == "uplink"  # voisin réseau (bridge/routeur) même non géré
    await _collect(c, sim_ip, ids, order=("aruba",))
    k = {p["name"]: p for p in (await c.get(f"/api/v1/devices/{ids['comware']}/interfaces")).json()}
    assert k["GE1/0/1"]["neighbors"][0]["matched_device_name"] == "aruba"  # corrélation rétroactive


async def test_graph_unmanaged_neighbors_and_site_filter(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await _create_three(c, sim_ip)
    await _collect(c, sim_ip, ids, order=("comware",))  # voisins aruba/cisco inconnus de l'inventaire à ce stade
    async for s in dbsession.get_session():  # les retire de la corrélation pour simuler des équipements non gérés
        await s.execute(text("DELETE FROM devices WHERE name IN ('aruba','cisco')"))
        await s.commit()
    g0 = (await c.get("/api/v1/topology/graph")).json()
    assert [n["name"] for n in g0["nodes"]] == ["comware"] and g0["edges"] == []
    g1 = (await c.get("/api/v1/topology/graph", params={"include_unmanaged": "true"})).json()
    assert {n["label"] for n in g1["nodes"] if not n["managed"]} == {"sw-access-aruba-01", "sw-core-cisco-01"}
    assert len(g1["edges"]) == 2
    site = (await c.post("/api/v1/sites", json={"name": "Autre site"})).json()["id"]
    assert (await c.get("/api/v1/topology/graph", params={"site_id": site})).json() == {"nodes": [], "edges": []}


async def test_scheduler_creates_due_jobs_once_and_beat_is_configured(client, as_role, lab, sim_ip) -> None:  # type: ignore[no-untyped-def]
    from app.services.scheduler import create_due_topology_jobs
    from app.worker.celery_app import celery_app

    c = await as_role("lasthop-admins")
    ids = await _create_three(c, sim_ip)
    async for s in dbsession.get_session():
        first = await create_due_topology_jobs(s)
        second = await create_due_topology_jobs(s)  # déjà en file : aucun doublon
    assert len(first) == 3 and second == []
    assert celery_app.conf.beat_schedule["topology-sweep"]["task"] == "lasthop.topology.schedule"
    assert set(ids.values())


async def test_topology_through_real_celery_worker(client, as_role, lab, sim_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await _create_three(c, sim_ip)
    async for s in dbsession.get_session():
        await s.execute(
            text("UPDATE devices SET mgmt_ip = CAST(:ip AS inet) WHERE id = CAST(:i AS uuid)"),
            {"ip": sim_ip, "i": ids["cisco"]},
        )
        await s.commit()
    j = await _wait(c, (await c.post(f"/api/v1/devices/{ids['cisco']}/topology")).json()["job_id"])
    assert j["status"] == "done" and j["result"]["interfaces"] == 4 and j["result"]["driver"] == "cisco_ios"


async def test_topology_errors_are_explicit(client, as_role, lab, sim_ip, inline_jobs) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    cid = (
        await c.post("/api/v1/credentials", json={"name": "bad", "version": "v2c", "community": "bad-community-1"})
    ).json()["id"]
    d = (
        await c.post(
            "/api/v1/devices",
            json={
                "name": "x",
                "mgmt_ip": sim_ip,
                "role": "access",
                "credential_id": cid,
                "snmp_port": PORT,
                "timeout_ms": 1000,
                "retries": 0,
            },
        )
    ).json()
    j = await _wait(c, (await c.post(f"/api/v1/devices/{d['id']}/topology")).json()["job_id"])
    assert (j["status"], j["error_code"]) == ("failed", "DEVICE_UNREACHABLE")
    dev = (await c.get(f"/api/v1/devices/{d['id']}")).json()
    assert dev["last_topology_status"] == "DEVICE_UNREACHABLE"
