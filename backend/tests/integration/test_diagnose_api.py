"""Diagnostic SNMP d'un équipement (job « diagnose ») contre snmpsim : tables lisibles, verdicts, droits, audit."""

import httpx
from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import create_three, run_on_sim, wait_job


async def test_diagnose_job_reports_tables_and_verdicts(
    client: httpx.AsyncClient, as_role, lab, sim_ip, inline_jobs
) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    j = await run_on_sim(c, sim_ip, ids, "comware", "diagnose", lambda cl, jid: wait_job(cl, jid))
    assert j["status"] == "done", j
    res = j["result"]
    assert res["driver"] == "comware"
    checks = {x["key"]: x for x in res["checks"]}
    assert checks["if_physical"]["status"] == "ok" and checks["if_physical"]["rows"] == 4
    assert checks["fdb_qbridge"]["status"] == "ok" and checks["arp_media"]["status"] in ("ok", "empty")
    assert checks["cdp"]["status"] == "empty"  # pas de CDP sur Comware : explication fournie, pas d'erreur
    verdicts = {v["feature"]: v["level"] for v in res["verdicts"]}
    assert verdicts["Topologie (liaisons entre équipements)"] == "ok" and verdicts["Localisation en direct"] == "ok"
    assert "secret" not in str(res).lower() and "community" not in str(res).lower()
    async for s in dbsession.get_session():
        n = (await s.execute(text("SELECT count(*) FROM audit_log WHERE action = 'device.diagnose'"))).scalar_one()
        assert n == 1


async def test_diagnose_shows_what_is_missing_on_a_l2_access_switch(
    client: httpx.AsyncClient, as_role, lab, sim_ip, inline_jobs
) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    ids = await create_three(c, sim_ip)
    j = await run_on_sim(c, sim_ip, ids, "aruba", "diagnose", lambda cl, jid: wait_job(cl, jid))
    verdicts = {v["feature"]: v for v in j["result"]["verdicts"]}
    arp = verdicts["Apprentissage IP ↔ MAC (ARP)"]
    assert arp["level"] == "na" and "FortiGate" in arp["advice"]  # le conseil désigne le cas du routeur/pare-feu
    assert verdicts["Apprentissage MAC → port"]["level"] == "partial"  # BRIDGE-MIB sans VLAN : signalé


async def test_diagnose_is_admin_only(client: httpx.AsyncClient, as_role, lab, sim_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    did = (await create_three(c, sim_ip))["aruba"]
    for group in ("lasthop-viewers", "lasthop-operators"):
        v = await as_role(group)
        assert (await v.post(f"/api/v1/devices/{did}/diagnose")).status_code == 403
