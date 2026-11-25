# ruff: noqa: F811, E501
"""Modification de port (VLAN, PVID, accès/trunk) par SSH contre de faux switchs : garde-fous, aperçu, alerte, exécution."""

import uuid

import asyncssh
from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import wait_job
from tests.integration.test_backups import PORT, SSH_PASSWORD, make_device, ssh_ip  # noqa: F401

SYS_OID = {
    "cisco_ios": "1.3.6.1.4.1.9.1.2134",
    "comware": "1.3.6.1.4.1.25506.11.1.186",
    "cx": "1.3.6.1.4.1.47196.4.1.1.3.1",
    "os": "1.3.6.1.4.1.11.2.3.7.11.176",
}
DRIVER = {
    "cfg_cisco": "cisco_ios",
    "cfg_comware": "comware",
    "cfg_cx": "aruba_os",
    "cfg_os": "aruba_os",
    "cfg_reject": "cisco_ios",
}
OID = {"cfg_cisco": "cisco_ios", "cfg_comware": "comware", "cfg_cx": "cx", "cfg_os": "os", "cfg_reject": "cisco_ios"}


async def sim(ip: str, persona: str, *lines: str) -> str:
    """Se connecte au faux switch comme un humain et lance des commandes (relecture du journal `show ztest-log`)."""
    async with asyncssh.connect(ip, PORT[persona], username="backup", password=SSH_PASSWORD, known_hosts=None) as c:
        r = await c.run(input="\n".join([*lines, "exit"]) + "\n")
        return str(r.stdout)


async def setup_port(
    c,
    ip,
    persona,
    *,
    name,
    port="Gi1/0/5",
    descr="GigabitEthernet1/0/5",
    mode="access",
    pvid=10,  # type: ignore[no-untyped-def]
    tagged=(),
    role="access",
    dev_role="access",
    is_trunk=False,
    neighbor=None,
    mac_count=1,
):
    did = await make_device(c, ip, persona, driver=DRIVER[persona], name=name)
    iid = str(uuid.uuid4())
    async for s in dbsession.get_session():
        await s.execute(
            text("UPDATE devices SET sys_object_id=:o, role=:r WHERE id=CAST(:d AS uuid)"),
            {"o": SYS_OID[OID[persona]], "r": dev_role, "d": did},
        )
        for vid, vname in ((1, "default"), (10, "USERS"), (20, "VOICE"), (30, "MGMT")):
            await s.execute(
                text("INSERT INTO device_vlans(device_id, vlan_id, name) VALUES (CAST(:d AS uuid), :v, :n)"),
                {"d": did, "v": vid, "n": vname},
            )
        await s.execute(
            text(
                "INSERT INTO interfaces(id, device_id, if_index, name, descr, oper_status, is_trunk, mac_count, role_detected, port_mode, pvid, tagged_vlans)"
                " VALUES (CAST(:i AS uuid), CAST(:d AS uuid), 5, :n, :ds, 1, :t, :m, :r, :pm, :pv, CAST(:tg AS jsonb))"
            ),
            {
                "i": iid,
                "d": did,
                "n": port,
                "ds": descr,
                "t": is_trunk,
                "m": mac_count,
                "r": role,
                "pm": mode,
                "pv": pvid,
                "tg": str(list(tagged)),
            },
        )
        if neighbor:
            await s.execute(
                text(
                    "INSERT INTO neighbors(id, device_id, interface_id, protocol, remote_chassis_id, remote_port_id, remote_sysname, remote_is_network_device, last_seen)"
                    " VALUES (gen_random_uuid(), CAST(:d AS uuid), CAST(:i AS uuid), 'lldp', 'aa', '1', :n, true, now())"
                ),
                {"d": did, "i": iid, "n": neighbor},
            )
        await s.commit()
    await sim(ip, persona, "clear ztest-log")
    return did, iid


async def enable(c) -> None:  # type: ignore[no-untyped-def]
    assert (await c.put("/api/v1/settings/port_config_enabled", json={"value": True})).status_code == 200


def prev(c, iid, **body):  # type: ignore[no-untyped-def]
    return c.post(f"/api/v1/interfaces/{iid}/port-config/preview", json=body)


async def test_disabled_by_default_and_admin_only(client, as_role, lab3, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    did, iid = await setup_port(c, ssh_ip, "cfg_cisco", name="cfg1")
    r = await prev(c, iid, mode="access", access_vlan=20)
    assert r.status_code == 409 and "désactivée" in r.json()["detail"]
    assert (await c.post(f"/api/v1/interfaces/{iid}/port-config/apply", json={"plan_id": "x" * 30})).status_code == 409
    await enable(c)
    for group in ("lasthop-viewers", "lasthop-operators"):
        v = await as_role(group)
        assert (await prev(v, iid, mode="access", access_vlan=20)).status_code == 403
        assert (
            await v.post(f"/api/v1/interfaces/{iid}/port-config/apply", json={"plan_id": "x" * 30})
        ).status_code == 403
        assert (await v.get(f"/api/v1/devices/{did}/vlans")).status_code == 403


async def test_only_vlans_known_to_the_device_are_accepted(client, as_role, lab3, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    did, iid = await setup_port(c, ssh_ip, "cfg_cisco", name="cfg2")
    await enable(c)
    assert [v["id"] for v in (await c.get(f"/api/v1/devices/{did}/vlans")).json()] == [1, 10, 20, 30]
    for body in (
        {"mode": "access", "access_vlan": 99},
        {"mode": "access", "access_vlan": 4095},
        {"mode": "access"},
        {"mode": "trunk", "native_vlan": 99, "allowed_vlans": [10]},
        {"mode": "trunk", "native_vlan": 1, "allowed_vlans": [10, 77]},
        {"mode": "access", "access_vlan": 10},
    ):  # 10 : déjà le cas
        r = await prev(c, iid, **body)
        assert r.status_code == 422, (body, r.text)
    assert (await prev(c, iid, mode="access", access_vlan=20, evil="x")).status_code == 422
    assert (await prev(c, iid, mode="access", access_vlan=20)).status_code == 200


async def test_preview_then_apply_cisco_and_plan_is_single_use(client, as_role, lab3, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    did, iid = await setup_port(c, ssh_ip, "cfg_cisco", name="cfg3")
    await enable(c)
    p = (await prev(c, iid, mode="access", access_vlan=20)).json()
    assert p["commands"] == [
        "configure terminal",
        "interface GigabitEthernet1/0/5",
        "switchport mode access",
        "switchport access vlan 20",
        "end",
    ]
    assert (
        p["save_commands"] == ["write memory"]
        and p["requires_ack"] is False
        and p["current"] == {"mode": "access", "pvid": 10, "tagged": []}
    )
    assert (await sim(ssh_ip, "cfg_cisco", "show ztest-log")).count(
        "switchport"
    ) == 0  # l'aperçu n'envoie RIEN à l'équipement
    r = await c.post(f"/api/v1/interfaces/{iid}/port-config/apply", json={"plan_id": p["plan_id"]})
    assert r.status_code == 202
    j = await wait_job(c, r.json()["job_id"], timeout=60)
    assert j["status"] == "done" and j["result"]["ok"] and j["result"]["saved"], j
    log = await sim(ssh_ip, "cfg_cisco", "show ztest-log")
    for line in ("interface GigabitEthernet1/0/5", "switchport mode access", "switchport access vlan 20", "SAVED"):
        assert line in log, log
    assert (
        await c.post(f"/api/v1/interfaces/{iid}/port-config/apply", json={"plan_id": p["plan_id"]})
    ).status_code == 409  # usage unique
    async for s in dbsession.get_session():
        acts = {
            a
            for (a,) in (await s.execute(text("SELECT action FROM audit_log WHERE action LIKE 'port_config.%'"))).all()
        }
        assert acts == {"port_config.preview", "port_config.apply", "port_config.result"}
        d = (await s.execute(text("SELECT details::text FROM audit_log WHERE action='port_config.apply'"))).scalar_one()
        assert "switchport access vlan 20" in d and "cfg3" in d  # commandes et cible tracées
    # sans enregistrement : rien n'est sauvegardé sur l'équipement
    await sim(ssh_ip, "cfg_cisco", "clear ztest-log")
    p2 = (await prev(c, iid, mode="access", access_vlan=30, save=False)).json()
    assert p2["save_commands"] == [] and any("PAS enregistrée" in a["text"] for a in p2["alerts"])
    j2 = await wait_job(
        c,
        (await c.post(f"/api/v1/interfaces/{iid}/port-config/apply", json={"plan_id": p2["plan_id"]})).json()["job_id"],
        timeout=60,
    )
    assert (
        j2["result"]["ok"]
        and not j2["result"]["saved"]
        and "SAVED" not in await sim(ssh_ip, "cfg_cisco", "show ztest-log")
    )


async def test_uplink_requires_typing_the_port_name(client, as_role, lab3, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    _, iid = await setup_port(
        c,
        ssh_ip,
        "cfg_cisco",
        name="cfg4",
        port="Gi1/0/1",
        descr="GigabitEthernet1/0/1",
        mode="trunk",
        pvid=1,
        tagged=(10, 30),
        role="uplink",
        is_trunk=True,
        neighbor="sw-dist-01",
        dev_role="core",
        mac_count=60,
    )
    await enable(c)
    p = (await prev(c, iid, mode="trunk", native_vlan=1, allowed_vlans=[10, 20])).json()
    assert p["requires_ack"] is True and p["ack_phrase"] == "Gi1/0/1"
    texts = " ".join(a["text"] for a in p["alerts"] if a["level"] == "danger")
    assert "UPLINK vers sw-dist-01" in texts and "cœur" in texts and "VLAN retirés du trunk : 30" in texts
    body = {"plan_id": p["plan_id"]}
    for wrong in (None, "", "Gi1/0/2", "gi1/0/1"):
        r = await c.post(f"/api/v1/interfaces/{iid}/port-config/apply", json={**body, "acknowledge": wrong})
        assert r.status_code in (422, 409), wrong
        p = (
            await prev(c, iid, mode="trunk", native_vlan=1, allowed_vlans=[10, 20])
        ).json()  # l'aperçu est consommé : on le refait
        body = {"plan_id": p["plan_id"]}
    assert "interface" not in await sim(ssh_ip, "cfg_cisco", "show ztest-log")  # rien n'a été envoyé
    r = await c.post(f"/api/v1/interfaces/{iid}/port-config/apply", json={**body, "acknowledge": "Gi1/0/1"})
    assert r.status_code == 202
    j = await wait_job(c, r.json()["job_id"], timeout=60)
    assert j["result"]["ok"], j
    assert "switchport trunk allowed vlan 1,10,20" in await sim(ssh_ip, "cfg_cisco", "show ztest-log")


async def test_plan_belongs_to_one_user_and_one_port(client, as_role, lab3, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    did, iid = await setup_port(c, ssh_ip, "cfg_cisco", name="cfg5")
    iid2 = str(uuid.uuid4())
    async for s in dbsession.get_session():  # un second port du même équipement
        await s.execute(
            text(
                "INSERT INTO interfaces(id, device_id, if_index, name, port_mode, pvid) VALUES (CAST(:i AS uuid), CAST(:d AS uuid), 6, 'Gi1/0/6', 'access', 10)"
            ),
            {"i": iid2, "d": did},
        )
        await s.commit()
    await enable(c)
    p = (await prev(c, iid, mode="access", access_vlan=20)).json()
    assert (
        await c.post(f"/api/v1/interfaces/{iid2}/port-config/apply", json={"plan_id": p["plan_id"]})
    ).status_code == 403  # autre port


async def test_state_changed_since_preview_sends_nothing(client, as_role, lab3, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    _, iid = await setup_port(c, ssh_ip, "cfg_cisco", name="cfg6", mode="trunk", pvid=1, tagged=(10,), is_trunk=True)
    await enable(c)
    p = (await prev(c, iid, mode="access", access_vlan=20)).json()
    async for s in dbsession.get_session():  # une collecte entre-temps : le port était en réalité en accès
        await s.execute(
            text("UPDATE interfaces SET port_mode='access', tagged_vlans='[]'::jsonb WHERE id=CAST(:i AS uuid)"),
            {"i": iid},
        )
        await s.commit()
    ack = p["ack_phrase"]
    r = await c.post(f"/api/v1/interfaces/{iid}/port-config/apply", json={"plan_id": p["plan_id"], "acknowledge": ack})
    j = await wait_job(c, r.json()["job_id"], timeout=60)
    assert (
        j["status"] == "failed"
        and j["result"]["error_code"] == "STATE_CHANGED"
        and "rien n'a été envoyé" in j["result"]["message"]
    )
    assert j["result"]["steps"] == [] and "interface" not in await sim(ssh_ip, "cfg_cisco", "show ztest-log")


async def test_equipment_error_stops_and_nothing_is_saved(client, as_role, lab3, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    _, iid = await setup_port(c, ssh_ip, "cfg_reject", name="cfg7", mode="trunk", pvid=5, tagged=(10,), is_trunk=True)
    await enable(c)
    p = (await prev(c, iid, mode="trunk", native_vlan=1, allowed_vlans=[10])).json()
    r = await c.post(
        f"/api/v1/interfaces/{iid}/port-config/apply", json={"plan_id": p["plan_id"], "acknowledge": p["ack_phrase"]}
    )
    j = await wait_job(c, r.json()["job_id"], timeout=60)
    res = j["result"]
    assert j["status"] == "failed" and res["error_code"] == "COMMAND_REJECTED" and res["saved"] is False
    assert "refusé une commande" in res["message"] and "PAS été enregistrée" in res["message"]
    assert any("native vlan" in s["command"] for s in res["steps"]) and "Invalid input" in res["detail"]
    log = await sim(ssh_ip, "cfg_reject", "show ztest-log")
    assert "SAVED" not in log  # aucune sauvegarde après une erreur


async def test_each_syntax_is_sent_to_its_equipment(client, as_role, lab3, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    cases = (
        (
            "cfg_comware",
            dict(port="GE1/0/5", descr="GigabitEthernet1/0/5"),
            ["port link-type access", "port access vlan 20"],
        ),
        ("cfg_cx", dict(port="1/1/5", descr="1/1/5"), ["interface 1/1/5", "vlan access 20"]),
        (
            "cfg_os",
            dict(port="5", descr="5", mode="hybrid", tagged=(30,)),
            ["no vlan 30 tagged 5", "vlan 20 untagged 5"],
        ),
    )
    await enable(c)
    for n, (persona, kw, expected) in enumerate(cases):
        _, iid = await setup_port(c, ssh_ip, persona, name=f"cfgs{n}", **kw)
        p = (await prev(c, iid, mode="access", access_vlan=20)).json()
        r = await c.post(
            f"/api/v1/interfaces/{iid}/port-config/apply",
            json={"plan_id": p["plan_id"], "acknowledge": p["ack_phrase"]},
        )
        j = await wait_job(c, r.json()["job_id"], timeout=60)
        assert j["result"]["ok"] and j["result"]["saved"], (persona, j)
        log = await sim(ssh_ip, persona, "show ztest-log")
        for line in expected:
            assert line in log, (persona, log)
        assert "SAVED" in log
        did = (await c.get("/api/v1/devices", params={})).json()[0]["id"]
        assert (await c.delete(f"/api/v1/devices/{did}")).status_code in (
            200,
            204,
        )  # libère l'adresse pour l'équipement suivant


async def test_unsupported_driver_or_missing_ssh_is_refused(client, as_role, lab3, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    c = await as_role("lasthop-admins")
    did, iid = await setup_port(c, ssh_ip, "cfg_cisco", name="cfg8")
    await enable(c)
    async for s in dbsession.get_session():
        await s.execute(text("UPDATE devices SET driver='fortinet' WHERE id=CAST(:d AS uuid)"), {"d": did})
        await s.commit()
    assert (await prev(c, iid, mode="access", access_vlan=20)).status_code == 422
    async for s in dbsession.get_session():
        await s.execute(
            text("UPDATE devices SET driver='cisco_ios', ssh_host_key=NULL WHERE id=CAST(:d AS uuid)"), {"d": did}
        )
        await s.commit()
    r = await prev(c, iid, mode="access", access_vlan=20)
    assert r.status_code == 422 and "SSH" in r.json()["detail"]
