"""Corrélation ARP + FDB -> endpoints et historique (données synthétiques, sans SNMP)."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text

from app.db import session as dbsession
from app.db.models import Device, Endpoint, EndpointHistory, Interface
from app.drivers.models import ArpInfo, FdbInfo
from app.services.learning import persist_learning
from tests.conftest import V3


@pytest.fixture
async def net(client, as_role, lab):  # type: ignore[no-untyped-def]
    """2 switchs d'accès (sw1, sw2) ayant chacun : port 1 = accès, port 2 = accès, port 9 = uplink ; + un routeur."""
    c = await as_role("lasthop-admins")
    cid = (await c.post("/api/v1/credentials", json={"name": "c", "version": "v3", **V3})).json()["id"]
    ids: dict[str, str] = {}
    import ipaddress

    base = ipaddress.ip_address(lab["ip"])
    for n, name in enumerate(("sw1", "sw2", "rtr")):
        r = await c.post(
            "/api/v1/devices",
            json={"name": name, "mgmt_ip": str(base + 30 + n), "role": "access", "credential_id": cid},
        )
        assert r.status_code == 201, r.text
        ids[name] = r.json()["id"]
    async for s in dbsession.get_session():
        for name in ("sw1", "sw2"):
            for idx, role, cnt in ((1, "access", 3), (2, "access", 1), (9, "uplink", 50)):
                s.add(
                    Interface(
                        device_id=ids[name], if_index=idx, name=f"{name}-p{idx}", role_detected=role, mac_count=cnt
                    )
                )
        await s.commit()
    return ids


async def _learn(dev: str, ids, arp=None, fdb=None):  # type: ignore[no-untyped-def]
    async for s in dbsession.get_session():
        d = (await s.execute(select(Device).where(Device.id == ids[dev]))).scalar_one()
        stats = await persist_learning(s, d, arp, fdb)
        await s.commit()
        return stats


async def _eps():  # type: ignore[no-untyped-def]
    async for s in dbsession.get_session():
        return {(str(e.mac), str(e.ip) if e.ip else None): e for e in (await s.execute(select(Endpoint))).scalars()}


async def _history(mac: str):  # type: ignore[no-untyped-def]
    async for s in dbsession.get_session():
        rows = (
            (
                await s.execute(
                    select(EndpointHistory.change)
                    .join(Endpoint, Endpoint.id == EndpointHistory.endpoint_id)
                    .where(Endpoint.mac == mac)
                    .order_by(EndpointHistory.id)
                )
            )
            .scalars()
            .all()
        )
        return list(rows)


M1, M2 = "02:00:00:00:00:01", "02:00:00:00:00:02"


async def test_join_arp_fdb_excluding_uplinks(net) -> None:  # type: ignore[no-untyped-def]
    await _learn("rtr", net, arp=[ArpInfo("10.1.1.1", M1, 1, 10), ArpInfo("10.1.1.2", M2, 1, 10)])
    assert await _eps() == {}  # ARP seul : pas de localisation => pas d'endpoint
    # M1 vu sur un port d'accès ; M2 uniquement sur l'uplink (de passage) => ignoré
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 1), FdbInfo(M2, 10, 9)])
    eps = await _eps()
    assert set(eps) == {(M1, "10.1.1.1")}
    e = eps[(M1, "10.1.1.1")]
    assert (e.device_name, e.port_name, e.vlan, e.active) == ("sw1", "sw1-p1", 10, True)
    assert await _history(M1) == ["appeared"]


async def test_mac_without_arp_is_kept_with_null_ip_then_gets_ip(net) -> None:  # type: ignore[no-untyped-def]
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 1)])
    assert set(await _eps()) == {(M1, None)}
    await _learn("rtr", net, arp=[ArpInfo("10.1.1.1", M1, 1, 10)])
    assert set(await _eps()) == {(M1, "10.1.1.1")}  # la ligne (mac, NULL) devient (mac, ip) : pas de doublon
    assert await _history(M1) == ["appeared", "ip_changed"]


async def test_move_between_ports_and_switches_and_vlan_change(net) -> None:  # type: ignore[no-untyped-def]
    await _learn("rtr", net, arp=[ArpInfo("10.1.1.1", M1, 1, 10)])
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 1)])
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 2)])  # autre port, même switch
    await _learn("sw1", net, fdb=[FdbInfo(M1, 20, 2)])  # même port, autre VLAN
    await _learn("sw1", net, fdb=[])  # a quitté sw1
    await _learn("sw2", net, fdb=[FdbInfo(M1, 20, 1)])  # réapparaît ailleurs
    e = (await _eps())[(M1, "10.1.1.1")]
    assert (e.device_name, e.port_name, e.active) == ("sw2", "sw2-p1", True)
    assert await _history(M1) == ["appeared", "moved", "vlan_changed", "disappeared", "appeared"]


async def test_history_payload_keeps_names_after_move(net) -> None:  # type: ignore[no-untyped-def]
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 1)])
    await _learn("sw2", net, fdb=[FdbInfo(M1, 10, 1)])
    await _learn("sw1", net, fdb=[])
    async for s in dbsession.get_session():
        h = (await s.execute(select(EndpointHistory).where(EndpointHistory.change == "moved"))).scalar_one()
    assert h.old["device"] == "sw1" and h.new["device"] == "sw2" and h.new["port"] == "sw2-p1"


async def test_ip_change_for_same_mac_and_arp_aging_keeps_last_ip(net) -> None:  # type: ignore[no-untyped-def]
    await _learn("rtr", net, arp=[ArpInfo("10.1.1.1", M1, 1, 10)])
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 1)])
    await _learn("rtr", net, arp=[ArpInfo("10.1.1.9", M1, 1, 10)])  # nouvelle adresse
    assert set(await _eps()) == {(M1, "10.1.1.9")}
    await _learn("rtr", net, arp=[])  # l'entrée ARP vieillit : la MAC est toujours vue => dernière IP conservée
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 1)])
    e = (await _eps())[(M1, "10.1.1.9")]
    assert e.active and await _history(M1) == ["appeared", "ip_changed"]


async def test_multiple_ips_for_one_mac_make_multiple_endpoints(net) -> None:  # type: ignore[no-untyped-def]
    await _learn("rtr", net, arp=[ArpInfo("10.1.1.1", M1, 1, 10), ArpInfo("fd00::1", M1, 1, 10)])
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 1)])
    assert set(await _eps()) == {(M1, "10.1.1.1"), (M1, "fd00::1")}


async def test_flapping_mac_prefers_most_recent_then_least_loaded_port(net) -> None:  # type: ignore[no-untyped-def]
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 1)])  # sw1-p1 (3 MAC)
    await _learn("sw2", net, fdb=[FdbInfo(M1, 10, 2)])  # sw2-p2 (1 MAC), observation plus récente
    e = (await _eps())[(M1, None)]
    assert (e.device_name, e.port_name) == ("sw2", "sw2-p2")


async def test_manual_uplink_override_removes_endpoints_from_that_port(net) -> None:  # type: ignore[no-untyped-def]
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 1)])
    async for s in dbsession.get_session():
        await s.execute(text("UPDATE interfaces SET role_override='uplink' WHERE name='sw1-p1'"))
        await s.commit()
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 1)])  # recollecte : le port est désormais un uplink forcé
    assert not (await _eps())[(M1, None)].active
    assert await _history(M1) == ["appeared", "disappeared"]


async def test_incomplete_collection_changes_nothing(net) -> None:  # type: ignore[no-untyped-def]
    await _learn("sw1", net, fdb=[FdbInfo(M1, 10, 1)])
    stats = await _learn(
        "sw2", net, arp=None, fdb=None
    )  # rien collecté (ex. équipement L3 seul sans ARP) : pas d'effet
    assert stats.get("disappeared", 0) == 0 and (await _eps())[(M1, None)].active
    _ = datetime.now(UTC)
