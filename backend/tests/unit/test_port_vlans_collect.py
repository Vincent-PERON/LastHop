"""Lecture (SNMP, hors ligne) des VLAN connus, du PVID et du mode des ports sur les parcours de référence."""

import pathlib

from app.drivers.registry import get_driver
from app.snmp.offline import WalkClient, parse_walk

WALKS = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "walks"


async def snapshot(name: str, driver: str):  # type: ignore[no-untyped-def]
    client = WalkClient(parse_walk((WALKS / f"lab-{name}.snmprec").read_text()))
    return await get_driver(driver)().collect_topology(client)


async def test_arubaos_vlans_pvid_and_modes() -> None:
    snap = await snapshot("aruba", "aruba_os")
    assert snap.vlans == {10: "USERS", 20: "VOICE", 30: "MGMT"}
    pv = snap.port_vlans
    by_name = {i.name: i.if_index for i in snap.interfaces}
    assert pv[by_name["1"]].mode == "trunk" and pv[by_name["1"]].tagged == (10, 20)
    assert (
        pv[by_name["2"]].mode == "hybrid" and pv[by_name["2"]].tagged == (30,) and pv[by_name["2"]].pvid == 10
    )  # VLAN voix tagué
    assert pv[by_name["3"]].mode == "access" and pv[by_name["3"]].pvid == 10 and pv[by_name["3"]].tagged == ()


async def test_comware_vlans() -> None:
    snap = await snapshot("comware", "comware")
    assert snap.vlans == {1: "default", 20: "VOICE"}
    assert all(v.pvid == 1 for v in snap.port_vlans.values())


async def test_cisco_vlans_from_vtp_and_ports_from_vmvlan() -> None:
    snap = await snapshot("cisco", "cisco_ios")
    assert snap.vlans == {10: "USERS", 20: "VOICE"}  # VLAN 1002 (FDDI) exclu
    pv = snap.port_vlans
    assert pv[10101].mode == "trunk" and pv[10101].pvid == 1  # VLAN natif du trunk
    assert (pv[10102].mode, pv[10102].pvid) == ("access", 10) and (pv[10104].mode, pv[10104].pvid) == ("access", 20)


async def test_generic_device_without_vlan_tables_reports_nothing_instead_of_guessing() -> None:
    snap = await snapshot("aruba", "generic")  # mêmes tables Q-BRIDGE : le pilote générique les lit aussi
    assert snap.vlans and snap.port_vlans
    client = WalkClient(parse_walk((WALKS / "generic-minimal.snmprec").read_text()))
    g = await get_driver("generic")().collect_topology(client)
    assert g.vlans == {} and g.port_vlans == {}  # pas de Q-BRIDGE : jamais de VLAN inventés
