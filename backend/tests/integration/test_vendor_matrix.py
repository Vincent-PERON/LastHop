"""Matrice constructeur × version SNMP contre snmpsim (Aruba/ProCurve, Comware, Cisco IOS ; v2c et v3 authPriv).

Pour chaque constructeur et chaque version, les mêmes enregistrements doivent donner les mêmes résultats : identité,
interfaces, voisins LLDP/CDP, trunks, FDB (BRIDGE, Q-BRIDGE, instances VLAN Cisco), ARP, recherche MAC ciblée.
Les attendus viennent de `tests-infra/snmpsim/gen_data.py` (topologie de laboratoire).
"""

import pytest

from app.drivers.registry import get_driver
from app.services.probe import identify_target
from app.snmp import oids
from app.snmp.bridge import fmt_mac
from app.snmp.client import AUTH_FAILURE, SnmpClient, SnmpCredential, SnmpError, SnmpTarget

PORT = 1161
V3_USER = "lasthop-test"
V3_AUTH = "test-auth-key-1234"
V3_PRIV = "test-priv-key-1234"

#   constructeur : (community v2c / contextName v3, driver, nom système)
VENDORS = {
    "aruba": ("lab-aruba", "aruba_os", "sw-access-aruba-01"),
    "comware": ("lab-comware", "comware", "sw-dist-comware-01"),
    "cisco": ("lab-cisco", "cisco_ios", "sw-core-cisco-01"),
}
MATRIX = [(v, ver) for v in VENDORS for ver in ("v2c", "v3")]
IDS = [f"{v}-{ver}" for v, ver in MATRIX]


def make_target(ip: str, vendor: str, version: str, **cred: str) -> SnmpTarget:
    name = VENDORS[vendor][0]
    if version == "v2c":
        credential = SnmpCredential(version="v2c", community=name)
        context = ""
    else:
        credential = SnmpCredential(
            version="v3",
            username=cred.get("username", V3_USER),
            auth_proto=cred.get("auth_proto", "sha256"),
            priv_proto=cred.get("priv_proto", "aes128"),
            auth_key=cred.get("auth_key", V3_AUTH),
            priv_key=cred.get("priv_key", V3_PRIV),
        )
        context = name
    return SnmpTarget(host=ip, port=PORT, credential=credential, context_name=context, timeout_s=2, retries=0)


def mac(hex12: str) -> str:
    return fmt_mac(bytes.fromhex(hex12))


@pytest.mark.parametrize(("vendor", "version"), MATRIX, ids=IDS)
async def test_identity(sim_ip: str, vendor: str, version: str) -> None:
    ident = await identify_target(make_target(sim_ip, vendor, version))
    assert (ident.driver, ident.sys_name) == (VENDORS[vendor][1], VENDORS[vendor][2])


@pytest.mark.parametrize(("vendor", "version"), MATRIX, ids=IDS)
async def test_topology_snapshot(sim_ip: str, vendor: str, version: str) -> None:
    drv = get_driver(VENDORS[vendor][1])()
    async with SnmpClient(make_target(sim_ip, vendor, version)) as c:
        snap = await drv.collect_topology(c, min_tagged_vlans=2)
    names = {i.name for i in snap.interfaces}
    nbrs = {(n.protocol, n.remote_sysname, n.is_network_device) for n in snap.neighbors}
    if vendor == "aruba":
        assert names == {"1", "2", "3", "4"}
        assert snap.chassis_mac == mac("001122334401")
        assert nbrs == {("lldp", "sw-dist-comware-01", True), ("lldp", "phone-1001", False)}
        # port 1 : tagué dans 2 VLAN ; port 2 : un seul VLAN tagué = pas un trunk
        assert len(snap.trunk_if_indexes) == 1
    elif vendor == "comware":
        assert names == {"GE1/0/1", "GE1/0/2", "GE1/0/3", "GE1/0/4"}  # l'interface VLAN (type 53) n'est pas un port
        assert snap.chassis_mac == mac("001122334402")
        assert nbrs == {("lldp", "sw-access-aruba-01", True), ("lldp", "sw-core-cisco-01", True)}
        assert len(snap.trunk_if_indexes) == 1  # port 4 : trunk sans voisin
    else:
        assert names == {"Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4"}
        assert snap.chassis_mac == mac("001122334403")
        assert nbrs == {("cdp", "sw-dist-comware-01.lab.local", True)}  # Cisco : CDP, aucun LLDP
        assert snap.trunk_if_indexes == {10101}  # trunk lu dans CISCO-VTP-MIB
    assert all(i.name for i in snap.interfaces) and sys_name_ok(snap.sys_name, vendor)


def sys_name_ok(name: str | None, vendor: str) -> bool:
    return name == VENDORS[vendor][2]


@pytest.mark.parametrize(("vendor", "version"), MATRIX, ids=IDS)
async def test_fdb(sim_ip: str, vendor: str, version: str) -> None:
    drv = get_driver(VENDORS[vendor][1])()
    entries = await drv.collect_fdb(make_target(sim_ip, vendor, version), 25, 4)
    macs = {e.mac for e in entries}
    assert len(macs) == len(entries) or vendor == "cisco"
    if vendor == "aruba":  # BRIDGE-MIB (sans VLAN) ; seules les entrées « learned » comptent (3 sur 7 ne le sont pas)
        assert len(entries) == 30 and {e.vlan for e in entries} == {None}
        assert mac("02bb00000003") not in macs and mac("02bb00000004") not in macs
    elif vendor == "comware":  # Q-BRIDGE : VLAN dans l'index
        assert len(entries) == 9 and {e.vlan for e in entries} == {1}
    else:  # une instance de bridge par VLAN (VTP) ; la numérotation des ports de bridge diffère entre VLAN 10 et 20
        got = {(e.mac, e.vlan, e.if_index) for e in entries}
        assert got == {
            (mac("02bb00000001"), 10, 10102),
            (mac("02cc00000000"), 10, 10102),
            (mac("02dd00000002"), 10, 10104),
            (mac("02dd00000001"), 20, 10103),
        }


@pytest.mark.parametrize(("vendor", "version"), MATRIX, ids=IDS)
async def test_arp(sim_ip: str, vendor: str, version: str) -> None:
    drv = get_driver(VENDORS[vendor][1])()
    async with SnmpClient(make_target(sim_ip, vendor, version)) as c:
        arp = await drv.collect_arp(c, 25)
    ips = {a.ip for a in arp}
    if vendor == "aruba":
        assert arp == []  # équipement L2 : pas de table ARP
    elif vendor == "comware":  # ipNetToPhysical : états invalid/incomplete et MAC de diffusion ignorés
        assert ips == {f"10.50.0.{n}" for n in (11, 12, 21, 30, 31, 32, 33, 40)}
        assert "10.50.0.255" not in ips and "10.50.0.99" not in ips
    else:  # ipNetToMedia (repli) : entrée « invalid » ignorée
        assert ips == {"10.60.0.5"}


@pytest.mark.parametrize(("vendor", "version"), MATRIX, ids=IDS)
async def test_targeted_mac_lookup_and_unknown_mac(sim_ip: str, vendor: str, version: str) -> None:
    drv = get_driver(VENDORS[vendor][1])()
    known = {"aruba": "02ee00000001", "comware": "02bb00000001", "cisco": "02dd00000001"}[vendor]
    hit = await drv.lookup_mac(make_target(sim_ip, vendor, version), bytes.fromhex(known), [], 25, 4)
    assert hit is not None and not hit.is_self
    if vendor == "cisco":  # trouvée dans l'instance VLAN 20
        assert (hit.vlan, hit.if_index) == (20, 10103)
    elif vendor == "comware":
        assert (hit.vlan, hit.bridge_port) == (1, 1)
    else:
        assert hit.bridge_port == 2
    unknown = await drv.lookup_mac(make_target(sim_ip, vendor, version), bytes.fromhex("02fe00000001"), [], 25, 4)
    assert unknown is None


@pytest.mark.parametrize("vendor", list(VENDORS))
@pytest.mark.parametrize(
    "bad",
    [
        {"auth_key": "wrong-auth-key-9999"},  # mauvaise clé d'authentification
        {"priv_key": "wrong-priv-key-9999"},  # mauvaise clé de chiffrement
        {"username": "unknown-user"},  # utilisateur inconnu
        {"auth_proto": "sha512", "priv_proto": "aes256"},  # algorithmes différents de ceux de l'agent
    ],
    ids=["auth-key", "priv-key", "user", "algos"],
)
async def test_v3_credential_errors_are_reported_as_auth_failure(sim_ip: str, vendor: str, bad: dict[str, str]) -> None:
    with pytest.raises(SnmpError) as e:
        async with SnmpClient(make_target(sim_ip, vendor, "v3", **bad)) as c:
            await c.get(oids.SYS_NAME)
    assert e.value.code == AUTH_FAILURE


@pytest.mark.parametrize("vendor", list(VENDORS))
async def test_every_vendor_answers_read_only_only(sim_ip: str, vendor: str) -> None:
    """Aucune primitive d'écriture n'existe côté client : la lecture réussit, l'API du client n'expose que get/walk."""
    async with SnmpClient(make_target(sim_ip, vendor, "v2c")) as c:
        assert (await c.get(oids.SYS_NAME))[oids.SYS_NAME]
        public = {m for m in dir(c) if not m.startswith("_")}
        assert public <= {"get", "walk", "t"}  # t = la cible ; aucune méthode d'écriture
