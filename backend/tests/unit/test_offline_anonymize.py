import pathlib
import re

from app.snmp.offline import Anonymizer, WalkClient, anonymize, parse_walk, to_snmprec

WALKS = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "walks"

NETSNMP = """\
.1.3.6.1.2.1.1.1.0 = Hex-STRING: 46 6F 72 74 69 47 61 74 65 2D 31 30 30 46
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.12356.101.1.1000
.1.3.6.1.2.1.1.3.0 = Timeticks: (123456) 0:20:34.56
.1.3.6.1.2.1.1.5.0 = STRING: "fw-paris-01"
.1.3.6.1.2.1.1.6.0 = STRING: "Salle serveur, rue Secrète 12"
.1.3.6.1.2.1.2.2.1.3.1 = INTEGER: ethernetCsmacd(6)
.1.3.6.1.2.1.2.2.1.2.1 = STRING: port1
.1.3.6.1.2.1.31.1.1.1.18.1 = STRING: Lien vers la compta (Mme Durand)
.1.3.6.1.2.1.4.22.1.2.1.192.168.1.50 = Hex-STRING: 00 1A 2B 3C 4D 5E
.1.3.6.1.2.1.4.22.1.4.1.192.168.1.50 = INTEGER: dynamic(3)
.1.3.6.1.2.1.17.4.3.1.2.0.26.43.60.77.94 = INTEGER: 1
.1.3.6.1.2.1.17.4.3.1.3.0.26.43.60.77.94 = INTEGER: learned(3)
.1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.26.43.60.77.94 = INTEGER: 1
.1.3.6.1.2.1.4.35.1.4.1.1.4.192.168.1.60 = Hex-STRING: 00 1A 2B 3C 4D 5F
.1.0.8802.1.1.2.1.4.1.1.9.0.1.1 = STRING: sw-voisin-lyon
.1.0.8802.1.1.2.1.4.1.1.5.0.1.1 = Hex-STRING: 00 1A 2B 3C 4D 60
"""


def test_parse_netsnmp_output() -> None:
    w = parse_walk(NETSNMP)
    assert w["1.3.6.1.2.1.1.1.0"] == ("4x", "466f727469476174652d31303046")
    assert w["1.3.6.1.2.1.1.2.0"] == ("6", "1.3.6.1.4.1.12356.101.1.1000")
    assert w["1.3.6.1.2.1.1.3.0"] == ("67", "123456")
    assert w["1.3.6.1.2.1.2.2.1.3.1"] == ("2", "6")
    assert w["1.3.6.1.2.1.4.22.1.2.1.192.168.1.50"] == ("4x", "001a2b3c4d5e")
    assert w["1.3.6.1.2.1.1.5.0"] == ("4", "fw-paris-01")


def test_snmprec_round_trip_and_walk_client() -> None:
    w = parse_walk(NETSNMP)
    again = parse_walk(to_snmprec(w))
    assert again == w
    import asyncio

    async def go() -> None:
        c = WalkClient(w)
        rows = [(o, v) async for o, v in c.walk("1.3.6.1.2.1.2.2.1.3")]
        assert rows == [("1.3.6.1.2.1.2.2.1.3.1", 6)]
        got = await c.get("1.3.6.1.2.1.1.5.0", "1.3.6.1.9.9.9")
        assert got == {"1.3.6.1.2.1.1.5.0": b"fw-paris-01", "1.3.6.1.9.9.9": None}

    asyncio.run(go())


def test_anonymization_replaces_identities_consistently_and_keeps_structure() -> None:
    anon, rep = anonymize(parse_walk(NETSNMP), salt=b"x" * 16)
    text = to_snmprec(anon)
    for secret in ("192.168.1", "fw-paris", "Durand", "Secrète", "sw-voisin-lyon", "001a2b3c4d5e", "0.26.43.60.77.94"):
        assert secret not in text, secret
    # le préfixe constructeur (OUI) des MAC est conservé, pas la fin
    assert re.search(r"\|4x\|001a2b[0-9a-f]{6}\n", text)
    # cohérence : la même MAC / la même IP donne la même valeur partout (index OID ET valeur)
    mac_in_value = next(v for o, (t, v) in anon.items() if o.startswith("1.3.6.1.2.1.4.22.1.2."))
    assert mac_in_value != "001a2b3c4d5e" and len(mac_in_value) == 12
    fdb_oids = [o for o in anon if o.startswith("1.3.6.1.2.1.17.4.3.1.2.")]
    q_oids = [o for o in anon if o.startswith("1.3.6.1.2.1.17.7.1.2.2.1.2.")]
    assert fdb_oids[0].split(".")[-6:] == q_oids[0].split(".")[-6:]  # même MAC dans BRIDGE et Q-BRIDGE
    assert bytes(int(p) for p in fdb_oids[0].split(".")[-6:]).hex()[:6] == "001a2b"
    ip_index = next(o for o in anon if o.startswith("1.3.6.1.2.1.4.22.1.4."))
    assert ip_index.split(".")[11:] and ip_index.split(".")[11] == "10"  # 10.x.y.z
    assert rep.macs >= 2 and rep.ips >= 1 and rep.strings >= 3
    # structure conservée : les collecteurs fonctionnent toujours sur le résultat
    import asyncio

    from app.services.diagnose import diagnose

    result = asyncio.run(diagnose(WalkClient(anon)))
    assert result["driver"] == "fortinet"
    assert {c["key"]: c["status"] for c in result["checks"]}["arp_media"] == "ok"


def test_anonymization_is_not_reversible_across_runs_and_deterministic_within_one() -> None:
    a1, a2 = Anonymizer(b"a" * 16), Anonymizer(b"b" * 16)
    mac = bytes.fromhex("001a2b3c4d5e")
    assert a1.mac(mac) == a1.mac(mac) and a1.mac(mac) != a2.mac(mac)
    assert a1.ip("192.168.1.50") == a1.ip("192.168.1.50") != a2.ip("192.168.1.50")
    # adresses spéciales inchangées
    assert a1.ip("0.0.0.0") == "0.0.0.0"  # noqa: S104
    assert a1.ip("224.0.0.1") == "224.0.0.1"


def test_existing_fixtures_survive_anonymization() -> None:
    """Un parcours réel anonymisé doit rester exploitable : mêmes résultats de collecte avant/après."""
    import asyncio

    from app.drivers.registry import detect_driver
    from app.snmp import bridge

    async def counts(walk) -> tuple[int, int, int]:  # type: ignore[no-untyped-def]
        c = WalkClient(walk)
        drv = detect_driver("1.3.6.1.4.1.25506.11.1.186")()
        snap = await drv.collect_topology(c)
        return len(snap.interfaces), len(snap.neighbors), len(await bridge.collect_fdb(c))

    walk = parse_walk((WALKS / "lab-comware.snmprec").read_text())
    anon, _ = anonymize(walk)
    assert asyncio.run(counts(anon)) == asyncio.run(counts(walk))
