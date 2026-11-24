"""Jeu de tests PAR ÉQUIPEMENT, sans réseau : chaque parcours de `fixtures/walks/<nom>.snmprec` est rejoué dans les vrais
collecteurs (WalkClient) et comparé à `<nom>.expect.json`. Ajouter un équipement = déposer ces deux fichiers
(voir docs/ADD_DRIVER.md). Les parcours « synthetic » sont écrits à la main ; les autres viennent de matériel réel anonymisé."""

import json
import pathlib

import pytest

from app.drivers.registry import detect_driver
from app.services.diagnose import diagnose
from app.snmp import bridge, oids
from app.snmp.client import as_text
from app.snmp.offline import WalkClient, parse_walk

WALKS = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "walks"
CASES = sorted(p.name.removesuffix(".expect.json") for p in WALKS.glob("*.expect.json"))


def load(name: str) -> tuple[WalkClient, dict]:  # type: ignore[type-arg]
    walk = parse_walk((WALKS / f"{name}.snmprec").read_text())
    return WalkClient(walk), json.loads((WALKS / f"{name}.expect.json").read_text())


def test_every_walk_has_expectations() -> None:
    walks = {p.stem for p in WALKS.glob("*.snmprec")}
    assert walks == set(CASES), f"parcours sans .expect.json (ou l'inverse) : {walks ^ set(CASES)}"


@pytest.mark.parametrize("name", CASES)
async def test_driver_and_collectors(name: str) -> None:
    client, exp = load(name)
    sys_oid = as_text((await client.get(oids.SYS_OBJECT_ID))[oids.SYS_OBJECT_ID])
    driver = detect_driver(sys_oid)()
    assert driver.name == exp["driver"]
    snap = await driver.collect_topology(client)
    assert len(snap.interfaces) == exp["interfaces"], [i.name for i in snap.interfaces]
    assert len(snap.neighbors) == exp["neighbors"]
    assert len(await bridge.collect_fdb(client)) == exp["fdb"]
    arp = await driver.collect_arp(client, 25)
    assert len(arp) == exp["arp"]
    for ip, vlan in exp.get("arp_vlans", {}).items():
        assert {a.ip: a.vlan for a in arp}[ip] == vlan


@pytest.mark.parametrize("name", CASES)
async def test_diagnostic_verdicts(name: str) -> None:
    client, exp = load(name)
    result = await diagnose(client)
    assert result["driver"] == exp["driver"]
    got = {v["feature"]: v["level"] for v in result["verdicts"]}
    for feature, level in exp["verdicts"].items():
        assert got[feature] == level, (feature, got)
    for v in result["verdicts"]:  # chaque manque s'accompagne d'une explication actionnable
        if v["level"] in ("missing", "partial"):
            assert v["advice"], v
