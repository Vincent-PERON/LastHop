"""Modification de port : validation (VLAN connus), commandes par constructeur, alertes, étanchéité du code."""

import pathlib
import re

import pytest

import app
from app.services import port_config as pc

KNOWN = {1, 10, 20, 30}
ACCESS20 = pc.PortChange(mode="access", access_vlan=20)
TRUNK = pc.PortChange(mode="trunk", native_vlan=1, allowed_vlans=(10, 20))
FROM_ACCESS = pc.PortState("access", 10)
FROM_TRUNK = pc.PortState("trunk", 1, (10, 30))


def cmds(syntax: str, port: str, cur: pc.PortState, change: pc.PortChange) -> list[str]:
    return pc.build_commands(syntax, port, cur, change)


def test_vlan_must_exist_on_the_device() -> None:
    pc.validate_change(ACCESS20, KNOWN)
    pc.validate_change(TRUNK, KNOWN)
    for bad, msg in (
        (pc.PortChange("access", access_vlan=99), "n'existe pas"),
        (pc.PortChange("access", access_vlan=0), "invalide"),
        (pc.PortChange("access", access_vlan=5000), "invalide"),
        (pc.PortChange("access"), "obligatoire"),
        (pc.PortChange("access", access_vlan=10, native_vlan=1), "ni VLAN natif"),
        (pc.PortChange("trunk", native_vlan=99, allowed_vlans=(10,)), "n'existe pas"),
        (pc.PortChange("trunk", native_vlan=1, allowed_vlans=(10, 4000)), "invalide|n'existe pas"),
        (pc.PortChange("trunk", native_vlan=1, access_vlan=10), "pas de VLAN d'accès"),
        (pc.PortChange("hybride", access_vlan=10), "Mode inconnu"),
    ):
        with pytest.raises(pc.PortConfigError, match=msg):
            pc.validate_change(bad, KNOWN)
    with pytest.raises(pc.PortConfigError, match="pas connus"):  # aucune collecte : on ne devine pas
        pc.validate_change(ACCESS20, set())


def test_cisco_commands() -> None:
    assert cmds("cisco_ios", "GigabitEthernet1/0/5", FROM_ACCESS, ACCESS20) == [
        "interface GigabitEthernet1/0/5",
        "switchport mode access",
        "switchport access vlan 20",
    ]
    assert cmds("cisco_ios", "Gi1/0/5", FROM_TRUNK, ACCESS20)[:3] == [
        "interface Gi1/0/5",
        "no switchport trunk native vlan",
        "no switchport trunk allowed vlan",
    ]
    assert cmds("cisco_ios", "Gi1/0/5", FROM_ACCESS, TRUNK) == [
        "interface Gi1/0/5",
        "switchport mode trunk",
        "switchport trunk native vlan 1",
        "switchport trunk allowed vlan 1,10,20",
    ]


def test_comware_commands() -> None:
    assert cmds("comware", "GigabitEthernet1/0/5", FROM_ACCESS, ACCESS20) == [
        "interface GigabitEthernet1/0/5",
        "port link-type access",
        "port access vlan 20",
    ]
    assert cmds("comware", "GigabitEthernet1/0/5", FROM_ACCESS, TRUNK) == [
        "interface GigabitEthernet1/0/5",
        "port link-type trunk",
        "undo port trunk permit vlan all",
        "port trunk permit vlan 1 10 20",
        "port trunk pvid vlan 1",
    ]


def test_aruba_cx_commands() -> None:
    assert cmds("aruba_cx", "1/1/5", FROM_ACCESS, ACCESS20) == ["interface 1/1/5", "vlan access 20"]
    assert cmds("aruba_cx", "1/1/5", FROM_TRUNK, ACCESS20) == [
        "interface 1/1/5",
        "no vlan trunk native",
        "no vlan trunk allowed",
        "vlan access 20",
    ]
    assert cmds("aruba_cx", "1/1/5", FROM_TRUNK, TRUNK) == [
        "interface 1/1/5",
        "no vlan trunk allowed",
        "vlan trunk native 1",
        "vlan trunk allowed 1,10,20",
    ]


def test_arubaos_switch_commands_are_vlan_centric_and_need_the_current_state() -> None:
    # accès : on retire les VLAN étiquetés actuels, puis VLAN non étiqueté
    assert cmds("aruba_os", "5", pc.PortState("hybrid", 10, (20,)), ACCESS20) == [
        "no vlan 20 tagged 5",
        "vlan 20 untagged 5",
    ]
    # trunk : retire les VLAN étiquetés en trop, ajoute les manquants, fixe le VLAN natif
    assert cmds("aruba_os", "5", pc.PortState("trunk", 1, (10, 30)), TRUNK) == [
        "no vlan 30 tagged 5",
        "vlan 20 tagged 5",
        "vlan 1 untagged 5",
    ]
    with pytest.raises(pc.PortConfigError, match="inconnu"):
        cmds("aruba_os", "5", pc.PortState(None, None), ACCESS20)
    with pytest.raises(pc.PortConfigError, match="pas prise en charge"):
        cmds("generic", "5", FROM_ACCESS, ACCESS20)


def test_variant_detection_and_plan_digest() -> None:
    assert pc.variant("aruba_os", "1.3.6.1.4.1.47196.4.1.1.3.1") == "aruba_cx"
    assert pc.variant("aruba_os", "1.3.6.1.4.1.11.2.3.7.11.176") == "aruba_os"
    assert (
        pc.variant("cisco_ios", None) == "cisco_ios"
        and pc.variant("generic", None) is None
        and pc.variant("fortinet", None) is None
    )
    a = pc.make_plan("cisco_ios", "Gi1/0/5", FROM_ACCESS, ACCESS20, alerts=[])
    b = pc.make_plan("cisco_ios", "Gi1/0/5", FROM_TRUNK, ACCESS20, alerts=[])
    assert a.commands[0] == "configure terminal" and a.commands[-1] == "end" and a.save_commands == ["write memory"]
    assert a.digest() != b.digest()  # état du port différent => commandes différentes => empreinte différente
    assert (
        pc.make_plan(
            "comware", "X", FROM_ACCESS, pc.PortChange("access", access_vlan=20, save=False), alerts=[]
        ).save_commands
        == []
    )


def alerts(**over) -> list[pc.Alert]:  # type: ignore[no-untyped-def]
    base = dict(
        port_name="Gi1/0/5",
        current=FROM_ACCESS,
        change=ACCESS20,
        role="access",
        is_trunk=False,
        neighbor_names=[],
        mac_count=1,
        mac_threshold=20,
        device_role="access",
    )
    base.update(over)
    return pc.assess(**base)  # type: ignore[arg-type]


def levels(a: list[pc.Alert]) -> set[str]:
    return {x.level for x in a}


def test_a_simple_access_port_needs_no_special_confirmation() -> None:
    a = alerts()
    assert (
        "danger" not in levels(a) and not pc.make_plan("cisco_ios", "p", FROM_ACCESS, ACCESS20, alerts=a).requires_ack
    )
    assert any("poste(s) actuellement connecté" in x.text for x in a)


def test_dangerous_situations_require_explicit_confirmation() -> None:
    cases = {
        "uplink": alerts(role="uplink"),
        "voisin réseau": alerts(neighbor_names=["sw-dist-01"]),
        "trunk": alerts(is_trunk=True, current=FROM_TRUNK, change=TRUNK),
        "cœur": alerts(device_role="core"),
        "distribution": alerts(device_role="distribution"),
        "beaucoup de MAC": alerts(mac_count=45),
        "trunk vers accès": alerts(current=FROM_TRUNK),
        "natif modifié": alerts(current=pc.PortState("trunk", 5, (10,)), change=TRUNK),
        "VLAN retirés": alerts(current=pc.PortState("trunk", 1, (10, 30)), change=TRUNK),
    }
    for name, a in cases.items():
        assert "danger" in levels(a), name
        assert pc.make_plan("cisco_ios", "p", FROM_ACCESS, ACCESS20, alerts=a).requires_ack, name
    up = alerts(role="uplink", neighbor_names=["sw-core-01"])
    assert "UPLINK vers sw-core-01" in up[0].text and "coupé" in up[0].text.replace("couper", "coupé")


def test_unsaved_change_is_flagged() -> None:
    a = alerts(change=pc.PortChange("access", access_vlan=20, save=False))
    assert any("PAS enregistrée" in x.text for x in a)


def test_same_state_is_detected() -> None:
    assert pc.same_as_current(pc.PortState("access", 20), ACCESS20)
    assert not pc.same_as_current(FROM_ACCESS, ACCESS20)
    assert pc.same_as_current(pc.PortState("trunk", 1, (10, 20)), TRUNK)
    assert not pc.same_as_current(pc.PortState("trunk", 1, ()), TRUNK)  # VLAN autorisés inconnus : on laisse faire


def test_configuration_commands_exist_only_in_the_port_config_modules() -> None:
    """Étanchéité : seuls services/port_config*.py contiennent des commandes de configuration ; le reste de l'application
    (sauvegardes, SNMP…) reste strictement en lecture."""
    root = pathlib.Path(app.__file__).parent
    marker = re.compile(
        r"switchport (mode|access|trunk)|port link-type|system-view|configure terminal|undo port|vlan trunk|\bwrite memory\b|save force"
    )
    allowed = {"port_config.py", "port_config_job.py"}
    offenders = [
        str(p.relative_to(root))
        for p in root.rglob("*.py")
        if p.name not in allowed and marker.search(p.read_text(encoding="utf-8"))
    ]
    # (backup_messages.py cite « write memory » dans un conseil affiché à l'utilisateur : texte, pas une commande envoyée)
    assert set(offenders) <= {"services/backup_messages.py", "services/ssh_backup.py"}, offenders
    for name in ("backup_messages.py", "ssh_backup.py"):
        text = (root / "services" / name).read_text(encoding="utf-8")
        assert not re.search(r'(run|run_any)\(\s*f?["\'](configure|system-view|write memory|save)', text)
