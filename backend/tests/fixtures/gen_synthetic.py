"""Génère les parcours SYNTHÉTIQUES (écrits à la main d'après la documentation des constructeurs, pas de matériel réel) :
FortiGate et équipement générique minimaliste. Les parcours réels anonymisés (`walk-anonymize`) vont dans walks/ avec leur
fichier .expect.json (voir docs/ADD_DRIVER.md). Usage : python3 gen_synthetic.py"""

import pathlib

OUT = pathlib.Path(__file__).parent / "walks"
H = lambda s: s.encode().hex()  # noqa: E731


def oidkey(o: str) -> tuple[int, ...]:
    return tuple(int(x) for x in o.split("."))


def write(name: str, rows: dict[str, tuple[str, str]]) -> None:
    (OUT / f"{name}.snmprec").write_text(
        "".join(f"{o}|{t}|{v}\n" for o, (t, v) in sorted(rows.items(), key=lambda kv: oidkey(kv[0])))
    )


def mac_oid(mac: str) -> str:
    return ".".join(str(int(mac[i : i + 2], 16)) for i in range(0, 12, 2))


def base(r: dict, sysoid: str, name: str, descr: str) -> None:
    r["1.3.6.1.2.1.1.1.0"] = ("4", descr)
    r["1.3.6.1.2.1.1.2.0"] = ("6", sysoid)
    r["1.3.6.1.2.1.1.3.0"] = ("67", "123456")
    r["1.3.6.1.2.1.1.5.0"] = ("4", name)


# --- FortiGate : routeur/pare-feu inter-VLAN. Ports physiques + sous-interfaces VLAN (type 135), ARP « ipNetToMedia »,
#     pas de BRIDGE-MIB ni de LLDP exposés par SNMP.
f: dict[str, tuple[str, str]] = {}
base(f, "1.3.6.1.4.1.12356.101.1.1000", "fw-core", "FortiGate-100F")
for idx, name in ((1, "port1"), (2, "port2"), (3, "port3"), (4, "wan1")):
    f[f"1.3.6.1.2.1.2.2.1.2.{idx}"] = ("4", name)
    f[f"1.3.6.1.2.1.2.2.1.3.{idx}"] = ("2", "6")
    f[f"1.3.6.1.2.1.2.2.1.8.{idx}"] = ("2", "1")
    f[f"1.3.6.1.2.1.31.1.1.1.1.{idx}"] = ("4", name)
for idx, name in ((20, "vlan10_users"), (21, "vlan20_voice")):
    f[f"1.3.6.1.2.1.2.2.1.2.{idx}"] = ("4", name)
    f[f"1.3.6.1.2.1.2.2.1.3.{idx}"] = ("2", "135")  # l2vlan : interface logique, pas un port
    f[f"1.3.6.1.2.1.2.2.1.8.{idx}"] = ("2", "1")
    f[f"1.3.6.1.2.1.31.1.1.1.1.{idx}"] = ("4", name)
for ifidx, ip, mac, typ in (
    (20, "10.10.0.21", "001a2b000021", 3),
    (20, "10.10.0.22", "001a2b000022", 3),
    (21, "10.20.0.31", "001a2b000031", 3),
    (20, "10.10.0.99", "001a2b000099", 2),  # « invalid » : ignorée
):
    f[f"1.3.6.1.2.1.4.22.1.2.{ifidx}.{ip}"] = ("4x", mac)
    f[f"1.3.6.1.2.1.4.22.1.4.{ifidx}.{ip}"] = ("2", str(typ))
write("fortigate-synthetic", f)

# --- Équipement générique minimaliste : types d'interface anciens (117/62), noms seulement (pas d'ifDescr), pas de table
#     des ports de bridge, FDB BRIDGE-MIB SANS colonne de statut, voisins CDP uniquement.
g: dict[str, tuple[str, str]] = {}
base(g, "1.3.6.1.4.1.99999.1.1", "sw-minimal", "Switch minimal 8 ports")
for idx, typ in ((1, 117), (2, 117), (3, 62), (4, 62)):
    g[f"1.3.6.1.2.1.2.2.1.3.{idx}"] = ("2", str(typ))
    g[f"1.3.6.1.2.1.2.2.1.8.{idx}"] = ("2", "1")
    g[f"1.3.6.1.2.1.31.1.1.1.1.{idx}"] = ("4", f"ge-0/0/{idx - 1}")
for mac, port in (("02aa00000001", 1), ("02aa00000002", 3), ("02aa00000003", 3)):
    g[f"1.3.6.1.2.1.17.4.3.1.2.{mac_oid(mac)}"] = ("2", str(port))
g["1.3.6.1.4.1.9.9.23.1.2.1.1.6.2.1"] = ("4", "sw-upstream")
g["1.3.6.1.4.1.9.9.23.1.2.1.1.7.2.1"] = ("4", "Gi0/1")
g["1.3.6.1.4.1.9.9.23.1.2.1.1.9.2.1"] = ("4x", "00000008")
write("generic-minimal", g)
print("ok")
