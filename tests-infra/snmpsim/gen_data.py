"""Génère les enregistrements .snmprec des 3 équipements de laboratoire (topologie cohérente).

Usage : python3 gen_data.py   (réécrit data/*.snmprec)
Topologie : aruba(port1) <-LLDP-> comware(port1) ; comware(port2) <-LLDP/CDP-> cisco(Gi1/0/2) ;
aruba(port2) -> téléphone (LLDP, non géré) ; aruba(port3) = 25 MAC (> seuil) ; comware(port4) = trunk 802.1Q ; cisco Gi1/0/1 = trunk VTP.
"""
import pathlib

OUT = pathlib.Path(__file__).parent / "data"
MAC = {"aruba": "001122334401", "comware": "001122334402", "cisco": "001122334403"}
H = lambda s: s.encode().hex()  # noqa: E731


def mac_oid(mac_hex: str) -> str:
    return ".".join(str(int(mac_hex[i : i + 2], 16)) for i in range(0, 12, 2))


def base(name, descr, sysoid, ent=None):
    r = {
        "1.3.6.1.2.1.1.1.0": ("4x", H(descr)),
        "1.3.6.1.2.1.1.2.0": ("6", sysoid),
        "1.3.6.1.2.1.1.3.0": ("67", "987654321"),
        "1.3.6.1.2.1.1.5.0": ("4", name),
    }
    if ent:
        r["1.3.6.1.2.1.47.1.1.1.1.13.1"] = ("4", ent)
    return r


def interfaces(r, items, bridge_map=None):
    for idx, descr, name, alias, typ, oper in items:
        r[f"1.3.6.1.2.1.2.2.1.2.{idx}"] = ("4", descr)
        r[f"1.3.6.1.2.1.2.2.1.3.{idx}"] = ("2", str(typ))
        r[f"1.3.6.1.2.1.2.2.1.8.{idx}"] = ("2", str(oper))
        r[f"1.3.6.1.2.1.31.1.1.1.1.{idx}"] = ("4", name)
        if alias:
            r[f"1.3.6.1.2.1.31.1.1.1.18.{idx}"] = ("4", alias)
    for bp, idx in (bridge_map or {}).items():
        r[f"1.3.6.1.2.1.17.1.4.1.2.{bp}"] = ("2", str(idx))


def bitmap(ports):
    n = max(ports)
    b = bytearray((n + 7) // 8)
    for p in ports:
        b[(p - 1) // 8] |= 0x80 >> ((p - 1) % 8)
    return bytes(b).hex()


def lldp_local(r, mac_hex, name, ports):
    r["1.0.8802.1.1.2.1.3.2.0"] = ("4x", mac_hex)
    r["1.0.8802.1.1.2.1.3.1.0"] = ("2", "4")
    r["1.0.8802.1.1.2.1.3.3.0"] = ("4", name)
    for num, text in ports.items():
        r[f"1.0.8802.1.1.2.1.3.7.1.2.{num}"] = ("2", "5")
        r[f"1.0.8802.1.1.2.1.3.7.1.3.{num}"] = ("4", text)


def lldp_rem(r, local, idx, chassis_hex, port_sub, port_id, sysname, caps_hex, desc=""):
    t = f"0.{local}.{idx}"
    r[f"1.0.8802.1.1.2.1.4.1.1.4.{t}"] = ("2", "4")
    r[f"1.0.8802.1.1.2.1.4.1.1.5.{t}"] = ("4x", chassis_hex)
    r[f"1.0.8802.1.1.2.1.4.1.1.6.{t}"] = ("2", str(port_sub))
    r[f"1.0.8802.1.1.2.1.4.1.1.7.{t}"] = ("4", port_id)
    if desc:
        r[f"1.0.8802.1.1.2.1.4.1.1.8.{t}"] = ("4", desc)
    r[f"1.0.8802.1.1.2.1.4.1.1.9.{t}"] = ("4", sysname)
    r[f"1.0.8802.1.1.2.1.4.1.1.12.{t}"] = ("4x", caps_hex)


def fdb_dot1d(r, entries):  # (mac_hex, bridge_port, status)
    for mac, bp, st in entries:
        r[f"1.3.6.1.2.1.17.4.3.1.2.{mac_oid(mac)}"] = ("2", str(bp))
        r[f"1.3.6.1.2.1.17.4.3.1.3.{mac_oid(mac)}"] = ("2", str(st))


def fdb_dot1q(r, vlan, entries):
    for mac, bp, st in entries:
        r[f"1.3.6.1.2.1.17.7.1.2.2.1.2.{vlan}.{mac_oid(mac)}"] = ("2", str(bp))
        r[f"1.3.6.1.2.1.17.7.1.2.2.1.3.{vlan}.{mac_oid(mac)}"] = ("2", str(st))


def arp_physical(r, if_index, ip, mac_hex, state=1):
    a = ip.split(".")
    idx = f"{if_index}.1.4.{'.'.join(a)}"
    r[f"1.3.6.1.2.1.4.35.1.4.{idx}"] = ("4x", mac_hex)
    r[f"1.3.6.1.2.1.4.35.1.6.{idx}"] = ("2", str(state))


def arp_media(r, if_index, ip, mac_hex, typ=3):
    idx = f"{if_index}.{ip}"
    r[f"1.3.6.1.2.1.4.22.1.2.{idx}"] = ("4x", mac_hex)
    r[f"1.3.6.1.2.1.4.22.1.4.{idx}"] = ("2", str(typ))


def bridge_map(r, mapping):
    for bp, idx in mapping.items():
        r[f"1.3.6.1.2.1.17.1.4.1.2.{bp}"] = ("2", str(idx))


def write(name, r, raw=False):
    def key(o):
        return tuple(int(x) for x in o.split("."))

    (OUT / (f"{name}.snmprec" if raw else f"lab-{name}.snmprec")).write_text("".join(f"{o}|{t}|{v}\n" for o, (t, v) in sorted(r.items(), key=lambda kv: key(kv[0]))))


# ---------------- Aruba (accès) ----------------
a = base("sw-access-aruba-01",
         "Aruba JL253A 2930F-48G-4SFP+ Switch, revision WC.16.11.0004, ROM WC.16.01.0007", "1.3.6.1.4.1.11.2.3.7.11.176", "JL253A")
interfaces(a, [(i, str(i), str(i), "<script>alert(1)</script>poste-compta" if i == 1 else "", 6, 1) for i in range(1, 5)],
           {i: i for i in range(1, 5)})
a["1.3.6.1.2.1.17.1.1.0"] = ("4x", MAC["aruba"])
lldp_local(a, MAC["aruba"], "sw-access-aruba-01", {i: str(i) for i in range(1, 5)})
lldp_rem(a, 1, 1, MAC["comware"], 5, "GigabitEthernet1/0/1", "sw-dist-comware-01", "28", "GigabitEthernet1/0/1")
lldp_rem(a, 2, 1, "aabbcc000001", 3, "aabbcc000001", "phone-1001", "04")
a["1.3.6.1.2.1.17.7.1.4.3.1.2.10"] = ("4x", bitmap([1, 2, 3, 4]))   # egress VLAN 10
a["1.3.6.1.2.1.17.7.1.4.3.1.4.10"] = ("4x", bitmap([2, 3, 4]))      # untagged -> port 1 est tagué
a["1.3.6.1.2.1.17.7.1.4.3.1.2.20"] = ("4x", bitmap([1, 4]))         # VLAN 20 : port 1 tagué aussi (2 VLAN tagués = trunk)
a["1.3.6.1.2.1.17.7.1.4.3.1.4.20"] = ("4x", bitmap([4]))
a["1.3.6.1.2.1.17.7.1.4.3.1.2.30"] = ("4x", bitmap([2]))            # VLAN voix tagué sur le port 2 seulement (1 VLAN tagué = pas trunk)
a["1.3.6.1.2.1.17.7.1.4.3.1.4.30"] = ("4x", bitmap([]) if False else "00")
fdb_dot1d(a, [(f"02aa00000{i:03x}"[-12:].rjust(12, "0"), 3, 3) for i in range(25)]
          + [("02bb00000001", 4, 3), ("02bb00000002", 4, 3), ("02bb00000003", 4, 4), ("02bb00000004", 4, 2)]
          + [("02ee00000001", 2, 3), ("02cc00000000", 1, 3), ("02dd00000001", 1, 3)])
for vid, vname in ((10, "USERS"), (20, "VOICE"), (30, "MGMT")):
    a[f"1.3.6.1.2.1.17.7.1.4.3.1.1.{vid}"] = ("4", vname)
for bp, pv in ((1, 1), (2, 10), (3, 10), (4, 20)):
    a[f"1.3.6.1.2.1.17.7.1.4.5.1.1.{bp}"] = ("66", str(pv))   # dot1qPvid
write("aruba", a)

# ---------------- Comware (distribution) ----------------
c = base("sw-dist-comware-01",
         "HPE Comware Platform Software, Software Version 7.1.070, Release 6635P05\nHPE 5130-24G-4SFP+ EI Switch\nCopyright (c) 2010-2021 Hewlett Packard Enterprise Development LP",
         "1.3.6.1.4.1.25506.11.1.186")
interfaces(c, [(i, f"GigabitEthernet1/0/{i}", f"GE1/0/{i}", "", 6, 1) for i in range(1, 5)] + [(100, "Vlan-interface1", "Vlan1", "", 53, 1)],
           {i: i for i in range(1, 5)})
c["1.3.6.1.2.1.17.1.1.0"] = ("4x", MAC["comware"])
lldp_local(c, MAC["comware"], "sw-dist-comware-01", {i: f"GigabitEthernet1/0/{i}" for i in range(1, 5)})
lldp_rem(c, 1, 1, MAC["aruba"], 7, "1", "sw-access-aruba-01", "28")
lldp_rem(c, 2, 1, MAC["cisco"], 5, "GigabitEthernet1/0/2", "sw-core-cisco-01", "28")
c["1.3.6.1.2.1.17.7.1.4.3.1.2.1"] = ("4x", bitmap([1, 2, 3, 4]))
c["1.3.6.1.2.1.17.7.1.4.3.1.4.1"] = ("4x", bitmap([1, 2, 3]))       # port 4 tagué dans VLAN 1 et 20 = trunk sans voisin
c["1.3.6.1.2.1.17.7.1.4.3.1.2.20"] = ("4x", bitmap([4]))
c["1.3.6.1.2.1.17.7.1.4.3.1.4.20"] = ("4x", "00")
fdb_dot1q(c, 1, [(f"02cc0000000{i}", 3, 3) for i in range(5)]
          + [("02bb00000001", 1, 3), ("02bb00000002", 1, 3), ("02ee00000001", 1, 3), ("02dd00000001", 2, 3)])
for ip, mac, st in [("10.50.0.11", "02bb00000001", 1), ("10.50.0.12", "02bb00000002", 2), ("10.50.0.21", "02ee00000001", 1),
                    ("10.50.0.30", "02cc00000000", 1), ("10.50.0.31", "02cc00000001", 1), ("10.50.0.32", "02cc00000002", 1),
                    ("10.50.0.33", "02cc00000003", 1), ("10.50.0.40", "02dd00000001", 1),
                    ("10.50.0.99", "02ff00000099", 7), ("10.50.0.98", "02ff00000098", 5), ("10.50.0.255", "ffffffffffff", 1)]:
    arp_physical(c, 100, ip, mac, st)
for vid, vname in ((1, "default"), (20, "VOICE")):
    c[f"1.3.6.1.2.1.17.7.1.4.3.1.1.{vid}"] = ("4", vname)
for bp in range(1, 5):
    c[f"1.3.6.1.2.1.17.7.1.4.5.1.1.{bp}"] = ("66", "1")
write("comware", c)

# ---------------- Cisco (cœur) : CDP uniquement + trunk VTP ----------------
k = base("sw-core-cisco-01",
         "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc3)\nTechnical Support: http://www.cisco.com/techsupport",
         "1.3.6.1.4.1.9.1.2134", "WS-C2960X-48FPD-L")
interfaces(k, [(10100 + i, f"GigabitEthernet1/0/{i}", f"Gi1/0/{i}", "", 6, 1) for i in range(1, 5)],
           {i: 10100 + i for i in range(1, 5)})
k["1.3.6.1.2.1.17.1.1.0"] = ("4x", MAC["cisco"])
k["1.3.6.1.4.1.9.9.23.1.2.1.1.6.10102.1"] = ("4", "sw-dist-comware-01.lab.local")
k["1.3.6.1.4.1.9.9.23.1.2.1.1.7.10102.1"] = ("4", "GigabitEthernet1/0/2")
k["1.3.6.1.4.1.9.9.23.1.2.1.1.8.10102.1"] = ("4", "HPE 5130")
k["1.3.6.1.4.1.9.9.23.1.2.1.1.9.10102.1"] = ("4x", "00000008")
for i in range(1, 5):
    k[f"1.3.6.1.4.1.9.9.46.1.6.1.1.14.{10100 + i}"] = ("2", "1" if i == 1 else "2")
fdb_dot1d(k, [("02dd00000001", 4, 3)])
for vlan in (10, 20, 1002):
    k[f"1.3.6.1.4.1.9.9.46.1.3.1.1.2.1.{vlan}"] = ("2", "1")
    k[f"1.3.6.1.4.1.9.9.46.1.3.1.1.3.1.{vlan}"] = ("2", "1" if vlan < 1002 else "3")
arp_media(k, 5001, "10.60.0.5", "02dd00000001")
arp_media(k, 5001, "10.60.0.6", "02dd00000009", typ=2)   # invalid : ignoré
for vid, vname in ((10, "USERS"), (20, "VOICE"), (1002, "fddi-default")):
    k[f"1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.{vid}"] = ("4", vname)
for ifx, vm in ((10102, 10), (10103, 10), (10104, 20)):
    k[f"1.3.6.1.4.1.9.9.68.1.2.2.1.2.{ifx}"] = ("2", str(vm))      # vmVlan (ports d'accès)
k["1.3.6.1.4.1.9.9.46.1.6.1.1.5.10101"] = ("2", "1")               # VLAN natif du trunk Gi1/0/1
write("cisco", k)
# Instances de bridge par VLAN : la numérotation des ports de bridge DIFFÈRE d'un VLAN à l'autre
for vlan, bmap, fdb in (
    (10, {1: 10101, 2: 10102, 3: 10103, 4: 10104},
     [("02bb00000001", 2, 3), ("02cc00000000", 2, 3), ("02dd00000002", 4, 3)]),
    (20, {5: 10103, 6: 10104},
     [("02dd00000001", 5, 3), ("02dd00000003", 6, 2)]),
):
    v = {"1.3.6.1.2.1.1.5.0": ("4", f"vlan{vlan}")}
    bridge_map(v, bmap)
    fdb_dot1d(v, fdb)
    write(f"cisco@{vlan}", v)          # v2c : community lab-cisco@<vlan>
    write(f"vlan-{vlan}", v, raw=True)  # v3 : contextName vlan-<vlan>
print("ok")
