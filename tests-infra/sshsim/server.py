"""Faux équipements réseau en SSH (CLI interactive avec invite, écho, pagination), une personnalité par port.

Compte de TEST : utilisateur « backup » / mot de passe « test-ssh-password-1234 » ; l'utilisateur « keyuser » accepte
n'importe quelle clé publique (uniquement pour les tests de profil à clé).
"""
import asyncio
import sys
from dataclasses import dataclass, field

import asyncssh

PASSWORD = "test-ssh-password-1234"

CISCO_RUNNING = """Building configuration...

Current configuration : 1432 bytes
!
! Last configuration change at 10:00:00 UTC Sun Nov 22 2026
!
version 15.2
hostname sw-core
!
enable secret 5 $1$abcd$XyZ123SecretHashValue
username admin privilege 15 secret 9 $9$VerySecretScryptHash
snmp-server community TopSecretCommunity RO
snmp-server user lasthop-ro LASTHOP-RO v3 auth sha256 MyAuthKey12345 priv aes 128 MyPrivKey12345
!
interface GigabitEthernet1/0/1
 description uplink-vers-distribution
 switchport mode trunk
!
interface GigabitEthernet1/0/2
 description poste-compta
 switchport access vlan 10
 spanning-tree portfast
!
line vty 0 15
 transport input ssh
!
end"""
CISCO_STARTUP = CISCO_RUNNING.replace("Building configuration...\n\nCurrent configuration : 1432 bytes\n", "Using 1432 out of 262144 bytes\n").replace(
    "! Last configuration change at 10:00:00 UTC Sun Nov 22 2026", "! NVRAM config last updated at 09:00:00 UTC Sun Nov 22 2026")
CISCO_RUNNING_V2 = CISCO_RUNNING.replace(" description poste-compta", " description poste-compta-v2").replace("!\nline vty", "interface Vlan99\n ip address 10.99.0.1 255.255.255.0\n!\nline vty")
COMWARE = """#
 version 7.1.070, Release 6635P05
#
 sysname sw-dist
#
local-user admin class manage
 password hash $h$6$ComwareSecretHashValue==
 service-type ssh
 authorization-attribute user-role network-admin
#
snmp-agent community read cipher $c$3$SecretCommunityCipher==
#
interface GigabitEthernet1/0/1
 port link-mode bridge
 description uplink-aruba
#
return"""
ARUBA = """; J9772A Configuration Editor; Created on release #YA.16.10
hostname "sw-acc"
snmp-server community "ArubaSecretCommunity" Unrestricted
radius-server key "RadiusSharedSecret99"
password manager user-name "admin" sha1 "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
vlan 1
   name "DEFAULT_VLAN"
   untagged 1-24
   exit"""


@dataclass
class Persona:
    prompt: str
    running: str
    startup: str
    pager_off: str | None = "terminal length 0"  # commande acceptée pour désactiver la pagination (None = non supportée)
    startup_cmd: str = "show startup-config"
    running_cmd: str = "show running-config"
    rejects_show: bool = False
    silent: bool = False
    delay: float = 0.0
    empty: bool = False
    legacy_only: bool = False
    alt_key: bool = False
    page_size: int = 18
    paging: bool = False
    config: str | None = None  # cisco | comware | cx | os : accepte le mode configuration (tests de modification de port)
    reject: tuple = ()  # fragments de commandes refusés en configuration
    state: dict = field(default_factory=dict)


PERSONAS = {
    2201: Persona("sw-core#", CISCO_RUNNING, CISCO_STARTUP),
    2202: Persona("<sw-dist>", COMWARE, COMWARE, pager_off="screen-length disable",
                  running_cmd="display current-configuration", startup_cmd="display saved-configuration"),
    # ProCurve : `show startup-config` n'existe pas (→ repli sur `show config`)
    2203: Persona("sw-acc#", ARUBA, ARUBA, pager_off="no page", startup_cmd="show config"),
    2204: Persona("sw-core#", CISCO_RUNNING_V2, CISCO_STARTUP),  # running ≠ startup
    2205: Persona("sw-core#", CISCO_RUNNING_V2, CISCO_RUNNING_V2.replace("! Last configuration change at 10:00:00 UTC Sun Nov 22 2026", "")),
    2206: Persona("sw-core#", CISCO_RUNNING * 3, CISCO_STARTUP * 3, pager_off=None, paging=True),  # pagination impossible à couper
    2207: Persona("sw-core>", CISCO_RUNNING, CISCO_STARTUP),  # mode utilisateur
    2208: Persona("sw-core#", CISCO_RUNNING, CISCO_STARTUP, rejects_show=True),
    2209: Persona("sw-core#", "!", "!", empty=True),
    2210: Persona("sw-core#", CISCO_RUNNING, CISCO_STARTUP, silent=True),  # aucune invite
    2211: Persona("sw-core#", CISCO_RUNNING, CISCO_STARTUP, legacy_only=True),
    2212: Persona("sw-core#", CISCO_RUNNING, CISCO_STARTUP, startup_cmd="show nvram"),  # startup refusé, running OK
    2215: Persona("sw-core#", CISCO_RUNNING, CISCO_STARTUP, alt_key=True),  # autre clé d'hôte
    2216: Persona("sw-core#", CISCO_RUNNING, CISCO_STARTUP, delay=6.0),  # très lent
    # --- Modification de port : un faux équipement par syntaxe ; `show ztest-log` rend toutes les commandes de configuration reçues
    2217: Persona("sw-cfg#", CISCO_RUNNING, CISCO_STARTUP, config="cisco"),
    2218: Persona("<sw-cfg>", COMWARE, COMWARE, pager_off="screen-length disable", config="comware",
                  running_cmd="display current-configuration", startup_cmd="display saved-configuration"),
    2219: Persona("sw-cx#", ARUBA, ARUBA, pager_off="no page", config="cx"),
    2220: Persona("sw-os#", ARUBA, ARUBA, pager_off="no page", config="os", startup_cmd="show config"),
    2221: Persona("sw-cfg#", CISCO_RUNNING, CISCO_STARTUP, config="cisco", reject=("native vlan",)),  # refuse une commande
}


def config_prompt(kind: str, base: str, mode: str, iface: str) -> str:
    name = base.strip("#<>")
    if kind == "comware":
        return {"exec": f"<{name}>", "config": f"[{name}]", "if": f"[{name}-{iface}]"}[mode]
    return {"exec": f"{name}#", "config": f"{name}(config)#", "if": f"{name}(config-if)#"}[mode]


def config_command(p: "Persona", cmd: str, st: dict) -> str | None:
    """Traite une commande de configuration ; retourne le texte de sortie ou None si la commande n'est pas de configuration."""
    k, mode = p.config, st["mode"]
    enter = {"cisco": "configure terminal", "comware": "system-view", "cx": "configure terminal", "os": "configure"}[k]
    leave = {"cisco": "end", "comware": "return", "cx": "end", "os": "end"}[k]
    save = {"cisco": "write memory", "comware": "save force", "cx": "write memory", "os": "write memory"}[k]
    if cmd == "clear ztest-log":
        st["log"].clear()
        st["mode"] = "exec"
        return "cleared"
    if cmd == "show ztest-log":
        return "\r\n".join(st["log"]) or "(vide)"
    if mode == "exec":
        if cmd == enter:
            st["mode"] = "config"
            return ""
        if cmd == save:
            st["log"].append("SAVED")
            return {"cisco": "Building configuration...\r\n[OK]", "comware": "Validating file. Please wait...\r\nSaved the current configuration to mainboard device successfully.",
                    "cx": "Copying configuration: [Success]", "os": ""}[k]
        return None
    if cmd == leave:
        st["mode"] = "exec"
        return ""
    if any(frag in cmd for frag in p.reject):
        return "% Invalid input detected at '^' marker."
    if cmd.startswith("interface "):
        st["mode"], st["iface"] = "if", cmd.split(" ", 1)[1]
        st["log"].append(cmd)
        return ""
    allowed = ("switchport", "no switchport", "port ", "undo port", "vlan ", "no vlan")
    if cmd.startswith(allowed):
        st["log"].append(cmd)
        return ""
    return "% Invalid input detected at '^' marker."


class Server(asyncssh.SSHServer):
    def connection_made(self, conn):
        self._user = None

    def begin_auth(self, username):
        self._user = username
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "backup" and password == PASSWORD

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return username == "keyuser"


def make_handler(p: Persona):
    async def handle(process):
        w = process.stdout.write
        if p.silent:
            await asyncio.sleep(60)
            return
        w("\r\nAuthorized access only.\r\n\r\n" + p.prompt)
        paging = p.paging
        while True:
            try:
                line = await process.stdin.readline()
            except asyncssh.BreakReceived:
                break
            if not line:
                break
            cmd = line.strip()
            if not cmd:
                w("\r\n" + p.prompt)
                continue
            if p.delay:
                await asyncio.sleep(p.delay)
            w(cmd + "\r\n")  # écho de la commande, comme un vrai équipement
            if cmd in ("exit", "quit", "logout"):
                break
            if p.config:
                st = p.state.setdefault("s", {"mode": "exec", "log": [], "iface": ""})
                if p.pager_off and cmd == p.pager_off:
                    paging = False
                    w(config_prompt(p.config, p.prompt, st["mode"], st["iface"]))
                    continue
                out = config_command(p, cmd, st)
                if out is not None:
                    w((out + "\r\n") if out else "")
                    w(config_prompt(p.config, p.prompt, st["mode"], st["iface"]))
                    continue
            if p.pager_off and cmd == p.pager_off:
                paging = False
            elif cmd in ("terminal length 0", "screen-length disable", "no page", "terminal length 1000"):
                w("% Invalid input detected at '^' marker.\r\n")
            elif cmd in (p.running_cmd, p.startup_cmd) and not p.rejects_show:
                text = p.running if cmd == p.running_cmd else p.startup
                if p.empty:
                    w("!\r\n")
                else:
                    lines = text.split("\n")
                    for i in range(0, len(lines), p.page_size):
                        w("\r\n".join(lines[i:i + p.page_size]) + "\r\n")
                        if paging and i + p.page_size < len(lines):
                            w(" --More-- ")
                            await process.stdin.read(1)  # attend une touche (espace)
                            w("\r          \r")
            else:
                w("% Invalid input detected at '^' marker.\r\n")
            w(p.prompt)
        process.exit(0)

    return handle


async def main():
    k1 = asyncssh.generate_private_key("ssh-ed25519")
    k2 = asyncssh.generate_private_key("ssh-ed25519")
    print("empreinte K1:", k1.get_fingerprint("sha256"), flush=True)
    for port, p in PERSONAS.items():
        kw = {}
        if p.legacy_only:  # équipement ancien : uniquement des algorithmes hérités
            kw = {"kex_algs": ["diffie-hellman-group14-sha1"], "encryption_algs": ["aes128-cbc"], "mac_algs": ["hmac-sha1"]}
        await asyncssh.create_server(Server, "0.0.0.0", port, server_host_keys=[k2 if p.alt_key else k1],
                                     process_factory=make_handler(p), encoding="utf-8", line_editor=False, **kw)
    print("faux switchs prêts sur", sorted(PERSONAS), flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
