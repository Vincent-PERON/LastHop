import pytest

from app.services import cli
from app.services.backup_messages import HUMAN, fmt_size


def test_clean_removes_ansi_pagers_and_carriage_returns() -> None:
    raw = "\x1b[0mline1\r\n --More-- \rline2\r\n<--- More --->line3\x00"
    assert cli.clean(raw) == "line1\nline2\nline3"


@pytest.mark.parametrize(
    "out",
    [
        "% Invalid input detected at '^' marker.",
        "Unrecognized command",
        "% Unknown command or computer name",
        "Error: syntax error",
    ],
)
def test_error_output_detected_only_when_short(out: str) -> None:
    assert cli.looks_like_error(out)
    assert not cli.looks_like_error("hostname x\n" * 100 + "! invalid input is only a comment here")


def test_secrets_are_masked_in_all_vendor_syntaxes() -> None:
    cfg = (
        "enable secret 5 $1$abcd$Hash\nusername admin privilege 15 secret 9 $9$Scrypt\nsnmp-server community TopSecret RO\n"
        "snmp-agent community read cipher $c$3$Cipher==\n local-user admin\n password hash $h$6$Hash==\n"
        'radius-server key "SharedSecret99"\npassword manager user-name "admin" sha1 "5baa61e4"\n'
        "snmp-server user u G v3 auth sha256 MyAuthKey12345 priv aes 128 MyPrivKey12345\n"
        "hostname sw-core\ninterface Gi1/0/1\n description keyboard-lab\nip route 0.0.0.0 0.0.0.0 10.0.0.1\n"
    )
    masked = cli.mask_secrets(cfg)
    for secret in (
        "$1$abcd$Hash",
        "$9$Scrypt",
        "TopSecret",
        "$c$3$Cipher==",
        "$h$6$Hash==",
        "SharedSecret99",
        "5baa61e4",
        "MyAuthKey12345",
        "MyPrivKey12345",
    ):
        assert secret not in masked, secret
    # le reste de la configuration reste lisible
    assert (
        "hostname sw-core" in masked
        and "description keyboard-lab" in masked
        and "ip route 0.0.0.0 0.0.0.0 10.0.0.1" in masked
    )
    assert masked.count(cli.MASK) >= 8


def test_normalize_ignores_cisco_noise_but_not_real_changes() -> None:
    p = cli.PROFILES["cisco_ios"]
    a = "Building configuration...\n\nCurrent configuration : 10 bytes\n!\n! Last configuration change at 10:00\nhostname a\nend"
    b = "Using 10 out of 999 bytes\n!\n! NVRAM config last updated at 09:00\nhostname a\nend"
    assert cli.normalize(a, p) == cli.normalize(b, p)
    assert cli.normalize(a, p) != cli.normalize(b.replace("hostname a", "hostname b"), p)


def test_diff_and_profiles_cover_supported_families() -> None:
    assert cli.diff_stats("a\nb\nc", "a\nB\nc\nd") == (2, 1)
    assert "+B" in cli.unified_diff("a\nb", "a\nB", "x", "y")
    assert set(cli.PROFILES) == {"cisco_ios", "comware", "aruba_os"}
    assert cli.PROFILES["cisco_ios"].needs_privilege("sw>") and not cli.PROFILES["cisco_ios"].needs_privilege("sw#")
    for name, pf in cli.PROFILES.items():
        assert pf.running and pf.startup, name
        assert all(
            c.split()[0] in ("show", "display", "terminal", "screen-length", "no")
            for c in (*pf.running, *pf.startup, *pf.pager_off)
        )


def test_only_read_commands_are_ever_sent() -> None:
    """Aucune commande de modification dans les profils (lecture seule côté CLI également)."""
    forbidden = {
        "write",
        "copy",
        "configure",
        "conf",
        "erase",
        "delete",
        "reload",
        "save",
        "commit",
        "format",
        "enable",
        "reboot",
    }
    for pf in cli.PROFILES.values():
        for c in (*pf.running, *pf.startup, *pf.pager_off):
            assert not (set(c.lower().split()) & forbidden), c


def test_every_error_code_has_message_and_advice() -> None:
    for code, (what, advice) in HUMAN.items():
        assert what.endswith((".", "…")) and advice and len(what) > 20, code
        assert not any(t in what for t in ("Exception", "Traceback", "asyncssh", "errno")), code
    assert fmt_size(500) == "500 octets" and fmt_size(2048) == "2.0 Ko"
