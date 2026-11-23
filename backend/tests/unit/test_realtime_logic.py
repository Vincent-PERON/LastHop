import pytest

from app.services.realtime import MESSAGES, Hit, build_chain, parse_query


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("10.0.0.1", ("ip", "10.0.0.1")),
        (" 2001:DB8::1 ", ("ip", "2001:db8::1")),
        ("AA:BB:CC:DD:EE:FF", ("mac", "aa:bb:cc:dd:ee:ff")),
        ("aabb.ccdd.eeff", ("mac", "aa:bb:cc:dd:ee:ff")),
        ("AA-BB-CC-DD-EE-FF", ("mac", "aa:bb:cc:dd:ee:ff")),
        ("aabbccddeeff", ("mac", "aa:bb:cc:dd:ee:ff")),
    ],
)
def test_parse_query_all_formats(raw: str, expected: tuple[str, str]) -> None:
    assert parse_query(raw) == expected


@pytest.mark.parametrize(
    "raw", ["", "hello", "10.0.0", "10.0.0.256", "aa:bb", "zz:bb:cc:dd:ee:ff", "1.2.3.4; DROP TABLE x", "a" * 64]
)
def test_parse_query_rejects_garbage(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_query(raw)


def hit(dev: str, nb: str | None, role: str = "uplink") -> Hit:
    return Hit(dev, dev, 1, "p1", 10, role, 0, False, nb, None)


def test_chain_follows_uplinks_back_to_access_switch() -> None:
    # core -> dist -> access ; une branche parallèle (autre switch qui pointe vers dist) est incluse à la même profondeur que core
    uplinks = [hit("core", "dist"), hit("dist", "access"), hit("other", "dist"), hit("stray", "unknown-dev")]
    chain = build_chain("access", uplinks)
    assert [(d, h.device) for d, h in chain] == [(2, "core"), (2, "other"), (1, "dist")]


def test_chain_ignores_cycles_and_unrelated() -> None:
    assert len(build_chain("a", [hit("b", "a"), hit("a", "b")])) == 1  # pas de boucle infinie
    assert build_chain("a", []) == []


def test_every_error_code_has_a_message() -> None:
    for code in (
        "GATEWAY_NOT_MANAGED",
        "IP_NOT_IN_ARP",
        "MAC_AGED_OUT",
        "DEVICE_UNREACHABLE",
        "SNMP_ERROR",
        "TIMEOUT",
        "ACCESS_NOT_MANAGED",
        "NO_SWITCHES",
        "SNMP_AUTH_FAILURE",
    ):
        assert MESSAGES[code]
