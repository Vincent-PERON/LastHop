import pytest

from app.services.dns import clean_hostname
from app.services.macs import parse_mac_input, to_canonical
from app.services.oui import download_oui, parse_oui_csv
from app.snmp.bridge import _ip_from_index, is_unicast_mac


@pytest.mark.parametrize(
    "raw", ["aa:bb:cc:dd:ee:ff", "AABB.CCDD.EEFF", "AA-BB-CC-DD-EE-FF", "aabbccddeeff", " aabb.ccdd.eeff "]
)
def test_mac_formats_all_normalize_identically(raw: str) -> None:
    assert to_canonical(parse_mac_input(raw)) == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize(
    "raw", ["", "aa:bb", "zz:bb:cc:dd:ee:ff", "aabbccddeeff00", "aa:bb:cc:dd:ee:f%", "a'; DROP TABLE x;--"]
)
def test_invalid_full_mac_rejected(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_mac_input(raw)


def test_partial_mac_is_hex_only() -> None:
    assert parse_mac_input("AA:bb", allow_partial=True) == "aabb"
    for bad in ("a", "%%", "aa_bb", "aa'bb"):
        with pytest.raises(ValueError):
            parse_mac_input(bad, allow_partial=True)


def test_arp_index_parsing_and_mac_filter() -> None:
    assert _ip_from_index(["1", "4", "10", "0", "0", "1"]) == "10.0.0.1"
    assert _ip_from_index(["2", "16"] + ["32", "1", "13", "184"] + ["0"] * 12) == "2001:db8::"
    assert _ip_from_index(["2", "16"] + ["32", "1", "13", "184"] + ["0"] * 11) is None  # mauvaise longueur
    assert _ip_from_index(["1", "4", "300", "0", "0", "1"]) is None
    assert _ip_from_index(["9", "4", "1", "2", "3", "4"]) is None
    assert is_unicast_mac(bytes.fromhex("02aa00000001"))
    assert not is_unicast_mac(bytes.fromhex("ffffffffffff")) and not is_unicast_mac(bytes.fromhex("01005e000001"))
    assert not is_unicast_mac(b"\x00" * 6) and not is_unicast_mac(b"\x02\x00")


def test_hostname_cleaning_rejects_hostile_names() -> None:
    assert clean_hostname("PC-01.Corp.Local.") == "pc-01.corp.local"
    for bad in ("bad host", "<script>x</script>", "a" * 300, "-lead.example", "x..y", "", None, "evil\n.example"):
        assert clean_hostname(bad) is None


def test_oui_csv_parsing_filters_and_sanitizes() -> None:
    csv_text = (
        "Registry,Assignment,Organization Name,Organization Address\n"
        "MA-L,0011AA,Acme\x00 Corp,Somewhere\n"
        'MA-L,02bb00,"Bravo, Inc",x\n'
        "MA-M,AABBCC1,Medium Block,x\n"
        "MA-L,ZZZZZZ,Broken,x\n"
        "MA-L,0011AB,,x\n"
    )
    assert dict(parse_oui_csv(csv_text)) == {"00:11:aa:00:00:00": "Acme Corp", "02:bb:00:00:00:00": "Bravo, Inc"}


async def test_oui_download_refuses_untrusted_sources() -> None:
    for url in ("http://standards-oui.ieee.org/oui/oui.csv", "https://evil.example/oui.csv", "file:///etc/passwd"):
        with pytest.raises(ValueError):
            await download_oui(url)
