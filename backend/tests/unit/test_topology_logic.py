import pytest

from app.services.topology import compute_role, first_label, norm_ifname
from app.snmp.bridge import bits_set, cdp_is_network_device, fmt_mac, lldp_is_network_device


def test_role_precedence_and_threshold() -> None:
    assert compute_role(network_neighbor="lldp", is_trunk=False, mac_count=0, threshold=20) == (
        "uplink",
        "lldp_neighbor",
    )
    assert compute_role(network_neighbor="cdp", is_trunk=True, mac_count=99, threshold=20) == ("uplink", "cdp_neighbor")
    assert compute_role(network_neighbor=None, is_trunk=True, mac_count=0, threshold=20) == ("uplink", "trunk")
    assert compute_role(network_neighbor=None, is_trunk=False, mac_count=21, threshold=20) == ("uplink", "mac_count")
    assert compute_role(network_neighbor=None, is_trunk=False, mac_count=20, threshold=20) == ("access", "none")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Gi1/0/24", "gigabitethernet1/0/24"),
        ("GigabitEthernet1/0/24", "gigabitethernet1/0/24"),
        ("GE1/0/1", "gigabitethernet1/0/1"),
        ("Te1/1/1", "tengigabitethernet1/1/1"),
        ("Po1", "port-channel1"),
        ("1", "1"),
        ("BAGG2", "bridge-aggregation2"),
    ],
)
def test_interface_name_normalization(raw: str, expected: str) -> None:
    assert norm_ifname(raw) == expected


def test_names_and_bitmaps() -> None:
    assert first_label("SW-Core.Lab.Local") == "sw-core"
    assert bits_set(bytes([0b10100000, 0b00000001])) == {1, 3, 16}
    assert fmt_mac(bytes.fromhex("001122334455")) == "00:11:22:33:44:55"


def test_capability_decoding_excludes_phones_and_access_points() -> None:
    assert lldp_is_network_device(bytes([0x28]))  # bridge + router
    assert lldp_is_network_device(bytes([0x20]))  # bridge
    assert not lldp_is_network_device(bytes([0x24]))  # bridge + telephone (téléphone avec port PC)
    assert not lldp_is_network_device(bytes([0x04]))  # telephone
    assert not lldp_is_network_device(bytes([0x30]))  # bridge + AP
    assert not lldp_is_network_device(None) and not lldp_is_network_device(b"")
    assert cdp_is_network_device(bytes.fromhex("00000008"))  # switch
    assert not cdp_is_network_device(bytes.fromhex("00000010"))  # host seul
